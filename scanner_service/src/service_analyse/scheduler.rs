use std::{collections::HashMap, sync::Arc};
use bson::{Document, doc};
use serde::{Serialize, Deserialize};
use mongodb::{Database, bson};
use tokio::{sync::Mutex, task::{self, JoinHandle}};
use chrono::Utc;

use crate::{config::ResultSavingOption, error::*, net_scanner::scheduler::{SchedulerStats, TaskPool}, scheduler::Scheduler};
use crate::config::GLOBAL_CONFIG;
use crate::net_scanner::result_handler::NetScanRecord;

use super::{ftp::FTPServiceAnalyser, ssh::SSHServiceAnalyser, web::WebServiceAnalyser};
use super::ServiceAnalyseResult;

const KEY_ANALYSE_TASKQUEUE: &str = "analyse_taskqueue";
const KEY_ANALYSE_RUNNING: &str = "analyse_running";

#[derive(Clone)]
pub struct ServiceAnalyser {
    web_analyser: WebServiceAnalyser,
    ftp_analyser: FTPServiceAnalyser,
    ssh_analyser: SSHServiceAnalyser,
}

impl ServiceAnalyser {
    pub fn new() -> Result<Self, SimpleError> {
        Ok(Self {
            web_analyser: WebServiceAnalyser::init_from_json(&GLOBAL_CONFIG.analyser.rules.wappanalyser)?,
            ftp_analyser: FTPServiceAnalyser::from_json(&GLOBAL_CONFIG.analyser.rules.ftp)?,
            ssh_analyser: SSHServiceAnalyser::from_json(&GLOBAL_CONFIG.analyser.rules.ssh)?,
        })
    }
}

#[derive(Clone)]
pub struct ServiceAnalyseScheduler {
    scheduler: Scheduler,
    resources: TaskResources,
}

impl ServiceAnalyseScheduler {
    pub async fn new(db: &Database, redis_url: &str) -> Result<Self, SimpleError> {
        Ok(Self {
            scheduler: Scheduler::new("analyser", redis_url).await?,
            resources: TaskResources {
                db: db.clone(),
                web_analyser: WebServiceAnalyser::init_from_json(&GLOBAL_CONFIG.analyser.rules.wappanalyser)?,
                ftp_analyser: FTPServiceAnalyser::from_json(&GLOBAL_CONFIG.analyser.rules.ftp)?,
                ssh_analyser: SSHServiceAnalyser::from_json(&GLOBAL_CONFIG.analyser.rules.ssh)?,
            }
        })
    }
    pub async fn run(&self) -> Result<JoinHandle<()>, SimpleError> {
        let dispatcher = self.clone();
        Ok(task::spawn(dispatcher.dispatch_tasks()))
    }

    async fn dispatch_tasks(mut self)
    {
        let stats = Arc::new(Mutex::new(SchedulerStats::default()));
        let mut task_pool = TaskPool::new(GLOBAL_CONFIG.analyser.scheduler.max_tasks, &stats);
        self.scheduler.recover_tasks().await.log_error_consume("service-analyser");
        loop {
            match self.try_dispatch_task(&mut task_pool).await {
                Ok(_) => (),
                Err(err) => {
                    log::error!("Failed to dispatch service analysing task: {}", err.msg);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    async fn try_dispatch_task(&mut self, task_pool: &mut TaskPool) -> Result<(), SimpleError> {
        let addr = self.scheduler.fetch_task().await?;

        let task = ServiceAnalyseTask {
            addr: addr.to_owned(),
            resource: self.resources.clone(),
        };
        task.start(task_pool).await;

        self.scheduler.complete_task(&addr).await?;
        Ok(())
    }

    pub async fn enqueue_task_addr(&mut self, addr: &str) -> Result<(), SimpleError> {
        self.scheduler.enqueue_task(addr).await
    }
}

#[derive(Clone)]
struct TaskResources {
    web_analyser: WebServiceAnalyser,
    ftp_analyser: FTPServiceAnalyser,
    ssh_analyser: SSHServiceAnalyser,
    db: Database,
}

struct ServiceAnalyseTask {
    addr: String,
    resource: TaskResources,
}

impl ServiceAnalyseTask {
    async fn start(self, task_pool: &mut TaskPool)
    {
        task_pool.spawn("service-analyse", async move {
            self.analyse().await.log_error_consume("service-analyse");
        }).await;
    }

    async fn analyse(self) -> Result<(), SimpleError> {
        log::info!("Analyse {}", self.addr);

        let mut web_services: HashMap::<String, ServiceAnalyseResult> = HashMap::new();
        let mut ftp_services: HashMap::<String, ServiceAnalyseResult> = HashMap::new();
        let mut ssh_services: HashMap::<String, ServiceAnalyseResult> = HashMap::new();

        match &GLOBAL_CONFIG.scanner.save {
            ResultSavingOption::SingleCollection(name) => {
                let colllection = self.resource.db.collection(name);
                let query = bson::doc!{
                    "addr": &self.addr,
                };

                let doc = colllection.find_one(query, None)
                    .await?
                    .ok_or(format!("Scan result of {} not found", self.addr))?;
                let record: NetScanRecord = bson::from_document(doc)?;

                if let Some(http_scan) = record.scan.http {
                    let services = self.resource.web_analyser.analyse_result_set(&http_scan).await?;
                    // for (name, version) in services {
                    //     web_services.insert(format!("web.{}", name), version);
                    // }
                    web_services = services;
                }
                let ftp_scan_result = record.scan.tcp.as_ref()
                    .and_then(|tcp|tcp.get("21"))
                    .and_then(|result|result.ftp.as_ref());
                if let Some(ftp_result) = ftp_scan_result {
                    ftp_services = self.resource.ftp_analyser.analyse_results_set(&ftp_result).await;
                }

                let ssh_scan_result = record.scan.tcp.as_ref()
                    .and_then(|tcp_result| tcp_result.get("22"))
                    .and_then(|result| result.ssh.as_ref());
                if let Some(ssh_result) = ssh_scan_result {
                    ssh_services = self.resource.ssh_analyser.analyse_results_set(ssh_result).await;
                }
            },
            _ => panic!("Unimplement"),
        }

        let time: bson::DateTime = Utc::now().into();
        let collection = self.resource.db.collection::<Document>(&GLOBAL_CONFIG.analyser.save);
        let query = doc! {
            "addr": &self.addr,
        };
        let update = doc! {
            "$set": {
                "addr": &self.addr,
                "last_update": bson::to_bson(&time)?,
                "web": bson::to_bson(&web_services)?,
                "ftp": bson::to_bson(&ftp_services)?,
                "ssh": bson::to_bson(&ssh_services)?,
            }
        };
        let mut opts = mongodb::options::UpdateOptions::default();
        opts.upsert = Some(true);
        collection.update_one(query, update, opts).await?;

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub addr: String,
    pub last_update: bson::DateTime,
    pub system: Option<HashMap<String, ServiceAnalyseResult>>,
    pub web: Option<HashMap<String, ServiceAnalyseResult>>,
    pub ftp: Option<HashMap<String, ServiceAnalyseResult>>,
    pub ssh: Option<HashMap<String, ServiceAnalyseResult>>,
}
