use std::{collections::HashMap};
use bson::{Document, doc};
use futures::future::join_all;
use serde::{Serialize, Deserialize};
use mongodb::{Database, bson};
use tokio::{task::{self, JoinHandle}};
use chrono::Utc;

use crate::{SchedulerStats, config::ResultSavingOption, error::*, scheduler::{Scheduler, TaskPool}, vul_search::VulnerabilitiesSearch};
use crate::config::GLOBAL_CONFIG;
use crate::net_scanner::result_handler::NetScanRecord;

use super::{ftp::FTPServiceAnalyser, ssh::SSHServiceAnalyser, web::WebServiceAnalyser};
use super::ServiceAnalyseResult;

const KEY_ANALYSE_TASKQUEUE: &str = "analyse_taskqueue";
const KEY_ANALYSE_RUNNING: &str = "analyse_running";

#[derive(Clone)]
pub struct ServiceAnalyseScheduler {
    scheduler: Scheduler,
    redis: redis::Client,
    db: Database,
}

impl ServiceAnalyseScheduler {
    pub async fn new(db: &Database, redis_url: &str) -> Result<Self, SimpleError> {
        let client = redis::Client::open(redis_url)?;
        
        Ok(Self {
            scheduler: Scheduler::new("analyser", redis_url).await?,
            db: db.clone(),
            redis: client,
        })
    }
    pub async fn run(&self) -> Result<JoinHandle<()>, SimpleError> {
        let dispatcher = self.clone();
        Ok(task::spawn(dispatcher.dispatch_tasks()))
    }

    async fn dispatch_tasks(mut self)
    {
        if !GLOBAL_CONFIG.analyser.scheduler.enabled {
            return;
        }
        let resources_pool: Vec<TaskResources> = join_all(
            (0..GLOBAL_CONFIG.analyser.scheduler.max_tasks)
            .into_iter()
            .map(|_|async { TaskResources::new(self.db.clone(), self.redis.clone()).await.unwrap() })
        ).await;


        let mut task_pool = self.scheduler.new_task_pool(
            GLOBAL_CONFIG.analyser.scheduler.max_tasks,
            resources_pool,
        );

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

    async fn try_dispatch_task(&mut self, task_pool: &mut TaskPool<TaskResources>) -> Result<(), SimpleError> {
        let addr = self.scheduler.fetch_task().await?;

        let task = ServiceAnalyseTask {
            addr: addr.to_owned(),
        };
        task.start(task_pool).await;

        self.scheduler.complete_task(&addr).await?;
        Ok(())
    }

    pub async fn enqueue_task_addr(&mut self, addr: &str) -> Result<(), SimpleError> {
        self.scheduler.enqueue_task(addr).await
    }
    pub async fn enqueue_task_list(&mut self, addr_list: Vec<String>) -> Result<(), SimpleError> {
        self.scheduler.enqueue_task_list(addr_list).await
    }
    pub async fn remove_task(&mut self, addr: &str) -> Result<usize, SimpleError>{
        self.scheduler.remove_task(addr).await
    }
    pub async fn clear_tasks(&mut self) -> Result<usize, SimpleError> {
        self.scheduler.clear_tasks().await
    }
    pub async fn stats(&mut self) -> SchedulerStats {
        self.scheduler.stats().await
    }
}

struct TaskResources {
    web_analyser: WebServiceAnalyser,
    ftp_analyser: FTPServiceAnalyser,
    ssh_analyser: SSHServiceAnalyser,
    db: Database,
    redis: redis::Client,
}

impl TaskResources { 
    async fn new(db: Database, redis: redis::Client) -> Result<Self, SimpleError>  {
        Ok(Self {
            ftp_analyser: FTPServiceAnalyser::from_json(
                &GLOBAL_CONFIG.analyser.rules.ftp, 
                VulnerabilitiesSearch::new(redis.clone(), db.clone()).await?
            )?,
            ssh_analyser: SSHServiceAnalyser::from_json(
                &GLOBAL_CONFIG.analyser.rules.ssh, 
                VulnerabilitiesSearch::new(redis.clone(), db.clone()).await?
            )?,
            web_analyser: WebServiceAnalyser::init_from_json(
                &GLOBAL_CONFIG.analyser.rules.wappanalyser,
                VulnerabilitiesSearch::new(redis.clone(), db.clone()).await?
            )?,
            db: db,
            redis: redis,
        })
    }
}

struct ServiceAnalyseTask {
    addr: String,
}

impl ServiceAnalyseTask {
    async fn start(self, task_pool: &mut TaskPool<TaskResources>)
    {
        // task_pool.spawn("service-analyse", Self::analyse, self).await;
        task_pool.spawn("service-analyse", |task, res| async move {
            task.analyse(res).await.log_error_consume("service-analyse");
        }, self).await;
    }

    async fn analyse(self, resource: & mut TaskResources) -> Result<(), SimpleError> {
        log::info!("Analyse {}", self.addr);

        let mut web_services: HashMap::<String, ServiceAnalyseResult> = HashMap::new();
        let mut ftp_services: HashMap::<String, ServiceAnalyseResult> = HashMap::new();
        let mut ssh_services: HashMap::<String, ServiceAnalyseResult> = HashMap::new();

        match &GLOBAL_CONFIG.scanner.save {
            ResultSavingOption::SingleCollection(name) => {
                let colllection = resource.db.collection(name);
                let query = bson::doc!{
                    "addr": &self.addr,
                };

                let doc = colllection.find_one(query, None)
                    .await?
                    .ok_or(format!("Scan result of {} not found", self.addr))?;
                let record: NetScanRecord = bson::from_document(doc)?;

                if let Some(http_scan) = record.scan.http {
                    let services = resource.web_analyser.analyse_result_set(&http_scan).await?;
                    // for (name, version) in services {
                    //     web_services.insert(format!("web.{}", name), version);
                    // }
                    web_services = services;
                }
                let ftp_scan_result = record.scan.tcp.as_ref()
                    .and_then(|tcp|tcp.get("21"))
                    .and_then(|result|result.ftp.as_ref());
                if let Some(ftp_result) = ftp_scan_result {
                    ftp_services = resource.ftp_analyser.analyse_results_set(&ftp_result).await;
                }

                let ssh_scan_result = record.scan.tcp.as_ref()
                    .and_then(|tcp_result| tcp_result.get("22"))
                    .and_then(|result| result.ssh.as_ref());
                if let Some(ssh_result) = ssh_scan_result {
                    ssh_services = resource.ssh_analyser.analyse_results_set(ssh_result).await;
                }
            },
            _ => panic!("Unimplement"),
        }

        let time: bson::DateTime = Utc::now().into();
        let collection = resource.db.collection::<Document>(&GLOBAL_CONFIG.analyser.save);
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
