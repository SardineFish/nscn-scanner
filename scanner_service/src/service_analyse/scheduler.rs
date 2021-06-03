use std::{collections::HashMap, str::FromStr, time::Duration};
use bson::{Document, doc};
use futures::future::{join3, join_all};
use serde::{Serialize, Deserialize};
use mongodb::{Database, bson, options::{UpdateModifications, UpdateOptions}};
use tokio::{task::{self, JoinHandle}, time::sleep};
use chrono::Utc;

use crate::{SchedulerStats, config::{self}, error::*, net_scanner::result_handler::TcpScanResultType, scheduler::{SharedSchedulerInternalStats, SharedSchedulerStats, TaskPool, local_scheduler::LocalScheduler}, vul_search::VulnerabilitiesSearch};
use crate::config::GLOBAL_CONFIG;
use crate::net_scanner::result_handler::NetScanRecord;

use super::{ftp::FTPServiceAnalyser, ip_geo::IP2Geo, ssh::SSHServiceAnalyser, web::WebServiceAnalyser};
use super::ServiceAnalyseResult;

const KEY_ANALYSE_TASKQUEUE: &str = "analyse_taskqueue";
const KEY_ANALYSE_RUNNING: &str = "analyse_running";

#[derive(Clone)]
pub struct ServiceAnalyseScheduler {
    redis: redis::Client,
    db: Database,
    stats_internal: SharedSchedulerInternalStats,
    stats: SharedSchedulerStats,
}

impl ServiceAnalyseScheduler {
    pub async fn new(db: &Database, redis_url: &str) -> Result<Self, SimpleError> {
        let client = redis::Client::open(redis_url)?;
        let internal_stats = SharedSchedulerInternalStats::new();
        
        Ok(Self {
            db: db.clone(),
            redis: client,
            stats: SharedSchedulerStats::new(),
            stats_internal: internal_stats.clone(),
        })
    }
    pub fn start(&self, master_addr: String, config: config::ServiceAnalyserOptions) -> Result<JoinHandle<()>, SimpleError> {
        let dispatcher = self.clone();
        let (scheduler, fetch_task) = 
            LocalScheduler::start("analyser".to_owned(), master_addr, &config.scheduler);
        let future = join3(
            self.clone().stats_mornitor(5.0), 
            dispatcher.dispatch_tasks(scheduler, config),
            fetch_task
        );
        Ok(task::spawn(async move {
            future.await;
        }))
    }

    async fn dispatch_tasks(mut self, mut scheduler: LocalScheduler, config: config::ServiceAnalyserOptions)
    {
        if !config.scheduler.enabled {
            return;
        }
        let resources_pool: Vec<TaskResources> = join_all(
            (0..config.scheduler.max_tasks)
            .into_iter()
            .map(|_|async { TaskResources::new(self.db.clone(), self.redis.clone()).await.unwrap() })
        ).await;

        let mut task_pool = TaskPool::new(
            config.scheduler.max_tasks, 
            self.stats_internal.clone(), 
            resources_pool);

        loop {
            match self.try_dispatch_task(&mut task_pool, &mut scheduler).await {
                Ok(_) => (),
                Err(err) => {
                    log::error!("Failed to dispatch service analysing task: {}", err.msg);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }
    
    pub async fn stats(&self) -> SchedulerStats {
        self.stats.clone_inner().await
    }

    pub async fn reset_stats(&self) {
        self.stats.reset().await
    }

    async fn try_dispatch_task(&mut self, task_pool: &mut TaskPool<TaskResources>, scheduler: &mut LocalScheduler) -> Result<(), SimpleError> {
        let addr = scheduler.fetch_task().await;

        let task = ServiceAnalyseTask {
            addr: addr.to_owned(),
        };
        task.start(task_pool).await;

        scheduler.complete_task(addr).await;
        Ok(())
    }
    
    async fn stats_mornitor(self, update_interval: f64) {
        loop {
            sleep(Duration::from_secs_f64(update_interval)).await;
            
            let stats = self.stats_internal.reset_stats().await;
            self.stats.update(&stats, update_interval).await;
        }
    }
}

struct TaskResources {
    web_analyser: WebServiceAnalyser,
    ftp_analyser: FTPServiceAnalyser,
    ssh_analyser: SSHServiceAnalyser,
    ip_geo: IP2Geo,
    db: Database,
    redis: redis::Client,
}

impl TaskResources { 
    async fn new(db: Database, redis: redis::Client) -> Result<Self, SimpleError>  {
        Ok(Self {
            ftp_analyser: FTPServiceAnalyser::from_json(
                &GLOBAL_CONFIG.analyser.externals.ftp_rules, 
                VulnerabilitiesSearch::new(redis.clone(), db.clone()).await?
            )?,
            ssh_analyser: SSHServiceAnalyser::from_json(
                &GLOBAL_CONFIG.analyser.externals.ssh_rules, 
                VulnerabilitiesSearch::new(redis.clone(), db.clone()).await?
            )?,
            web_analyser: WebServiceAnalyser::init_from_json(
                &GLOBAL_CONFIG.analyser.externals.wappanalyser_rules,
                VulnerabilitiesSearch::new(redis.clone(), db.clone()).await?
            )?,
            ip_geo: IP2Geo::from_json(
                &GLOBAL_CONFIG.analyser.externals.city_coords
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
        // log::info!("Analyse {}", self.addr);

        let mut services = Vec::new();
        // let mut web_services: HashMap::<String, ServiceAnalyseResult> = HashMap::new();
        // let mut ftp_services: HashMap::<String, ServiceAnalyseResult> = HashMap::new();
        // let mut ssh_services: HashMap::<String, ServiceAnalyseResult> = HashMap::new();

        let addr_int: u32 = std::net::Ipv4Addr::from_str(&self.addr)?.into();
        let collection = resource.db.collection::<NetScanRecord>(&GLOBAL_CONFIG.scanner.save.collection);
        let query = bson::doc!{
            "addr_int": addr_int as i64,
        };

        let doc = collection.find_one(query, None)
            .await?
            .ok_or(format!("Scan result of {} not found", self.addr))?;

        for result in doc.results {
            let analyse_results = match result.result {
                TcpScanResultType::Http(scan_result) => resource.web_analyser.analyse_result_set(&scan_result).await,
                TcpScanResultType::Ftp(scan_result) => resource.ftp_analyser.analyse_results_set(&scan_result).await,
                TcpScanResultType::SSH(scan_result) => resource.ssh_analyser.analyse_results_set(&scan_result).await,
                _ => HashMap::new(),
            };
            services.extend(analyse_results.into_iter().map(|r|r.1));
        }

        let geo = resource.ip_geo.search_ip(&self.addr);

        let collection = resource.db.collection::<Document>(&GLOBAL_CONFIG.analyser.save);
        // let result = ServiceRecord {
        //     addr: self.addr,
        //     addr_int: addr_int as i64,
        //     last_update: Utc::now().into(),
        //     services,
        // };
        let query = doc! {
            "addr_int": addr_int as i64,
        };
        let update = doc! {
            "$setOnInsert": {
                "addr": self.addr,
                "addr_int": addr_int as i64,
            },
            "$set": {
                "last_update": bson::to_bson(&bson::DateTime::from(Utc::now()))?,
                "services": bson::to_bson(&services)?,
                "geo": bson::to_bson(&geo)?,
            }
        };
        let opts = UpdateOptions::builder()
            .upsert(Some(true))
            .build();
        collection.update_one(query, update, opts).await?;
        
        // let mut results = HashMap::new();
        // for result in doc.results {
        // }

        // let record: NetScanRecord = bson::from_document(doc)?;

        // if let Some(http_scan) = record.scan.http {
        //     let services = resource.web_analyser.analyse_result_set(&http_scan).await?;
        //     // for (name, version) in services {
        //     //     web_services.insert(format!("web.{}", name), version);
        //     // }
        //     web_services = services;
        // }
        // let ftp_scan_result = record.scan.tcp.as_ref()
        //     .and_then(|tcp|tcp.get("21"))
        //     .and_then(|result|result.ftp.as_ref());
        // if let Some(ftp_result) = ftp_scan_result {
        //     ftp_services = resource.ftp_analyser.analyse_results_set(&ftp_result).await;
        // }

        // let ssh_scan_result = record.scan.tcp.as_ref()
        //     .and_then(|tcp_result| tcp_result.get("22"))
        //     .and_then(|result| result.ssh.as_ref());
        // if let Some(ssh_result) = ssh_scan_result {
        //     ssh_services = resource.ssh_analyser.analyse_results_set(ssh_result).await;
        // }


        // let time: bson::DateTime = Utc::now().into();
        // let collection = resource.db.collection::<Document>(&GLOBAL_CONFIG.analyser.save);
        // let query = doc! {
        //     "addr": &self.addr,
        // };
        // let addr_int: u32 = std::net::Ipv4Addr::from_str(&self.addr)?.into();
        // let update = doc! {
        //     "$set": {
        //         "addr": &self.addr,
        //         "addr_int": addr_int as i64,
        //         "last_update": bson::to_bson(&time)?,
        //         "web": bson::to_bson(&web_services)?,
        //         "ftp": bson::to_bson(&ftp_services)?,
        //         "ssh": bson::to_bson(&ssh_services)?,
        //         "geo": bson::to_bson(&geo)?,
        //     }
        // };
        // let mut opts = mongodb::options::UpdateOptions::default();
        // opts.upsert = Some(true);
        // collection.update_one(query, update, opts).await?;

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub addr: String,
    pub addr_int: i64,
    pub last_update: bson::DateTime,
    pub services: Vec<ServiceAnalyseResult>,
}

#[cfg(test)]
mod test {
    use chrono::Utc;
    use mongodb::bson::{self, doc};
    use tokio::test;

    use crate::NetScanRecord;
    
    #[test]
    async fn test_deserialize() {
        
        let doc = doc! {
            "addr_int" : 0,
            "addr" : "123.123.123.123",
            "online" : true,
            "results" : [
                {
                    "port" : 21,
                    "scanner" : "ftp",
                    "proxy" : "",
                    "time" : bson::to_bson(&bson::DateTime::from(Utc::now())).unwrap(),
                    "result" : "Err",
                    "data" : "deadline has elapsed"
                },
                {
                    "port" : 443,
                    "scanner" : "tls",
                    "proxy" : "",
                    "time" : bson::to_bson(&bson::DateTime::from(Utc::now())).unwrap(),
                    "result" : "Ok",
                    "data" : {
                        "cert" : "****"
                    }
                },
                {
                    "port" : 80,
                    "scanner" : "http",
                    "proxy" : "",
                    "time" : bson::to_bson(&bson::DateTime::from(Utc::now())).unwrap(),
                    "result" : "Ok",
                    "data" : {
                        "status" : 412,
                        "headers" : {
                            "cache-control" : "[\"no-cache\"]",
                            "date" : "[\"Thu, 03 Jun 2021 04:29:56 GMT\"]",
                            "connection" : "[\"keep-alive\"]",
                            "transfer-encoding" : "[\"chunked\"]",
                            "server" : "[\"******\"]",
                            "content-type" : "[\"text/html;charset=utf-8\"]"
                        },
                        "body" : "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n<html>\n<head>\n    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\n    <meta id=\"JLyKZlWgYjpTkAsEt9LnA\" content=\"\" >\n</head>\n<body>\n    <script type=\"text/javascript\" src=\"/xlIsAnK1Ny52/Gx56ae5/468faf\" r='m'></script>\n</body>\n</html>\n"
                    }
                },
                {
                    "port" : 22,
                    "scanner" : "ssh",
                    "proxy" : "",
                    "time" : bson::to_bson(&bson::DateTime::from(Utc::now())).unwrap(),
                    "result" : "Err",
                    "data" : "deadline has elapsed"
                }
            ]
        };
        let record: NetScanRecord = bson::from_document(doc).unwrap();
        println!("{:?}", record);
    }
}