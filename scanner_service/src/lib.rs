#![allow(dead_code)]

pub mod error;
mod proxy;
mod config;
mod address;
mod http;
mod ssl;
mod net_scanner;
mod utils;
mod service_analyse;
mod scheduler;
mod vul_search;

#[allow(dead_code)]
mod redis_pool;

use address::fetch_address_list;
use proxy::ProxyPool;
use config::GLOBAL_CONFIG;
use net_scanner::scheduler::{NetScanner};
use tokio::{task, time::sleep};

use error::*;

pub use net_scanner::scheduler::SchedulerController;
pub use service_analyse::{scheduler::ServiceAnalyseScheduler, scheduler::ServiceRecord, ServiceAnalyseResult, ServiceVuln};
pub use config::Config;
pub use net_scanner::result_handler::NetScanRecord;
pub use address::parse_ipv4_cidr;
pub use net_scanner::tcp_scanner::ftp::FTPAccess;

#[derive(Clone)]
pub struct ScannerService {
    scheduler: SchedulerController,
    analyser: ServiceAnalyseScheduler,
}

impl ScannerService {
    pub async fn start() -> Result<Self, SimpleError>
    {
        let mongodb = mongodb::Client::with_uri_str(&GLOBAL_CONFIG.mongodb).await.unwrap();
        let db = mongodb.database("nscn");
        // let redis_pool = Arc::new(RedisPool::open(&config.redis));
        // let redis = redis::Client::open(config.redis.as_str()).unwrap();
        // let conn = redis.get_multiplexed_tokio_connection().await.unwrap();
        let proxy_pool = ProxyPool::new();
        proxy_pool.start().await;
        let scanner = NetScanner::new(&GLOBAL_CONFIG.redis, &db, &proxy_pool);
        let scheduler = scanner.start().unwrap();
        
        // http_scanner.enqueue("47.102.198.236").await.unwrap();
        
        stats(&scheduler);
        // try_dispatch_address(&scheduler).await;

        // let range = parse_ipv4_cidr("47.102.198.0/24").unwrap();
        // for ip in range {
        //     let addr = std::net::Ipv4Addr::from(ip);
        //     http_scanner.enqueue(addr.to_string().as_str()).await;
        // }

        let analyser_scheduler = ServiceAnalyseScheduler::new(&db, &GLOBAL_CONFIG.redis).await.unwrap();
        let _ = analyser_scheduler.run().await.unwrap();
        // task::spawn(try_dispatch_analysing(db.clone(), analyser_scheduler));
        

        // analyser_join.await.unwrap();
        // scheduler.join().await;

        // panic!();

        Ok(Self {
            scheduler: scheduler,
            analyser: analyser_scheduler
        })
    }

    pub fn scheculer(&self) -> SchedulerController {
        self.scheduler.clone()
    }

    pub fn analyser(&self) -> ServiceAnalyseScheduler {
        self.analyser.clone()
    }

    pub fn config(&self) -> &'static Config{
        &GLOBAL_CONFIG
    }

    pub async fn fetch_address_list(&self, url: &str) -> Result<Vec<String>, SimpleError> {
        Ok(fetch_address_list(url).await?)
    }

    pub async fn join(self)
    {
        self.scheduler.join().await
    }
}

fn stats(scheduler: &SchedulerController) {
    let scheduler = scheduler.clone();
    let interval = 10.0;
    task::spawn(async move {
        loop {
            sleep(tokio::time::Duration::from_secs_f64(interval)).await;
            let stats = scheduler.reset_stats().await;
            log::info!("Scan speed: {:.2} IP/s, {:.2} Tasks/s", stats.dispatched_addrs as f64 / interval, stats.dispatched_tasks as f64 / interval);
            
                // log::info!("HTTP {} avg. {:.2}s, HTTPS {} avg. {:.2}s, FTP {} avg. {:.2}s, SSH {} avg. {:.2}s, TASK {} {} avg. {:.5}s, Spawn {:.5}s, Send {:.5}s",
                //     stats.http_tasks, stats.http_time / stats.http_tasks as f64, 
                //     stats.https_tasks, stats.https_time / stats.https_tasks as f64, 
                //     stats.ftp_tasks, stats.ftp_time / stats.ftp_tasks as f64, 
                //     stats.ssh_tasks, stats.ssh_time / stats.ssh_tasks as f64,
                //     stats.dispatched_tasks, stats.active_tasks, stats.task_time / stats.dispatched_tasks as f64,
                //     stats.spawn_time / stats.dispatched_tasks as f64,
                //     stats.send_time / stats.dispatched_tasks as f64,
                // );
            
        }
    });
}