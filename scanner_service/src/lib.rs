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
mod stats_mornitor;

#[allow(dead_code)]
mod redis_pool;

use address::fetch_address_list;
use proxy::ProxyPool;
use config::GLOBAL_CONFIG;
use net_scanner::scheduler::{NetScanner};
use stats_mornitor::{SchedulerStatsMornotor, SystemStatsMornitor};
use tokio::{task, time::sleep};

use error::*;

pub use net_scanner::scheduler::SchedulerController;
pub use service_analyse::{scheduler::ServiceAnalyseScheduler, scheduler::ServiceRecord, ServiceAnalyseResult, ServiceVuln};
pub use config::Config;
pub use net_scanner::result_handler::NetScanRecord;
pub use address::{parse_ipv4_cidr};
pub use net_scanner::tcp_scanner::ftp::FTPAccess;
pub use net_scanner::{http_scanner::HttpResponseData, https_scanner::HttpsResponse, result_handler::ScanTaskInfo, tcp_scanner::{ftp::FTPScanResult, ssh::SSHScannResult}};
pub use stats_mornitor::{SystemStats, SchedulerStatsReport};

#[derive(Clone)]
pub struct ScannerService {
    scheduler: SchedulerController,
    analyser: ServiceAnalyseScheduler,
    sys_mornitor: SystemStatsMornitor,
    scheduler_mornitor: SchedulerStatsMornotor,
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
        
        let scheduler_mornitor = SchedulerStatsMornotor::start(scheduler.stats());
        stats(scheduler_mornitor.clone());
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
            analyser: analyser_scheduler,
            sys_mornitor: SystemStatsMornitor::start(),
            scheduler_mornitor: scheduler_mornitor,
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

    pub async fn sys_stats(&self) -> SystemStats {
        self.sys_mornitor.get_stats().await
    }

    pub async fn scheduler_stats(&self) -> SchedulerStatsReport {
        self.scheduler_mornitor.get_stats().await
    }

    pub async fn join(self)
    {
        self.scheduler.join().await
    }
}

fn stats(mornitor: SchedulerStatsMornotor) {
    let interval = 10.0;
    task::spawn(async move {
        loop {
            sleep(tokio::time::Duration::from_secs_f64(interval)).await;
            let stats = mornitor.get_stats().await;
            log::info!("Scan speed: {:.2} IP/s, {:.2} Tasks/s, {} IPs pending", stats.ip_per_second, stats.tasks_per_second, stats.pending_addrs);
            
        }
    });
}