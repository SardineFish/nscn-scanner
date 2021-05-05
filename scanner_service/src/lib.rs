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
use scheduler::master_scheduler::MasterScheduler;
use stats_mornitor::{ScannerStatsMornotor, SystemStatsMornitor};
use tokio::{task, time::sleep};

use error::*;

pub use service_analyse::{scheduler::ServiceAnalyseScheduler, scheduler::ServiceRecord, ServiceAnalyseResult};
pub use config::Config;
pub use net_scanner::result_handler::NetScanRecord;
pub use address::{parse_ipv4_cidr};
pub use net_scanner::tcp_scanner::ftp::FTPAccess;
pub use net_scanner::{http_scanner::HttpResponseData, https_scanner::HttpsResponse, result_handler::ScanTaskInfo, tcp_scanner::{ftp::FTPScanResult, ssh::SSHScannResult}};
pub use stats_mornitor::{SystemStats, SchedulerStatsReport};
pub use scheduler::SchedulerStats;
pub use vul_search::VulnInfo;

#[derive(Clone)]
pub struct WorkerService {
    scanner: NetScanner,
    analyser: ServiceAnalyseScheduler,
    sys_mornitor: SystemStatsMornitor,
    scheduler_mornitor: ScannerStatsMornotor,
}

impl WorkerService {
    pub async fn start() -> Result<Self, SimpleError>
    {
        let mongodb = mongodb::Client::with_uri_str(&GLOBAL_CONFIG.mongodb).await.unwrap();
        let db = mongodb.database("nscn");
        
        let proxy_pool = ProxyPool::new();
        proxy_pool.start().await;
        let scanner = NetScanner::new(&GLOBAL_CONFIG.redis, &db, &proxy_pool);
        
        
        let scheduler_mornitor = ScannerStatsMornotor::start(scanner.stats());
        stats_log(scheduler_mornitor.clone());
        

        let analyser_scheduler = ServiceAnalyseScheduler::new(&db, &GLOBAL_CONFIG.redis).await.unwrap();
        // let _ = analyser_scheduler.run().await.unwrap();

        Ok(Self {
            scanner: scanner,
            analyser: analyser_scheduler,
            sys_mornitor: SystemStatsMornitor::start(),
            scheduler_mornitor: scheduler_mornitor,
        })
    }

    pub fn scanner(&self) -> NetScanner {
        self.scanner.clone()
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
}

#[derive(Clone)]
pub struct MasterService {
    scanner_scheduler: MasterScheduler,
    analyser_scheduler: MasterScheduler,
    workers: Vec<String>,
}

impl MasterService {
    pub async fn new() -> Result<Self, SimpleError> {
        Ok(Self {
            scanner_scheduler: MasterScheduler::start("scanner", 
                redis::Client::open(GLOBAL_CONFIG.redis.as_str())?).await?,
            analyser_scheduler: MasterScheduler::start("analysser", 
                redis::Client::open(GLOBAL_CONFIG.redis.as_str())?).await?,
            workers: Vec::new(),
        })
    }
}

fn stats_log(mornitor: ScannerStatsMornotor) {
    let interval = 10.0;
    task::spawn(async move {
        let mut last_stats = SchedulerStatsReport::default();
        loop {
            sleep(tokio::time::Duration::from_secs_f64(interval)).await;
            let stats = mornitor.get_stats().await;
            if last_stats == stats {
                continue;
            }
            log::info!("Scan speed: {:.2} IP/s, {:.2} Tasks/s, {} IPs pending", stats.ip_per_second, stats.tasks_per_second, stats.pending_addrs);
            last_stats = stats;
            
        }
    });
}