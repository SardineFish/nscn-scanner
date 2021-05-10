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

use std::{mem, sync::Arc};

use serde::{Serialize, Deserialize};
use address::fetch_address_list;
use futures::future::join_all;
use proxy::ProxyPool;
use net_scanner::{scanner_master::ScannerMasterScheduler, scheduler::{NetScanner}};
use reqwest::StatusCode;
use scheduler::{SharedSchedulerStats, master_scheduler::{MasterScheduler}};
use stats_mornitor::{SystemStatsMornitor};
use tokio::{sync::{Mutex}, task::{self, JoinHandle}, time::sleep};

use error::*;

pub use service_analyse::{scheduler::ServiceAnalyseScheduler, scheduler::ServiceRecord, ServiceAnalyseResult};
pub use config::Config;
pub use net_scanner::result_handler::NetScanRecord;
pub use address::{parse_ipv4_cidr};
pub use net_scanner::tcp_scanner::ftp::FTPAccess;
pub use net_scanner::{http_scanner::HttpResponseData, https_scanner::HttpsResponse, result_handler::ScanTaskInfo, tcp_scanner::{ftp::FTPScanResult, ssh::SSHScannResult}};
pub use stats_mornitor::{SystemStats};
pub use scheduler::SchedulerStats;
pub use vul_search::VulnInfo;
pub use config::*;

struct WorkerState {
    master_addr: String,
    scanner_handeler: Option<JoinHandle<()>>,
    analyser_handler: Option<JoinHandle<()>>,
}

impl WorkerState {
    fn abort(self) {
        if let Some(handler) = self.scanner_handeler {
            handler.abort();
        }
        if let Some(handler) = self.analyser_handler {
            handler.abort();
        }
    }
}

#[derive(Clone)]
pub struct WorkerService {
    scanner: NetScanner,
    analyser: ServiceAnalyseScheduler,
    sys_mornitor: SystemStatsMornitor,

    current_state: Arc<Mutex<Option<WorkerState>>>
}

impl WorkerService {
    pub async fn new() -> Result<Self, SimpleError>
    {
        let mongodb = mongodb::Client::with_uri_str(&GLOBAL_CONFIG.mongodb).await.unwrap();
        let db = mongodb.database("nscn");
        
        let proxy_pool = ProxyPool::new();
        proxy_pool.start().await;
        let scanner = NetScanner::new(&GLOBAL_CONFIG.redis, &db, &proxy_pool);
        
        stats_log(scanner.clone_stats());
        

        let analyser_scheduler = ServiceAnalyseScheduler::new(&db, &GLOBAL_CONFIG.redis).await.unwrap();
        // let _ = analyser_scheduler.run().await.unwrap();

        Ok(Self {
            scanner: scanner,
            analyser: analyser_scheduler,
            sys_mornitor: SystemStatsMornitor::start(),
            current_state: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn start(&self, master_addr: String) -> Result<(), SimpleError>{
        let current_master = {
            let guard = self.current_state.lock().await;
            guard.as_ref().map(|state| state.master_addr.to_owned()).unwrap_or(String::new())
        };
        if current_master != master_addr {
            self.abort().await;

            let state = WorkerState {
                analyser_handler: self.analyser.start(master_addr.clone()).log_error("start-analyser").ok(),
                scanner_handeler: self.scanner.start(master_addr.clone()).log_error("start-scanner").ok(),
                master_addr: master_addr
            };

            let mut guard = self.current_state.lock().await;
            *guard = Some(state);
            log::info!("New worker started");
        }

        Ok(())
    }

    async fn abort(&self) {
        let mut guard = self.current_state.lock().await;
        let state: Option<WorkerState> = mem::replace(&mut guard, None);
        if let Some(state) = state {
            state.abort();
            log::warn!("Abort running worker");
        } else {
            log::warn!("Abort No worker");
        }
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
}

#[derive(Clone)]
pub struct MasterService {
    scanner_scheduler: ScannerMasterScheduler,
    analyser_scheduler: MasterScheduler,
    workers: Arc<Mutex<Vec<String>>>,
    client: reqwest::Client,
}

#[derive(Serialize, Deserialize)]
pub struct WorkerStats {
    pub system: SystemStats,
    pub scanner: SchedulerStats,
    pub analyser: SchedulerStats,
}

impl MasterService {
    pub async fn new() -> Result<Self, SimpleError> {
        Ok(Self {
            scanner_scheduler: ScannerMasterScheduler::new().await?,
            analyser_scheduler: MasterScheduler::start("analysser", GLOBAL_CONFIG.redis.as_str()).await?,
            workers: Arc::new(Mutex::new(Vec::new())),
            client: reqwest::Client::new(),
        })
    }
    pub fn scanner(&self) -> &ScannerMasterScheduler {
        &self.scanner_scheduler
    }
    pub fn analyser(&self) -> &MasterScheduler {
        &self.analyser_scheduler
    }
    pub async fn workers(&self) -> Vec<String> {
        let guard= self.workers.lock().await;
        guard.to_owned()
    }
    pub async fn get_worker_stats(&self, addr: &str) -> Result<WorkerStats, SimpleError> {
        Ok(self.client.get(format!("http://{}/api/stats/all", addr))
            .send()
            .await?
            .json::<WorkerStats>()
            .await?)
    }
    pub async fn update_workers(&self, workers: Vec<String>) -> usize {
        let active_workers: Vec<String> = join_all(workers.into_iter()
            .map(|worker_addr| {
                let client = self.client.clone();
                async move {
                    let response = client.post(format!("http://{}/api/scheduler/master", worker_addr))
                    .json(&GLOBAL_CONFIG.listen)
                    .send()
                    .await;
                    match response {
                        Ok(response) if response.status() == StatusCode::OK => {
                            log::info!("Connected worker {}", worker_addr);
                            Some(worker_addr)
                        },
                        Ok(response) => {
                            log::error!("Failed to connect worker {}: {}", worker_addr, response.status());
                            None
                        },
                        Err(err) => {
                            log::error!("Failed to connect worker {}: {}", worker_addr, err);
                            None
                        }
                    }
                }
            }))
            .await
            .into_iter()
            .filter_map(|t|t)
            .collect();

        let mut guard = self.workers.lock().await;
        *guard = active_workers;
        log::info!("{} active workers", guard.len());

        guard.len()
    }
    

    pub fn config(&self) -> &'static Config{
        &GLOBAL_CONFIG
    }

    pub async fn fetch_address_list(&self, url: &str) -> Result<Vec<String>, SimpleError> {
        Ok(fetch_address_list(url).await?)
    }
}

fn stats_log(mornitor: SharedSchedulerStats) {
    let interval = 10.0;
    task::spawn(async move {
        let mut last_stats = SchedulerStats::default();
        loop {
            sleep(tokio::time::Duration::from_secs_f64(interval)).await;
            let stats = mornitor.clone_inner().await;
            if last_stats == stats {
                continue;
            }
            log::info!("Scan speed: {:.2} IP/s, {:.2} Tasks/s, {} IPs pending", stats.tasks_per_second, stats.jobs_per_second, stats.pending_tasks);
            last_stats = stats;
            
        }
    });
}