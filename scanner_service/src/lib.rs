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
use serde_json::json;
use stats_mornitor::{SystemStatsMornitor};
use tokio::{sync::{Mutex}, task::{self, JoinHandle}, time::sleep};

use error::*;

pub use service_analyse::{scheduler::ServiceAnalyseScheduler, scheduler::ServiceRecord, ServiceAnalyseResult, ip_geo::IPGeoData};
pub use config::Config;
pub use net_scanner::result_handler::NetScanRecord;
pub use address::{parse_ipv4_cidr};
pub use net_scanner::tcp_scanner::ftp::FTPAccess;
pub use net_scanner::{http_scanner::HttpResponseData, https_scanner::HttpsResponse, result_handler::ScanTaskInfo, tcp_scanner::{ftp::FTPScanResult, ssh::SSHScannResult}};
pub use stats_mornitor::{SystemStats};
pub use scheduler::SchedulerStats;
pub use vul_search::VulnInfo;
pub use config::*;

pub struct WorkerState {
    pub master_addr: String,
    scanner_handeler: Option<JoinHandle<()>>,
    analyser_handler: Option<JoinHandle<()>>,
    pub scanner_config: ScannerConfig,
    pub analyser_config: ServiceAnalyserOptions,
}

impl Clone for WorkerState {
    fn clone(&self) -> Self {
        Self {
            master_addr: self.master_addr.clone(),
            analyser_config: self.analyser_config.clone(),
            scanner_config: self.scanner_config.clone(),
            analyser_handler: None,
            scanner_handeler: None,
        }
    }
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
    runtime: Arc<tokio::runtime::Runtime>,
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
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
            
        // let _ = analyser_scheduler.run().await.unwrap();

        Ok(Self {
            scanner: scanner,
            analyser: analyser_scheduler,
            sys_mornitor: SystemStatsMornitor::start(),
            current_state: Arc::new(Mutex::new(None)),
            runtime: Arc::new(rt),
        })
    }

    pub async fn start(&self, master_addr: String, scanner_config: ScannerConfig, analyser_config: ServiceAnalyserOptions) -> Result<(), SimpleError>{
        let _guard = self.runtime.enter();
        let should_restart = {
            let guard = self.current_state.lock().await;
            match guard.as_ref() {
                Some(state)  
                    if state.master_addr != master_addr 
                    || state.scanner_config != scanner_config 
                    || state.analyser_config != analyser_config => true,
                None => true,
                _ => false,
            }
        };
        if should_restart {
            self.abort().await;

            self.scanner.reset_stats().await;
            self.analyser.reset_stats().await;
            let state = WorkerState {
                analyser_handler: match analyser_config.scheduler.enabled {
                    true => self.analyser.start(master_addr.clone(), analyser_config.clone()).log_error("start-analyser").ok(),
                    false => None,
                },
                scanner_handeler: match scanner_config.scheduler.enabled {
                    true => self.scanner.start(master_addr.clone(), scanner_config.clone()).log_error("start-scanner").ok(),
                    false => None,
                },
                master_addr,
                scanner_config,
                analyser_config
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

    pub async fn connect_master(&self, master_addr: &str) -> Result<(), SimpleError> {
        let response = reqwest::Client::new().post(format!("http://{}/api/scheduler/worker", master_addr))
            .json(&GLOBAL_CONFIG.listen)
            .send()
            .await?;
        match response.status() {
            StatusCode::OK => Ok(()),
            status => Err(format!("Failed to connect master: {}", status))?,
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

    pub async fn current_state(&self) -> Option<WorkerState> {
        self.current_state.lock().await.clone()
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
                    let response = client.post(format!("http://{}/api/scheduler/setup", worker_addr))
                    .json(&json!({"master_addr": &GLOBAL_CONFIG.listen}))
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
    pub async fn add_worker(&self, worker_addr: String) -> Result<(), SimpleError> {
        let response = self.client.post(format!("http://{}/api/scheduler/setup", worker_addr))
            .json(&json!({"master_addr": &GLOBAL_CONFIG.listen}))
            .send()
            .await;
        match response {
            Ok(response) if response.status() == StatusCode::OK => {
                log::info!("Connected worker {}", worker_addr);
                let mut guard = self.workers.lock().await;
                guard.push(worker_addr);
                Ok(())
            },
            Ok(response) => {
                log::error!("Failed to connect worker {}: {}", worker_addr, response.status());
                Err(format!("Failed to connect worker {}: {}", worker_addr, response.status()))?
            },
            Err(err) => {
                log::error!("Failed to connect worker {}: {}", worker_addr, err);
                Err(format!("Failed to connect worker {}: {}", worker_addr, err))?
            }
        }
    }
    

    pub fn config(&self) -> &'static Config{
        &GLOBAL_CONFIG
    }

    pub fn http_client(&self) -> &reqwest::Client {
        &self.client
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