use std::{net::Ipv4Addr};

use futures::{future::join, pin_mut};
use mongodb::{Database};
use tokio::{task::{self, JoinHandle}};

use crate::{ScannerConfig, SchedulerStats, config, error::*, scheduler::{SharedSchedulerInternalStats, SharedSchedulerStats, local_scheduler::LocalScheduler}};
use super::{http_scanner::HttpScanTask, https_scanner::HttpsScanTask, result_handler::ResultHandler, scanner::TcpScanTask, tcp_scanner::scanner::TCPScanTask};
use crate::proxy::proxy_pool::ProxyPool;

#[derive(Clone)]
pub struct NetScanner {
    redis_url: String,
    db: Database,
    resources: ScannerResources,
    stats: SharedSchedulerStats,
}

impl NetScanner {
    pub fn new(redis_url: &str, db: &Database, proxy_pool: &ProxyPool) -> Self {
        let internal_stats = SharedSchedulerInternalStats::new();
        let stats = SharedSchedulerStats::new();
        Self {
            redis_url: redis_url.to_owned(),
            db: db.clone(),
            resources: ScannerResources {
                proxy_pool: proxy_pool.clone(),
                result_handler: ResultHandler {
                    db: db.clone(),
                },
                stats: internal_stats,
                // analyser: ServiceAnalyser::new().unwrap(),
                // vuln_searcher: VulnerabilitiesSearch::new(),
            },
            stats,
        }
    }
    pub fn start(&self, master_addr: String, config: ScannerConfig) -> Result<JoinHandle<()>, SimpleError> {
        let scheduler = Scheduler::start(master_addr, self.resources.clone(), config);
        let mornitor = self.resources.stats.clone().start_mornitor(self.stats.clone(), 5.0);
        Ok(task::spawn(async move {
            pin_mut!(scheduler);
            pin_mut!(mornitor);
            join(scheduler, mornitor).await;
        }))
    }
    pub fn clone_stats(&self) -> SharedSchedulerStats {
        self.stats.clone()
    }
    pub async fn stats(&self) -> SchedulerStats {
        self.stats.clone_inner().await
    }
    
    pub async fn reset_stats(&self) {
        self.stats.reset().await
    }
}

// #[derive(Clone, Debug, Default, Serialize)]
// pub struct SchedulerStats { 
//     pub dispatched_addrs: usize,
//     pub dispatched_tasks: usize,
//     pub pending_address: usize,
//     // pub http_time: f64,
//     // pub http_tasks: usize,
//     // pub https_time: f64,
//     // pub https_tasks: usize,
//     // pub ftp_time: f64,
//     // pub ftp_tasks: usize,
//     // pub ssh_time: f64,
//     // pub ssh_tasks: usize,
//     // pub task_time: f64,
//     // pub spawn_time: f64,
//     // pub active_tasks: usize,
//     // pub send_time: f64,
// }


pub struct Scheduler {
    local_scheduler: LocalScheduler,
    task_pool: crate::scheduler::TaskPool<ScannerResources>,
    resources: ScannerResources,
    config: config::ScannerConfig,
    // pub proxy_pool: ProxyPool,
}
impl Scheduler {
    async fn start(master_addr: String, resources: ScannerResources, config: config::ScannerConfig) {
        let (local_scheduler, fetch_task)= 
            LocalScheduler::start("scanner".to_owned(), master_addr, &config.scheduler);
        
        let resource_pool = vec![resources.clone(); config.scheduler.max_tasks];

        let task_pool = crate::scheduler::TaskPool::new(
            config.scheduler.max_tasks, 
            resources.stats.clone(), 
            resource_pool);

        let scheduler = Self {
            local_scheduler,
            resources: resources.clone(),
            task_pool: task_pool,
            config,
        };
        join(scheduler.schedule_loop(), fetch_task).await;
    }
    async fn schedule_loop(mut self) {
        if !self.config.scheduler.enabled {
            return ;
        }
        loop {
            let ip_cidr = self.local_scheduler.fetch_task().await;
            self.dispatch_addrs(&ip_cidr).await;
            self.local_scheduler.complete_task(ip_cidr).await;
        }
    }
    async fn dispatch_addrs(&mut self, cidr: &str) {
        match crate::address::parse_ipv4_cidr(cidr) {
            Err(err) => log::error!("Failed to parse CIDR ip range: {}", err.msg),
            Ok(range) => {
                self.resources.stats.update_pending_tasks(range.len()).await;
                for ip_32 in range {
                    let addr = Ipv4Addr::from(ip_32).to_string();
                    self.dispatch(&addr).await;
                }
                // log::info!("Address {} completed.", ip_cidr);
            }
        }
    }
    async fn dispatch(&mut self, addr: &str) {
        if self.config.http.enabled {
            TcpScanTask::new(addr.to_owned(), 80, HttpScanTask(addr.to_owned(), 80)).schedule(&mut self.task_pool).await;
            // self.task_pool.spawn("http-scan", HttpScanTask::run, addr.to_owned()).await;
        }
        if self.config.https.enabled {
            TcpScanTask::new(addr.to_owned(), 443, HttpsScanTask).schedule(&mut self.task_pool).await;
            // self.task_pool.spawn("https-scan", HttpsScanTask::run, addr.to_owned()).await;
        }
        if self.config.tcp.enabled {
            TCPScanTask::dispatch(addr.to_owned(), &mut self.task_pool).await;
        }
        self.resources.stats.dispatch_tasks(1).await;
    }
}

enum ScanTask {
    ClearTasks,
    // IPRange(Range<u32>),
    IPCIDR(String),
}

const KEY_TASK_QUEUE: &str = "task_queue";
const KEY_RUNNING_TASKS: &str = "running_tasks";

#[derive(Clone)]
pub struct ScannerResources {
    pub proxy_pool: ProxyPool,
    pub result_handler: ResultHandler,
    pub stats: SharedSchedulerInternalStats,
    // pub stats: Arc<Mutex<SchedulerStats>>,
    // pub analyser: ServiceAnalyser,
}