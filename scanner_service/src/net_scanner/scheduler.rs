use std::{net::Ipv4Addr, sync::Arc, time::{Duration}};

use serde::{Serialize};
use futures::{Future};
use mongodb::{Database};
use redis::{AsyncCommands, RedisError, pipe};
use tokio::{sync::{Mutex, mpsc::{Receiver, Sender, channel}}, task::{self, JoinHandle}, time::{sleep}};
use async_trait::async_trait;

use crate::{error::*, parse_ipv4_cidr, scheduler::local_scheduler::LocalScheduler};
use super::{http_scanner::HttpScanTask, https_scanner::HttpsScanTask, result_handler::ResultHandler, tcp_scanner::scanner::TCPScanTask};
use crate::config::{GLOBAL_CONFIG};
use crate::proxy::proxy_pool::ProxyPool;

#[async_trait]
pub trait DispatchScanTask {
    async fn dispatch(addr: String, task_pool: &mut TaskPool);
}

#[derive(Clone)]
pub struct NetScanner {
    redis_url: String,
    db: Database,
    resources: ScannerResources,
}

impl NetScanner {
    pub fn new(redis_url: &str, db: &Database, proxy_pool: &ProxyPool) -> Self {
        Self {
            redis_url: redis_url.to_owned(),
            db: db.clone(),
            resources: ScannerResources {
                proxy_pool: proxy_pool.clone(),
                result_handler: ResultHandler {
                    db: db.clone(),
                },
                stats: Arc::new(Mutex::new(SchedulerStats::default())),
                // analyser: ServiceAnalyser::new().unwrap(),
                // vuln_searcher: VulnerabilitiesSearch::new(),
            }
        }
    }
    pub fn start(&self, master_addr: String) -> Result<JoinHandle<()>, SimpleError> {
        // let (sender, receiver) = channel(64);
        let scheduler = Scheduler::new(master_addr, &self.resources)?;
        Ok(task::spawn(scheduler.start()))
    }
    pub fn stats(&self) -> Arc<Mutex<SchedulerStats>> {
        self.resources.stats.clone()
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SchedulerStats { 
    pub dispatched_addrs: usize,
    pub dispatched_tasks: usize,
    pub pending_address: usize,
    // pub http_time: f64,
    // pub http_tasks: usize,
    // pub https_time: f64,
    // pub https_tasks: usize,
    // pub ftp_time: f64,
    // pub ftp_tasks: usize,
    // pub ssh_time: f64,
    // pub ssh_tasks: usize,
    // pub task_time: f64,
    // pub spawn_time: f64,
    // pub active_tasks: usize,
    // pub send_time: f64,
}

pub struct Scheduler {
    local_scheduler: LocalScheduler,
    task_pool: TaskPool,
    resources: ScannerResources,
    // pub proxy_pool: ProxyPool,
}
impl Scheduler {
    fn new(master_addr: String, resources: &ScannerResources) -> Result<Self, SimpleError> {
        Ok(Self {
            local_scheduler: LocalScheduler::new(master_addr, &GLOBAL_CONFIG.scanner.scheduler),
            task_pool: TaskPool::new(GLOBAL_CONFIG.scanner.scheduler.max_tasks, &resources.stats),
            resources: resources.clone(),
        })
    }
    async fn start(mut self) {
        if !GLOBAL_CONFIG.scanner.scheduler.enabled {
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
                // log::info!("Scanning {} with {} IPs", cidr, range.len());
                for ip_32 in range {
                    let addr = Ipv4Addr::from(ip_32).to_string();
                    self.dispatch(&addr).await;
                }
                // log::info!("Address {} completed.", ip_cidr);
            }
        }
    }
    async fn dispatch(&mut self, addr: &str) {
        if GLOBAL_CONFIG.scanner.http.enabled {
            HttpScanTask::dispatch(addr, &self.resources, &mut self.task_pool).await;
        }
        if GLOBAL_CONFIG.scanner.https.enabled {
            HttpsScanTask::spawn(addr, &self.resources, &mut self.task_pool).await;
        }
        if GLOBAL_CONFIG.scanner.tcp.enabled {
            TCPScanTask::dispatch(addr, &self.resources, &mut self.task_pool).await;
        }
        {
            let mut guard = self.resources.stats.lock().await;
            guard.dispatched_addrs += 1;
            if guard.pending_address > 0 {
                guard.pending_address -=1;   
            }
        }
    }
}

pub struct TaskPool {
    interval_jitter: bool,
    max_tasks: usize,
    running_tasks: usize,
    complete_sender: Sender<()>,
    complete_receiver: Receiver<()>,
    stats: Arc<Mutex<SchedulerStats>>,
}
impl TaskPool {
    pub fn new(max_tasks: usize, stats: &Arc<Mutex<SchedulerStats>>,) -> Self {
        let (sender, receiver) = channel(max_tasks * 2);
        Self {
            max_tasks,
            interval_jitter: true,
            running_tasks: 0,
            complete_sender: sender,
            complete_receiver: receiver,
            stats: stats.clone(),
        }
    }
    pub async fn spawn<T>(&mut self, _name: &'static str, future: T) where T : Future + Send + 'static, T::Output: Send + 'static {
        if self.running_tasks >= self.max_tasks {
            if self.interval_jitter {
                self.interval_jitter = false;
            }

            match self.complete_receiver.recv().await {
                Some(_) => {
                    self.running_tasks -= 1
                },
                None => panic!("Scheduler channel closed."),
            }
        }
        if self.interval_jitter {
            let interval = 5.0 / (GLOBAL_CONFIG.scanner.scheduler.max_tasks as f64);
            sleep(Duration::from_secs_f64(interval)).await;
        }
        
        self.running_tasks += 1;
        let complete_sender = self.complete_sender.clone();
        task::spawn(async move {
            future.await;
            // if let Err(_) = timeout(Duration::from_secs(300), future).await {
            //     log::error!("Task {} suspedned over 300s", name);
            // }
            // sleep(Duration::from_secs(5)).await;
            complete_sender.send(()).await.log_error_consume("scan-scheduler");
        });
        {
            let mut guard = self.stats.lock().await;
            guard.dispatched_tasks += 1;
        }
    }
}


enum ScanTask {
    ClearTasks,
    // IPRange(Range<u32>),
    IPCIDR(String),
}

const KEY_TASK_QUEUE: &str = "task_queue";
const KEY_RUNNING_TASKS: &str = "running_tasks";

// pub struct SchedulerController {
//     redis: redis::Client,
//     join_scheduler: Option<JoinHandle<()>>,
//     // join_receiver: Option<JoinHandle<()>>,
//     task_sender: Sender<ScanTask>,
//     scheduler_stats: Arc<Mutex<SchedulerStats>>,
// }

// impl SchedulerController {
//     pub fn start_scheduler(master_addr: String) {
//         let scheduler = Scheduler::new(master_addr, resources)
//     }
//     // pub async fn enqueue_addr(&self, addr: &str) -> Result<(), SimpleError> {
//     //     self.task_sender.send(ScanTask::IPCIDR(addr.to_owned())).await?;
//     //     Ok(())
//     // }
//     // pub async fn enqueue_range(&self, ip_range: Range<u32>) -> Result<(), SimpleError> {
//     //     self.task_sender.send(ScanTask::IPRange(ip_range)).await?;
//     //     Ok(())
//     // }
//     // pub async fn enqueue_addr_range(&self, cidr_addr: &str) -> Result<(), SimpleError> {
//     //     self.task_sender.send(ScanTask::IPCIDR(cidr_addr.to_owned())).await?;
//     //     Ok(())
//     // }
//     pub async fn join(self) {
//         match self.join_scheduler {
//             Some(join) => join.await.log_error_consume("join-task-receiver"),
//             _ => log::warn!("Cannot join from copies of controller."),
//         }
//     }
//     pub fn stats(&self) -> Arc<Mutex<SchedulerStats>> {
//         self.scheduler_stats.clone()
//     }
//     // pub async fn reset_stats(&self) -> SchedulerStats {
//     //     let mut stats = SchedulerStats::default();
//     //     {
//     //         let mut guard = self.scheduler_stats.lock().await;
//     //         mem::swap(&mut stats, &mut guard);
//     //         guard.pending_address = stats.pending_address;
//     //     }
//     //     stats
//     // }
//     // pub async fn get_pending_tasks(&self, skip: isize, count: isize) -> Result<Vec<String>, SimpleError> {
//     //     let mut redis = self.redis.get_async_connection().await?;
//     //     let result:Vec<String> = redis.lrange(KEY_TASK_QUEUE, -skip - count, -skip - 1).await?;

//     //     Ok(result)
//     // }
//     // pub async fn clear_tasks(&self) -> Result<usize, SimpleError> {
//     //     let mut redis = self.redis.get_async_connection().await?;
//     //     let count: usize = redis.llen(KEY_TASK_QUEUE).await?;

//     //     self.task_sender.send(ScanTask::ClearTasks).await?;

//     //     Ok(count)
//     // }
//     // pub async fn remove_task(&self, task: &str) -> Result<usize, SimpleError> {
//     //     let mut redis = self.redis.get_async_connection().await?;
//     //     let count: usize = redis.lrem(KEY_TASK_QUEUE, -1, task).await?;

//     //     let range = parse_ipv4_cidr(&task)?;

//     //     let mut guard = self.scheduler_stats.lock().await;
//     //     if guard.pending_address < range.len() {
//     //         guard.pending_address = 0;
//     //     } else {
//     //         guard.pending_address -= range.len() * count;
//     //     }

//     //     Ok(count)
//     // }

//     // async fn receive_task(redis: redis::Client, mut receiver: Receiver<ScanTask>, stats: Arc<Mutex<SchedulerStats>>) {
//     //     let mut redis = redis.get_async_connection().await.unwrap();
//     //     while let Some(task) = receiver.recv().await {
//     //         match task {
//     //             ScanTask::IPCIDR(addr) => {
//     //                 pipe().lpush(KEY_TASK_QUEUE, &addr).ignore()
//     //                 .query_async::<_, ()>(&mut redis)
//     //                 .await
//     //                 .log_error_consume("task-receiver");

//     //                 if let Ok(range) = parse_ipv4_cidr(&addr).log_error("task-receiver") {
//     //                     let mut guard = stats.lock().await;
//     //                     guard.pending_address += range.len();
//     //                 }
//     //             },
//     //             ScanTask::ClearTasks => {
//     //                 pipe().del(KEY_TASK_QUEUE).ignore()
//     //                 .query_async::<_, ()>(&mut redis)
//     //                 .await
//     //                 .log_error_consume("task-receiver");

//     //                 let mut guard = stats.lock().await;
//     //                 guard.pending_address = 0;

//     //             },
//     //         }
            
//     //     }
//     // }
// }

// impl Clone for SchedulerController {
//     fn clone(&self) -> Self {
//         Self {
//             redis: self.redis.clone(),
//             join_scheduler: None,
//             scheduler_stats: self.scheduler_stats.clone(),
//             task_sender: self.task_sender.clone(),
//         }
//     }
// }

#[derive(Clone)]
pub struct ScannerResources {
    pub proxy_pool: ProxyPool,
    pub result_handler: ResultHandler,
    pub stats: Arc<Mutex<SchedulerStats>>,
    // pub analyser: ServiceAnalyser,
}