use std::{mem, net::Ipv4Addr, sync::Arc, time::{Duration}};

use futures::{Future};
use mongodb::{Database};
use redis::{AsyncCommands, RedisError, pipe};
use tokio::{sync::{Mutex, mpsc::{Receiver, Sender, channel}}, task::{self, JoinHandle}, time::{sleep, timeout}};
use async_trait::async_trait;

use crate::{error::*, service_analyse::scheduler::ServiceAnalyser};
use super::{http_scanner::HttpScanTask, https_scanner::HttpsScanTask, result_handler::ResultHandler, tcp_scanner::scanner::TCPScanTask};
use crate::config::{GLOBAL_CONFIG};
use crate::proxy::proxy_pool::ProxyPool;



#[async_trait]
pub trait DispatchScanTask {
    async fn dispatch(addr: String, task_pool: &mut TaskPool);
}

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
                analyser: ServiceAnalyser::new().unwrap(),
            }
        }
    }
    pub fn start(&self) -> Result<SchedulerController, SimpleError> {
        let (sender, receiver) = channel(64);
        let scheduler = Scheduler::new(&self.redis_url, &self.resources)?;
        let redis = redis::Client::open(self.redis_url.as_str())?;
        let controller = SchedulerController {
            scheduler_stats: scheduler.resources.stats.clone(),
            join_receiver: Some(task::spawn(SchedulerController::receive_task(redis, receiver))),
            join_scheduler: Some(task::spawn(scheduler.start())),
            task_sender: sender,
        };
        Ok(controller)
    }
}

#[derive(Clone, Default)]
pub struct SchedulerStats { 
    pub dispatched_addrs: usize,
    pub dispatched_tasks: usize,
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
    redis: redis::Client,
    task_pool: TaskPool,
    resources: ScannerResources,
    // pub proxy_pool: ProxyPool,
}
impl Scheduler {
    fn new(redis_url: &str, resources: &ScannerResources) -> Result<Self, SimpleError> {
        Ok(Self {
            redis: redis::Client::open(redis_url)?,
            task_pool: TaskPool::new(GLOBAL_CONFIG.scanner.scheduler.max_tasks, &resources.stats),
            resources: resources.clone(),
        })
    }
    async fn start(mut self) {
        if !GLOBAL_CONFIG.scanner.scheduler.enabled {
            return ;
        }
        let mut redis = self.redis.get_async_connection().await.unwrap();
        self.recover_tasks().await;
        loop {
            let result: Result<String, RedisError> = redis.brpoplpush(KEY_TASK_QUEUE, KEY_RUNNING_TASKS, 0).await;
            let ip_cidr = match result {
                Err(err) => {
                    log::error!("Failed to pop https scanning task: {}", err);
                    sleep(Duration::from_secs(3)).await;
                    continue;
                },
                Ok(ip_cidr) => ip_cidr,
            };
            self.dispatch_addrs(&ip_cidr).await;
            let result: Result<usize, RedisError> = redis.lrem(KEY_RUNNING_TASKS, 1, &ip_cidr).await;
            match result {
                Ok(1) => (),
                Ok(n) => log::error!("Failed to remove running tasks: Unexpected return {}", n),
                Err(err) => log::error!("Failed to remove running task: {}", err),
            };
            
        }
    }
    async fn recover_tasks(&mut self) {
        let mut redis = self.redis.get_async_connection().await.unwrap();
        loop {
            let result: Result<Option<String>, RedisError> = redis.rpoplpush(KEY_RUNNING_TASKS, KEY_TASK_QUEUE).await;
            match result {
                Ok(Some(addr_cidr)) => log::warn!("Recovered unfinished task {}", addr_cidr),
                Ok(None) => break,
                Err(err) => {
                    log::error!("Failed to fetch task from redis: {}", err);
                    sleep(Duration::from_secs(3)).await;
                }
            }
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
    pub async fn spawn<T>(&mut self, name: &'static str, future: T) where T : Future + Send + 'static, T::Output: Send + 'static {
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
            if let Err(_) = timeout(Duration::from_secs(60), future).await {
                log::error!("Task {} suspedned over 60s", name);
            }
            // sleep(Duration::from_secs(5)).await;
            complete_sender.send(()).await.log_error_consume("result-saving");
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

pub struct SchedulerController {
    join_scheduler: Option<JoinHandle<()>>,
    join_receiver: Option<JoinHandle<()>>,
    task_sender: Sender<ScanTask>,
    scheduler_stats: Arc<Mutex<SchedulerStats>>,
}

impl SchedulerController {
    // pub async fn enqueue_addr(&self, addr: &str) -> Result<(), SimpleError> {
    //     self.task_sender.send(ScanTask::IPCIDR(addr.to_owned())).await?;
    //     Ok(())
    // }
    // pub async fn enqueue_range(&self, ip_range: Range<u32>) -> Result<(), SimpleError> {
    //     self.task_sender.send(ScanTask::IPRange(ip_range)).await?;
    //     Ok(())
    // }
    pub async fn enqueue_addr_range(&self, cidr_addr: &str) -> Result<(), SimpleError> {
        self.task_sender.send(ScanTask::IPCIDR(cidr_addr.to_owned())).await?;
        Ok(())
    }
    pub async fn join(self) {
        match (self.join_receiver, self.join_scheduler) {
            (Some(join_receiver), Some(join_scheduler)) => {
                join_receiver.await.log_error_consume("join-task-receiver");
                join_scheduler.await.log_error_consume("join-scheduler");
            },
            _ => log::warn!("Cannot join from copies of controller."),
        }
    }
    pub async fn clear_tasks(&self) -> Result<(), SimpleError> {
        self.task_sender.send(ScanTask::ClearTasks).await?;
        Ok(())
    }
    pub async fn stats(&self) -> SchedulerStats {
        let guard = self.scheduler_stats.lock().await;
        guard.clone()
    }
    pub async fn reset_stats(&self) -> SchedulerStats {
        let mut stats = SchedulerStats::default();
        {
            let mut guard = self.scheduler_stats.lock().await;
            mem::swap(&mut stats, &mut guard);
        }
        stats
    }

    async fn receive_task(redis: redis::Client, mut receiver: Receiver<ScanTask>) {
        let mut redis = redis.get_async_connection().await.unwrap();
        while let Some(task) = receiver.recv().await {
            match task {
                ScanTask::IPCIDR(addr) => 
                    pipe().lpush(KEY_TASK_QUEUE, addr).ignore()
                    .query_async::<_, ()>(&mut redis)
                    .await
                    .log_error_consume("task-receiver"),
                ScanTask::ClearTasks => 
                    pipe().del(KEY_TASK_QUEUE).ignore()
                    .query_async::<_, ()>(&mut redis)
                    .await
                    .log_error_consume("task-receiver"),
            }
            
        }
    }
}

impl Clone for SchedulerController {
    fn clone(&self) -> Self {
        Self {
            join_receiver: None,
            join_scheduler: None,
            scheduler_stats: self.scheduler_stats.clone(),
            task_sender: self.task_sender.clone(),
        }
    }
}

#[derive(Clone)]
pub struct ScannerResources {
    pub proxy_pool: ProxyPool,
    pub result_handler: ResultHandler,
    pub stats: Arc<Mutex<SchedulerStats>>,
    pub analyser: ServiceAnalyser,
}