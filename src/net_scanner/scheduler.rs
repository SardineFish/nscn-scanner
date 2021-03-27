use std::{collections::HashMap, mem, ops::Range, sync::Arc, time::{Duration, Instant}};

use chrono::Utc;
use futures::{Future};
use mongodb::{Database, bson, options::{UpdateOptions}};
use redis::{AsyncCommands, RedisError, pipe};
use serde::{Serialize};
use tokio::{sync::{Mutex, mpsc::{Receiver, Sender, channel}}, task::{self, JoinHandle}, time::sleep};
use async_trait::async_trait;

use crate::error::*;
use super::{http_scanner::HttpScanTask, https_scanner::HttpsScanTask, tcp_scanner::scanner::TCPScanTask};
use super::{http_scanner::HttpResponseData, https_scanner::HttpsResponse, tcp_scanner::scanner::TCPScanResult};
use crate::config::{GLOBAL_CONFIG, ResultSavingOption};
use crate::proxy::proxy_pool::ProxyPool;

#[derive(Serialize)]
pub struct NetScanRecord {
    pub addr: String,
    pub last_update: bson::DateTime,
    pub scan: NetScanResult,
}

#[derive(Serialize)]
#[serde(tag="result", content="data")]
pub enum ScanResult<T> {
    Ok(T),
    Err(String),
}

impl<T: Serialize> From<Result<T, SimpleError>> for ScanResult<T> {
    fn from(result: Result<T, SimpleError>) -> Self {
        match result {
            Ok(data) => Self::Ok(data),
            Err(err) => Self::Err(err.msg),
        }
    }
}

#[derive(Serialize)]
pub struct NetScanResult {
    pub http: Option<ScanTaskInfo<HttpResponseData>>,
    pub https: Option<ScanTaskInfo<HttpsResponse>>,
    pub tcp: Option<HashMap<u16, TCPScanResult>>,
}

#[async_trait]
pub trait DispatchScanTask {
    async fn dispatch(addr: String, task_pool: &mut TaskPool);
}

#[derive(Serialize)]
pub struct ScanTaskInfo<T> {
    pub proxy: String,
    pub time: bson::DateTime,
    #[serde(flatten)]
    pub result: ScanResult<T>,
}

impl<T> ScanTaskInfo<T> {
    fn new(result: ScanResult<T>) -> Self {
        Self {
            proxy: "".to_owned(),
            time: Utc::now().into(),
            result,
        }
    }
    fn with_proxy(proxy: &str, result: ScanResult<T>) -> Self {
        Self {
            proxy: proxy.to_owned(),
            time: Utc::now().into(),
            result,
        }
    }
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
    pub http_time: f64,
    pub http_tasks: usize,
    pub https_time: f64,
    pub https_tasks: usize,
    pub ftp_time: f64,
    pub ftp_tasks: usize,
    pub ssh_time: f64,
    pub ssh_tasks: usize,
    pub task_time: f64,
    pub spawn_time: f64,
    pub active_tasks: usize,
    pub send_time: f64,
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
        let mut redis = self.redis.get_async_connection().await.unwrap();
        loop {
            let result: Result<(String, String), RedisError> = redis.brpop(KEY_TASK_QUEUE, 0).await;
            match result {
                Err(err) if err.is_timeout() => (),
                Err(err) => log::error!("Failed to pop https scanning task: {}", err),
                Ok((_, addr)) => {
                    self.dispatch(&addr).await
                }
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
    complete_sender: Sender<Instant>,
    complete_receiver: Receiver<Instant>,
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
    pub async fn spawn<T>(&mut self, future: T) where T : Future + Send + 'static, T::Output: Send + 'static {
        let start = Instant::now();
        let task_start = std::time::Instant::now();
        if self.running_tasks >= self.max_tasks {
            if self.interval_jitter {
                self.interval_jitter = false;
            }

            match self.complete_receiver.recv().await {
                Some(t) => {
                    let end = Instant::now();
                    {
                        let mut guard = self.stats.lock().await;
                        guard.send_time += (end - t).as_secs_f64();
                    }
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
        let stats = self.stats.clone();
        task::spawn(async move {
            let end = std::time::Instant::now();
            {
                let mut guard = stats.lock().await;
                guard.task_time += (end - task_start).as_secs_f64();
            }
            future.await;
            // sleep(Duration::from_secs(5)).await;
            complete_sender.send(Instant::now()).await.log_error_consume("result-saving");
            {
                let mut guard = stats.lock().await;
                guard.active_tasks -= 1;
            }
        });
        let end = Instant::now();
        {
            let mut guard = self.stats.lock().await;
            guard.spawn_time += (end - start).as_secs_f64();
            guard.active_tasks += 1;
        }
        {
            let mut guard = self.stats.lock().await;
            guard.dispatched_tasks += 1;
        }
    }
}


enum ScanTask {
    ClearTasks,
    IPRange(Range<u32>),
    IPAddr(String),
}

const KEY_TASK_QUEUE: &str = "task_queue";

pub struct SchedulerController {
    join_scheduler: Option<JoinHandle<()>>,
    join_receiver: Option<JoinHandle<()>>,
    task_sender: Sender<ScanTask>,
    scheduler_stats: Arc<Mutex<SchedulerStats>>,
}

impl SchedulerController {
    pub async fn enqueue_addr(&self, addr: &str) -> Result<(), SimpleError> {
        self.task_sender.send(ScanTask::IPAddr(addr.to_owned())).await?;
        Ok(())
    }
    pub async fn enqueue_range(&self, ip_range: Range<u32>) -> Result<(), SimpleError> {
        self.task_sender.send(ScanTask::IPRange(ip_range)).await?;
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
            guard.active_tasks = stats.active_tasks;
        }
        stats
    }

    async fn receive_task(redis: redis::Client, mut receiver: Receiver<ScanTask>) {
        let mut redis = redis.get_async_connection().await.unwrap();
        while let Some(task) = receiver.recv().await {
            match task {
                ScanTask::IPRange(range) => match Self::try_enqueue_tasks(&mut redis, range).await {
                    Ok(_) => (),
                    err => err.log_error("task-receiver").unwrap(),
                },
                ScanTask::IPAddr(addr) => 
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
    async fn try_enqueue_tasks(redis: &mut redis::aio::Connection, range: Range<u32>) -> Result<(), SimpleError> {
        while redis.llen::<'_, _, i64>(KEY_TASK_QUEUE).await? > 5_000_000 {
            sleep(tokio::time::Duration::from_secs(60)).await;
        }
        let mut pipe = pipe();
        for ip in range {
            let addr = std::net::Ipv4Addr::from(ip).to_string();
            pipe.lpush(KEY_TASK_QUEUE, &addr).ignore();
        }
        pipe.query_async(redis).await?;
        Ok(())
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
}

#[derive(Clone)]
pub struct ResultHandler {
    db: Database,
}

impl ResultHandler {
    pub async fn save<T: Serialize>(&self, key: &str, ip_addr: &str, proxy: &str, result: ScanResult<T>) {
        self.try_save(key, ip_addr, proxy, result).await.log_error_consume("result-saving");
    }
    async fn try_save<T: Serialize>(&self, key: &str, ip_addr: &str, proxy: &str, result: ScanResult<T>) -> Result<(), SimpleError> {
        let collection = match &GLOBAL_CONFIG.scanner.save {
            ResultSavingOption::SingleCollection(collection) => self.db.collection(&collection),
            _ => panic!("Not implement"),
        };
        let key = format!("scan.{}", key);
        let info = ScanTaskInfo {
            proxy: proxy.to_owned(),
            time: Utc::now().into(),
            result,
        };

        let doc = bson::doc! {
            "$set": {
                "addr": ip_addr,
                "last_update": bson::to_bson(&bson::DateTime::from(Utc::now()))?,
                key: bson::to_bson(&info)?,
            }
        };
        let query = bson::doc! {
            "addr": ip_addr,
        };
        let mut opts = UpdateOptions::default();
        opts.upsert = Some(true);
        collection.update_one(query, doc, opts).await?;

        Ok(())
    }
}