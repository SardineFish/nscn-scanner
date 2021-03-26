use std::{collections::HashMap, ops::Range};

use chrono::Utc;
use futures::{Future};
use mongodb::{Collection, Database, bson, options::{FindOneAndUpdateOptions, UpdateOptions}};
use redis::{AsyncCommands, RedisError, pipe};
use serde::{Serialize};
use tokio::{sync::mpsc::{Receiver, Sender, channel}, task::{self, JoinHandle}, time::sleep};
use async_trait::async_trait;

use crate::{error::*, http_scanner::HttpScanTask, https_scanner::HttpsScanTask, tcp_scanner::scanner::TCPScanTask};
use crate::{http_scanner::HttpResponseData, https_scanner::HttpsResponse, proxy::ProxyPool, tcp_scanner::scanner::TCPScanResult};
use crate::config::{GLOBAL_CONFIG, ResultSavingOption};

#[derive(Serialize)]
pub struct NetScanRecord {
    pub addr: String,
    pub proxy: String,
    pub time: bson::DateTime,
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
    pub http: Option<ScanResult<HttpResponseData>>,
    pub https: Option<ScanResult<HttpsResponse>>,
    pub tcp: Option<HashMap<u16, TCPScanResult>>,
}

#[async_trait]
pub trait DispatchScanTask {
    async fn dispatch(addr: String, task_pool: &mut TaskPool);
}

pub struct NetScanner {
    redis_url: String,
    proxy_pool: ProxyPool,
    db: Database
}

impl NetScanner {
    pub fn new(redis_url: &str, db: &Database, proxy_pool: &ProxyPool) -> Self {
        Self {
            redis_url: redis_url.to_owned(),
            db: db.clone(),
            proxy_pool: proxy_pool.clone(),
        }
    }
    pub fn start(&self) -> Result<SchedulerController, SimpleError> {
        let (sender, receiver) = channel(64);
        let scheduler = Scheduler {
            redis: redis::Client::open(self.redis_url.as_str())?,
            task_pool: TaskPool::new(GLOBAL_CONFIG.scanner.scheduler.max_tasks),
            resources: ScannerResources {
                proxy_pool: self.proxy_pool.clone(),
                result_handler: ResultHandler {
                    db: self.db.clone(),
                }
            }
        };
        let controller = SchedulerController {
            join_receiver: task::spawn(SchedulerController::receive_task(redis::Client::open(self.redis_url.as_str())?, receiver)),
            join_scheduler: task::spawn(scheduler.start()),
            task_sender: sender
        };
        Ok(controller)
    }
}

pub struct Scheduler {
    redis: redis::Client,
    task_pool: TaskPool,
    resources: ScannerResources,
    // pub proxy_pool: ProxyPool,
}
impl Scheduler {
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
    }
}

pub struct TaskPool {
    max_tasks: usize,
    running_tasks: usize,
    complete_sender: Sender<bool>,
    complete_receiver: Receiver<bool>,
}
impl TaskPool {
    pub fn new(max_tasks: usize) -> Self {
        let (sender, receiver) = channel(max_tasks);
        Self {
            max_tasks,
            running_tasks: 0,
            complete_sender: sender,
            complete_receiver: receiver,
        }
    }
    pub async fn spawn<T>(&mut self, future: T) where T : Future + Send + 'static, T::Output: Send + 'static {
        if self.running_tasks >= self.max_tasks {
            match self.complete_receiver.recv().await {
                Some(_) => self.running_tasks -= 1,
                None => panic!("Scheduler channel closed."),
            }
            self.running_tasks += 1;
            let complete_sender = self.complete_sender.clone();
            task::spawn(async move {
                future.await;
                complete_sender.send(true).await;
            });
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
    join_scheduler: JoinHandle<()>,
    join_receiver: JoinHandle<()>,
    task_sender: Sender<ScanTask>,
}

impl SchedulerController {
    pub async fn enqueue_range(&self, ip_range: Range<u32>) -> Result<(), SimpleError> {
        self.task_sender.send(ScanTask::IPRange(ip_range)).await?;
        Ok(())
    }
    pub async fn join(self) {
        self.join_receiver.await;
        self.join_scheduler.await;
    }
    pub async fn clear_tasks(&self) -> Result<(), SimpleError> {
        self.task_sender.send(ScanTask::ClearTasks).await?;
        Ok(())
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

#[derive(Clone)]
pub struct ScannerResources {
    pub proxy_pool: ProxyPool,
    pub result_handler: ResultHandler,
}

#[derive(Clone)]
pub struct ResultHandler {
    db: Database,
}

impl ResultHandler {
    pub async fn save<T: Serialize>(&self, key: &str, ip_addr: &str, proxy: &str, result: T) {
        self.try_save(key, ip_addr, proxy, result).await.log_error_consume("result-saving");
    }
    async fn try_save<T: Serialize>(&self, key: &str, ip_addr: &str, proxy: &str, result: T) -> Result<(), SimpleError> {
        let collection = match &GLOBAL_CONFIG.scanner.save {
            ResultSavingOption::SingleCollection(collection) => self.db.collection(&collection),
            _ => panic!("Not implement"),
        };
        let key = format!("scan.{}", key);

        let doc = bson::doc! {
            "addr": ip_addr,
            "proxy": proxy,
            "time": bson::to_bson(&bson::DateTime::from(Utc::now()))?,
            key: bson::to_bson(&result)?,
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