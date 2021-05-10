use std::{sync::Arc, time::Duration};
use tokio::{sync::Mutex, task, time::sleep};
use redis::AsyncCommands;
use crate::error::SimpleError;

use super::{SharedSchedulerInternalStats, SharedSchedulerStats};

#[derive(Clone)]
pub struct MasterScheduler {
    key_taskqueue: String,
    key_running_tasks: String,
    redis: Arc<Mutex<redis::aio::Connection>>,
    redis_client: redis::Client,
    internal_stats: SharedSchedulerInternalStats,
    stats: SharedSchedulerStats,
}

impl MasterScheduler {
    pub async fn start(key: &str, redis_url: &str) -> Result<Self, SimpleError> {
        let redis = redis::Client::open(redis_url)?;
        let redis_conn = redis.get_async_connection().await?;

        let scheduler = Self {
            redis: Arc::new(Mutex::new(redis_conn)),
            key_taskqueue: format!("{}_taskqueue", key),
            key_running_tasks: format!("{}_running_tasks", key),
            redis_client: redis::Client::open(redis_url)?,
            internal_stats: SharedSchedulerInternalStats::new(),
            stats: SharedSchedulerStats::new(),
        };
        task::spawn(scheduler.clone().stats_mornitor(10.0));
        Ok(scheduler)
    }
    pub async fn fetch_tasks(&self, count: usize) -> Result<Vec<String>, SimpleError> {
        let mut redis = self.redis.lock().await;
        let mut tasks = Vec::<String>::with_capacity(count);
        let first_task: String = redis.brpoplpush(&self.key_taskqueue, &self.key_running_tasks, 0).await?;
        tasks.push(first_task);
        for _ in 1..count {
            let other_task: Option<String> = redis.rpoplpush(&self.key_taskqueue, &self.key_running_tasks).await?;
            match other_task {
                Some(task) => tasks.push(task),
                _ => break,
            }
        }

        Ok(tasks)
    }

    pub async fn completed_tasks(&self, tasks: Vec<String>) -> Result<(), SimpleError> {
        let mut redis = self.redis_client.get_async_connection().await?;
        self.internal_stats.dispatch_tasks(1).await;
        for task in &tasks {
            redis.lrem(&self.key_running_tasks, 1, task).await?;
        }
        self.internal_stats.remove_pending_tasks(tasks.len()).await;
        Ok(())
    }

    pub fn dispathcer(&self) -> TaskDispatcher {
        TaskDispatcher {
            key_taskqueue: self.key_taskqueue.clone(),
            key_running: self.key_running_tasks.clone(),
            redis_client: self.redis_client.clone(),
            stats: self.internal_stats.clone(),
        }
    }

    async fn stats_mornitor(self, update_interval: f64) {
        loop {
            sleep(Duration::from_secs_f64(update_interval)).await;
            
            let stats = self.internal_stats.reset_stats().await;
            self.stats.update(&stats, update_interval).await;
        }
    }
}

#[derive(Clone)]
pub struct TaskDispatcher {
    key_taskqueue: String,
    key_running: String,
    redis_client: redis::Client,
    stats: SharedSchedulerInternalStats,
}

impl TaskDispatcher {
    pub async fn enqueue_tasks(&self, tasks: Vec<String>) -> Result<(), SimpleError> {
        let mut redis = self.redis().await?;
        let count = tasks.len();
        if tasks.len() > 0 {
            redis.lpush(&self.key_taskqueue, tasks).await?;
        }

        self.stats.add_pending_tasks(count).await;
        Ok(())
    }

    pub async fn recover_tasks(&self) -> Result<(), SimpleError> {
        let mut redis = self.redis().await?;
        loop {
            let result: Option<String> = redis.rpoplpush(&self.key_running, &self.key_taskqueue).await?;
            if let None = result {
                return Ok(())
            }
        }
    }

    pub async fn enqueue_task(&self, task: &str) -> Result<(), SimpleError> {
        self.redis().await?.lpush(&self.key_taskqueue, task).await?;

        self.stats.add_pending_tasks(1).await;
        Ok(())
    }

    pub async fn get_pending_tasks(&self, skip: isize, count: isize) -> Result<Vec<String>, SimpleError> {
        let result:Vec<String> = self.redis().await?
            .lrange(&self.key_taskqueue, -skip - count, -skip - 1).await?;
        Ok(result)
    }

    pub async fn count_tasks(&self) -> Result<usize, SimpleError> {
        let count: usize = self.redis().await?.llen(&self.key_taskqueue).await?;
        
        self.stats.update_pending_tasks(count).await;
        Ok(count)
    }

    pub async fn clear_tasks(&self) -> Result<usize, SimpleError> {
        let count = self.count_tasks().await?;
        self.redis().await?.del(&self.key_taskqueue).await?;

        self.stats.update_pending_tasks(0).await;
        Ok(count)
    }

    pub async fn remove_task(&self, task: &str) -> Result<usize, SimpleError> {
        let count: usize = self.redis().await?.lrem(&self.key_taskqueue, 0, task).await?;

        self.stats.remove_pending_tasks(count).await;
        Ok(count)
    }
    
    async fn redis(&self) -> Result<redis::aio::Connection, SimpleError> {
        Ok(self.redis_client.get_async_connection().await?)
    }
}
