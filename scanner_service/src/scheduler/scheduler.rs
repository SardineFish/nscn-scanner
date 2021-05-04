use std::{mem, sync::{Arc, atomic::AtomicPtr}, time::Duration};

use futures::Future;
use serde::{Serialize};
use redis::AsyncCommands;
use tokio::{sync::{Mutex, mpsc::{Receiver, Sender, channel}}, task, time::sleep};

use crate::{error::*};

#[derive(Clone, Debug, Default)]
pub struct SchedulerInternalStats {
    pub completed_tasks: usize,
    pub dispatched_jobs: usize,
    pub pending_tasks: usize,
}

#[derive(Clone)]
pub struct SharedSchedulerInternalStats(Arc<Mutex<SchedulerInternalStats>>);

impl SharedSchedulerInternalStats {
    pub fn new()->Self {
        Self(Arc::new(Mutex::new(SchedulerInternalStats::default())))
    }
    pub(super) async fn reset_stats(&self) -> SchedulerInternalStats {
        let mut stats = SchedulerInternalStats::default();
        let mut guard = self.0.lock().await;
        mem::swap(&mut stats, &mut guard);
        guard.pending_tasks = stats.pending_tasks;
        stats
    }
    pub async fn dispatch_job(&self, count: usize) {
        let mut guard = self.0.lock().await;
        guard.dispatched_jobs +=count;
    }
    pub async fn dispatch_tasks(&self, count: usize) {
        let mut guard = self.0.lock().await;
        if guard.pending_tasks < count {
            guard.pending_tasks = 0;
        } else {
            guard.pending_tasks -= count;
        }
        guard.completed_tasks += count;
    }
    pub async fn update_pending_tasks(&self, count: usize) {
        let mut guard = self.0.lock().await;
        guard.pending_tasks = count;
    }
    pub async fn add_pending_tasks(&self, count: usize) {
        let mut guard = self.0.lock().await;
        guard.pending_tasks += count;
    }
    pub async fn remove_pending_tasks(&self, count: usize) {
        let mut guard = self.0.lock().await;
        if guard.pending_tasks < count {
            guard.pending_tasks = 0;
        } else {
            guard.pending_tasks -= count;
        }
    }
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct SchedulerStats {
    pub tasks_per_second: f64,
    pub jobs_per_second: f64,
    pub pending_tasks: usize,
}

#[derive(Clone)]
pub struct SharedSchedulerStats(Arc<Mutex<SchedulerStats>>);

impl SharedSchedulerStats {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(SchedulerStats::default())))
    }
    pub(super) async fn update(&mut self, stats: &SchedulerInternalStats, duration_seconds: f64) {
        let mut guard = self.0.lock().await;
        guard.tasks_per_second = stats.completed_tasks as f64 / duration_seconds;
        guard.jobs_per_second = stats.dispatched_jobs as f64 / duration_seconds;
        guard.pending_tasks = stats.pending_tasks;
    }
    pub async fn clone_inner(&self) -> SchedulerStats {
        let guard = self.0.lock().await;
        guard.clone()
    }
}

pub struct Scheduler {
    redis_key: String,
    redis: redis::Client,
    redis_connection: Option<redis::aio::Connection>,
    internal_stats: SharedSchedulerInternalStats,
    stats: SharedSchedulerStats,
}

macro_rules! get_redis {
    ($self_mut: expr, $redis: ident) => {
        if let None = $self_mut.redis_connection {
            $self_mut.redis_connection = Some($self_mut.redis.get_async_connection().await?);
        }
        let $redis = $self_mut.redis_connection.as_mut().ok_or("Failed to get redis connection")?;
    };
    ($self_mut: expr) => {
        if let None = $self_mut.redis_connection {
            $self_mut.redis_connection = Some($self_mut.redis.get_async_connection().await?);
            $self_mut.redis_connection.as_mut().ok_or("Failed to get redis connection")?
        } else {
            $self_mut.redis_connection.as_mut().ok_or("Failed to get redis connection")?
        }
    }
}

macro_rules! key_taskqueue {
    ($self_ref: expr) => {
        format!("{}_taskqueue", $self_ref.redis_key).as_str()
    };
}

impl Scheduler {
    pub async fn new(redis_key: &str, redis_url: &str) -> Result<Self, SimpleError> {
        let client = redis::Client::open(redis_url)?;
        let scheduler = Self {
            redis_key: redis_key.to_owned(),
            redis_connection: None, 
            redis: client,
            stats: SharedSchedulerStats::new(),
            internal_stats: SharedSchedulerInternalStats::new(),
        };
        task::spawn(scheduler.clone().stats_mornitor(10.0));
        Ok(scheduler)
    }
    pub async fn fetch_task(&mut self) -> Result<String, SimpleError> {
        get_redis!(self, redis);
        
        Ok(redis.brpoplpush(
            format!("{}_taskqueue", self.redis_key), 
            format!("{}_running", self.redis_key),
            0
        ).await?)
    }
    pub async fn recover_tasks(&mut self) -> Result<(), SimpleError> {
        get_redis!(self, redis);

        loop {
            let result: Result<Option<String>, redis::RedisError> = redis.rpoplpush(
                format!("{}_running", self.redis_key), 
                format!("{}_taskqueue", self.redis_key)
            ).await;
            match result {
                Err(err) => Err(err)?,
                Ok(None) => break,
                _ => (),
            }
        }

        let count = self.count_tasks().await?;
        self.internal_stats.update_pending_tasks(count).await;

        Ok(())
    }
    pub async fn complete_task(&mut self, task: &str) -> Result<(), SimpleError> {
        get_redis!(self, redis);
        self.internal_stats.dispatch_tasks(1).await;
        redis.lrem(format!("{}_running", self.redis_key), 1, task).await?;
        Ok(())
    }
    pub async fn enqueue_task(&mut self, task: &str) -> Result<(), SimpleError> {
        get_redis!(self, redis);

        redis.lpush(format!("{}_taskqueue", self.redis_key), task).await?;
        self.internal_stats.add_pending_tasks(1).await;
        Ok(())
    }
    pub async fn enqueue_task_list(&mut self, list: Vec<String>) -> Result<(), SimpleError> {
        let redis = get_redis!(self);
        let count = list.len();

        redis.lpush(key_taskqueue!(self), list).await?;
        self.internal_stats.add_pending_tasks(count).await;
        Ok(())
    }
    pub async fn count_tasks(&mut self) -> Result<usize, SimpleError> {
        let redis = get_redis!(self);

        let len: usize = redis.llen(key_taskqueue!(self)).await?;
        Ok(len)
    }
    pub async fn clear_tasks(&mut self) ->Result<usize, SimpleError> {
        let count = self.count_tasks().await?;
        let redis = get_redis!(self);
        redis.del(key_taskqueue!(self)).await?;
        self.internal_stats.update_pending_tasks(0).await;
        Ok(count)
    }
    pub async fn remove_task(&mut self, task: &str) -> Result<usize, SimpleError> {
        let redis = get_redis!(self);
        let count: usize = redis.lrem(key_taskqueue!(self), -1, task).await?;
        self.internal_stats.remove_pending_tasks(count).await;
        Ok(count)
    }
    pub async fn pending_tasks(&mut self) -> Result<Vec<String>, SimpleError> {
        let redis = get_redis!(self);
        let tasks: Vec<String> = redis.lrange(key_taskqueue!(self), 0, -1).await?;
        Ok(tasks)
    }
    pub async fn stats(&self) -> SchedulerStats {
        self.stats.clone_inner().await
    }
    pub fn new_task_pool<T: Send + 'static>(&self, max_tasks: usize, resource_pool: Vec<T>) -> TaskPool<T> {
        TaskPool::new(max_tasks, self.internal_stats.clone(), resource_pool)
    }
    async fn stats_mornitor(mut self, update_interval: f64) {
        loop {
            sleep(Duration::from_secs_f64(update_interval)).await;
            
            let stats = self.internal_stats.reset_stats().await;
            self.stats.update(&stats, update_interval).await;
        }
    }
}

impl Clone for Scheduler {
    fn clone(&self) -> Self {
        Self {
            redis: self.redis.clone(),
            redis_key: self.redis_key.clone(),
            redis_connection: None, 
            stats: self.stats.clone(), 
            internal_stats: self.internal_stats.clone(),
        }
    }
}

pub struct TaskPool<T> {
    interval_jitter: bool,
    max_tasks: usize,
    running_tasks: usize,
    complete_sender: Sender<T>,
    complete_receiver: Receiver<T>,
    stats: SharedSchedulerInternalStats,
    resource_pool: Vec<T>,
}

impl<Resource> TaskPool<Resource> where Resource: Send + 'static {
    pub fn new(max_tasks: usize, stats: SharedSchedulerInternalStats, resource_pool: Vec<Resource>) -> Self {
        let (sender, receiver) = channel(max_tasks * 2);
        Self {
            max_tasks,
            interval_jitter: true,
            running_tasks: 0,
            complete_sender: sender,
            complete_receiver: receiver,
            stats: stats,
            resource_pool,
        }
    }
    pub async fn spawn<T, Task>(&mut self, _name: &'static str, func: fn(Task, &'static mut Resource) -> T, task: Task)
    where T : Future + Send + 'static, 
        T::Output: Send + 'static,
        Task: Send + 'static,
        // F: FnOnce(Task, &mut Resource) -> T + Send + 'static
    {
        let complete_sender = self.complete_sender.clone();
        let future = self.wait_resource();
        let mut resource = future.await;
        task::spawn(async move {
            // future.await;
            let mut ptr: AtomicPtr<Resource> = AtomicPtr::new(&mut resource);
            let mut_ref = unsafe{ ptr.get_mut().as_mut().unwrap()};
            func(task, mut_ref).await;
            // if let Err(_) = timeout(Duration::from_secs(300), future).await {
            //     log::error!("Task {} suspedned over 300s", name);
            // }
            // sleep(Duration::from_secs(5)).await;
            complete_sender.send(resource).await.log_error_consume("scan-scheduler");
        });
    }
    async fn wait_resource(&mut self) -> Resource {
        if self.running_tasks >= self.max_tasks || self.resource_pool.len() <= 0 {
            if self.interval_jitter {
                self.interval_jitter = false;
            }

            match self.complete_receiver.recv().await {
                Some(resource) => {
                    self.running_tasks -= 1;
                    self.resource_pool.push(resource);
                },
                None => panic!("Scheduler channel closed."),
            }
        }
        if self.interval_jitter {
            let interval = 5.0 / (self.max_tasks as f64);
            sleep(Duration::from_secs_f64(interval)).await;
        }
        
        self.running_tasks += 1;
        let resource = self.resource_pool.pop().unwrap();
        self.stats.dispatch_job(1).await;
        resource
    }
    // pub async fn spawn<T>(&mut self, _name: &'static str, future: T) where T : Future + Send + 'static, T::Output: Send + 'static {
    //     if self.running_tasks >= self.max_tasks {
    //         if self.interval_jitter {
    //             self.interval_jitter = false;
    //         }

    //         match self.complete_receiver.recv().await {
    //             Some(_) => {
    //                 self.running_tasks -= 1
    //             },
    //             None => panic!("Scheduler channel closed."),
    //         }
    //     }
    //     if self.interval_jitter {
    //         let interval = 5.0 / (self.max_tasks as f64);
    //         sleep(Duration::from_secs_f64(interval)).await;
    //     }
        
    //     self.running_tasks += 1;
    //     let complete_sender = self.complete_sender.clone();
    //     task::spawn(async move {
    //         future.await;
    //         // if let Err(_) = timeout(Duration::from_secs(300), future).await {
    //         //     log::error!("Task {} suspedned over 300s", name);
    //         // }
    //         // sleep(Duration::from_secs(5)).await;
    //         complete_sender.send(()).await.log_error_consume("scan-scheduler");
    //     });
    //     self.stats.dispatch_job(1).await;
    // }
}