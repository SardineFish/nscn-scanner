use std::{sync::Arc, time::Duration};

use futures::Future;
use tokio::{sync::{Mutex, watch}, time::sleep};
use rand::{Rng, SeedableRng, prelude::SmallRng};

use crate::{config::WorkerSchedulerOptions, error::{LogError, SimpleError}};

struct WorkerTaskFetcher {
    master_addr: String,
    task_key: String,
    pending_tasks: Arc<Mutex<Vec<String>>>,
    remote_fetch_count: usize,
    remote_fetch_threshold: usize,
    fetch_request: watch::Receiver<()>,
    tasks_updated: watch::Sender<()>,
    client: reqwest::Client,
}

impl WorkerTaskFetcher {
    pub async fn start(self) {
        self.fetch_tasks().await;
    }

    async fn fetch_tasks(mut self) {
        loop {
            self.fetch_remote_tasks().await;
            self.tasks_updated.send(()).log_error_consume("task-updated");
            self.fetch_request.changed().await.log_error_consume("wait-fetch");
            log::info!("Recv fetch request");
        }
    }

    async fn fetch_remote_tasks(&mut self) {
        let tasks_list = loop {
            match self.try_fetch_remote_tasks().await {
                Ok(tasks) if tasks.len() > 0 => break tasks,
                Ok(_) => log::error!("Fetched empty tasks from remote master."),
                Err(err) => log::error!("Failed to fetch remote task: {}", err.msg),
            }
            sleep(Duration::from_secs(5)).await;
        };

        let mut pending_tasks = self.pending_tasks.lock().await;
        pending_tasks.extend(tasks_list.into_iter());
    }

    async fn try_fetch_remote_tasks(&self) -> Result<Vec<String>, SimpleError> {
        let tasks = self.client.post(format!("http://{}/api/scheduler/{}/fetch?count={}", self.master_addr, self.task_key, self.remote_fetch_count))
            .send()
            .await?
            .json::<Vec<String>>()
            .await?;
        Ok(tasks)
    }
}

pub struct LocalScheduler {
    enabled: bool,
    task_key: String,
    master_addr: String,
    request_fetch: watch::Sender<()>,
    tasks_updated: watch::Receiver<()>,
    pending_tasks: Arc<Mutex<Vec<String>>>,
    rng: rand::rngs::SmallRng,
    remote_fetch_count: usize,
    remote_fetch_threshold: usize,
    client: reqwest::Client,
}

impl LocalScheduler {
    pub fn start(task_key: String, master_addr: String, options: &WorkerSchedulerOptions) -> (Self, impl Future<Output=()> + Send + 'static) {
        let (fetch_sender, fetch_receiver) = watch::channel(());
        let (update_sender, update_receiver) = watch::channel(());

        let scheduler = Self {
            master_addr,
            task_key: task_key.to_owned(),
            enabled: options.enabled,
            rng: SmallRng::from_entropy(),
            client: reqwest::Client::new(),
            remote_fetch_count: options.fetch_count,
            remote_fetch_threshold: options.fetch_threshold,
            request_fetch: fetch_sender,
            pending_tasks: Arc::new(Mutex::new(Vec::with_capacity(options.fetch_count * 2))),
            tasks_updated: update_receiver,
        };

        let fetcher = WorkerTaskFetcher {
            client: scheduler.client.clone(),
            fetch_request: fetch_receiver,
            task_key,
            master_addr: scheduler.master_addr.clone(),
            pending_tasks: scheduler.pending_tasks.clone(),
            remote_fetch_count: options.fetch_count,
            remote_fetch_threshold: options.fetch_threshold,
            tasks_updated: update_sender,
        };

        (scheduler, fetcher.start())
    }

    pub async fn fetch_task(&mut self) -> String {
        log::info!("try fetch task");
        {
            let pending_tasks = self.pending_tasks.lock().await;
            if pending_tasks.len() < self.remote_fetch_threshold {
                log::info!("Request fetch");
                self.request_fetch.send(()).log_error_consume("request-fetch");
                if pending_tasks.len() <= 0 {
                    drop(pending_tasks);
                    log::info!("Wait fetch");
                    self.tasks_updated.changed().await.log_error_consume("wait-tasks-update");
                }
            }
        }

        log::info!("fetch task");
        let mut pending_tasks = self.pending_tasks.lock().await;

        let idx = self.rng.gen_range(0..pending_tasks.len());
        pending_tasks.swap_remove(idx)
    }

    pub async fn complete_task(&self, task: String) {
        self.client.post(format!("http://{}/api/scheduler/{}/complete", self.master_addr, self.task_key))
            .json(&vec![task])
            .send()
            .await
            .log_error_consume("task-complete");
    }
}