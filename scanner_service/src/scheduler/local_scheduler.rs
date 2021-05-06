use std::{time::Duration};

use futures::Future;
use tokio::{sync::{mpsc::{Receiver, Sender, channel}}, time::sleep};

use crate::{config::WorkerSchedulerOptions, error::{LogError, SimpleError}};

struct WorkerTaskFetcher {
    master_addr: String,
    task_key: String,
    remote_fetch_count: usize,
    remote_fetch_threshold: usize,
    task_sender: Sender<String>,
    client: reqwest::Client,
}

impl WorkerTaskFetcher {
    pub async fn start(self) {
        self.fetch_tasks().await;
    }

    async fn fetch_tasks(mut self) {
        loop {
            let task_list = self.fetch_remote_tasks().await;
            log::info!("fetched {} tasks", task_list.len());
            for task in task_list {
                match self.task_sender.send(task).await {
                    Ok(_) => (),
                    Err(err) => {
                        log::warn!("Failed to send task: {}", err);
                        return;
                    }
                }
                log::info!("enqueued 1 task1");
            }
        }
    }

    async fn fetch_remote_tasks(&mut self) -> Vec<String> {
        loop {
            match self.try_fetch_remote_tasks().await {
                Ok(tasks) if tasks.len() > 0 => return tasks,
                Ok(_) => log::error!("Fetched empty tasks from remote master."),
                Err(err) => log::error!("Failed to fetch remote task: {}", err.msg),
            }
            sleep(Duration::from_secs(5)).await;
        };
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
    task_receiver: Receiver<String>,
    remote_fetch_count: usize,
    remote_fetch_threshold: usize,
    client: reqwest::Client,
}

impl LocalScheduler {
    pub fn start(task_key: String, master_addr: String, options: &WorkerSchedulerOptions) -> (Self, impl Future<Output=()> + Send + 'static) {
        let (sender, receiver) = channel(options.fetch_threshold);

        let scheduler = Self {
            master_addr,
            task_key: task_key.to_owned(),
            enabled: options.enabled,
            client: reqwest::Client::new(),
            remote_fetch_count: options.fetch_count,
            remote_fetch_threshold: options.fetch_threshold,
            task_receiver: receiver,
        };

        let fetcher = WorkerTaskFetcher {
            client: scheduler.client.clone(),
            task_key,
            master_addr: scheduler.master_addr.clone(),
            remote_fetch_count: options.fetch_count,
            remote_fetch_threshold: options.fetch_threshold,
            task_sender: sender,
        };

        (scheduler, fetcher.start())
    }

    pub async fn fetch_task(&mut self) -> String {
        self.task_receiver.recv().await.unwrap()
    }

    pub async fn complete_task(&self, task: String) {
        self.client.post(format!("http://{}/api/scheduler/{}/complete", self.master_addr, self.task_key))
            .json(&vec![task])
            .send()
            .await
            .log_error_consume("task-complete");
    }
}