use std::{time::Duration};

use tokio::{time::sleep};
use rand::Rng;

use crate::error::{LogError, SimpleError};



pub struct LocalScheduler {
    master_addr: String,
    pending_tasks: Vec<String>,
    rng: rand::rngs::SmallRng,
    remote_fetch_count: usize,
    remote_fetch_threshold: usize,
    client: reqwest::Client,
}

impl LocalScheduler {
    pub async fn fetch_task(&mut self) -> String {
        if self.pending_tasks.len() < self.remote_fetch_threshold {
            self.fetch_remote_tasks().await;
        }

        let idx = self.rng.gen_range(0..self.pending_tasks.len());
        self.pending_tasks.swap_remove(idx)
    }

    pub async fn complete_task(&self, task: String) {
        self.client.post(format!("http://{}/api/scheduler/complete", self.master_addr))
            .json(&vec![task])
            .send()
            .await
            .log_error_consume("task-complete");
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

        self.pending_tasks.extend(tasks_list.into_iter());
    }

    async fn try_fetch_remote_tasks(&self) -> Result<Vec<String>, SimpleError> {
        let tasks = self.client.post(format!("http://{}/api/scheduler/fetch", self.master_addr))
            .send()
            .await?
            .json::<Vec<String>>()
            .await?;
        Ok(tasks)
    }
}