use lazy_static::lazy_static;
use serde::{Deserialize};
use tokio::fs::read_to_string;
use crate::error::*;

#[derive(Deserialize)]
pub struct Config {
    pub proxy_pool: String,
    pub proxy_pool_retry: u64,
    pub proxy_pool_verify: Vec<ProxyVerify>,
    pub proxy_pool_verify_https: String,
    pub mongodb: String,
    pub redis: String,
    pub addr_src: Vec<String>,
    pub proxy: Option<String>,
    pub max_tasks: usize,
    pub request_timeout: u64,
    pub dispatch_task: bool,
    pub reset_task_queue: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum ProxyVerify {
    Plain(String),
    Echo{base: String, pattern: String},
}

impl Config {
    pub async fn from_file(path: &str) -> Result<Self, SimpleError> {
        let data = read_to_string(path).await?;
        Ok(serde_json::from_str(&data)?)
    }
}

lazy_static!{
    pub static ref GLOBAL_CONFIG: Config = {
        let data = std::fs::read_to_string("config.json").unwrap();
        let config: Config = serde_json::from_str(&data).unwrap();
        config
    };
}