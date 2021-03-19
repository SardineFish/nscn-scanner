use lazy_static::lazy_static;
use serde::{Deserialize};
use tokio::fs::read_to_string;
use crate::error::*;



#[derive(Deserialize)]
pub struct Config {
    pub mongodb: String,
    pub redis: String,
    pub proxy_pool: ProxyPoolConfig,
    pub scanner: ScannerConfig,
}

#[derive(Deserialize)]
pub struct ProxyPoolConfig {
    pub fetch_addr: String,
    pub update_interval: u64,
    pub http_validate: Vec<ProxyVerify>,
    pub https_validate: String,
}

#[derive(Deserialize)]
pub struct ScannerConfig {
    pub http: HttpScannerOptions,
    pub https: HttpsScannerOptions,
    pub task: TaskOptions,
}

#[derive(Deserialize)]
pub struct HttpScannerOptions {
    pub timeout: u64,
    pub max_tasks: usize,
}

#[derive(Deserialize)]
pub struct HttpsScannerOptions {
    pub timeout: u64,
    pub max_tasks: usize,
}
#[derive(Deserialize)]
pub struct TaskOptions {
    pub dispatch: bool,
    pub clear_old_tasks: bool,
    pub addr_src: Vec<String>,
    pub proxy: Option<String>,
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