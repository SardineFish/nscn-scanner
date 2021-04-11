use std::collections::HashMap;

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
    pub analyser: ServiceAnalyserOptions,
    pub test: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
pub struct ProxyPoolConfig {
    pub update_http_proxy: bool,
    pub fetch_addr: String,
    pub update_interval: u64,
    pub http_validate: Vec<ProxyVerify>,
    pub https_validate: String,
    pub socks5: Socks5ProxyOptions,
}

#[derive(Deserialize)]
pub struct Socks5ProxyOptions {
    pub enabled: bool,
    pub fetch: String,
    pub pool_size: usize,
    pub validate: String,
}

#[derive(Deserialize)]
pub struct SchedulerOptions {
    pub enabled: bool,
    pub max_tasks: usize,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum ResultSavingOption {
    SingleCollection(String),
    Independent{http: String, https: String, tcp: String, },
}

#[derive(Deserialize)]
pub struct ScannerConfig {
    pub http: UniversalScannerOption,
    pub https: UniversalScannerOption,
    pub ssh: UniversalScannerOption,
    pub ftp: UniversalScannerOption,
    pub tcp: TCPScannerOptions,
    pub task: TaskOptions,
    pub scheduler: SchedulerOptions,
    pub save: ResultSavingOption,
}

#[derive(Deserialize)]
pub struct TCPScannerOptions {
    pub enabled: bool,
    pub ports: HashMap<u16, Vec<String>>,
}

#[derive(Deserialize)]
pub struct UniversalScannerOption {
    pub enabled: bool,
    pub use_proxy: bool,
    pub socks5: Option<bool>,
    pub timeout: u64,
}
#[derive(Deserialize)]
pub struct TaskOptions {
    pub fetch: bool,
    pub clear_old_tasks: bool,
    pub addr_src: Vec<String>,
    pub proxy: Option<String>,
}

#[derive(Deserialize)]
pub struct ServiceAnalyserOptions {
    pub rules: ServiceAnalyserRules,
    pub scheduler: SchedulerOptions,
    pub save: String,
}

#[derive(Deserialize)]
pub struct ServiceAnalyserRules {
    pub wappanalyser: String,
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