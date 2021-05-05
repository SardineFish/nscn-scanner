use std::{collections::HashMap, fmt::{self, Display, Formatter}};

use clap::{Clap, AppSettings};
use lazy_static::lazy_static;
use serde::{Deserialize};
use crate::error::*;



#[derive(Deserialize)]
pub struct Config {
    pub mongodb: String,
    pub redis: String,
    pub listen: String,
    pub role: NodeRole,
    pub workers: Option<Vec<String>>,
    pub init: Option<bool>,
    pub proxy_pool: ProxyPoolConfig,
    pub scanner: ScannerConfig,
    pub analyser: ServiceAnalyserOptions,
    pub stats: StatsConfig,
    pub test: Option<HashMap<String, String>>,
}

#[derive(Deserialize, Clap, Debug, PartialEq)]
pub enum NodeRole {
    Master,
    Worker,
    Standalone,
}

impl Display for NodeRole {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            NodeRole::Master => write!(f, "Master"),
            NodeRole::Standalone => write!(f, "Standalone"),
            NodeRole::Worker => write!(f, "Worker"),
        }
    }
}

#[derive(Deserialize)]
pub struct StatsConfig {
    pub net_interface: Option<String>,
    pub sys_update_interval: u64, //ms
    pub scheduler_update_interval: u64, // ms
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
    pub validate: Option<String>,
}

#[derive(Deserialize)]
pub struct WorkerSchedulerOptions {
    pub enabled: bool,
    pub max_tasks: usize,
    pub fetch_count: usize,
    pub fetch_threshold: usize,
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
    pub scheduler: WorkerSchedulerOptions,
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
    pub analyse_on_scan: bool,
    pub rules: ServiceAnalyserRules,
    pub scheduler: WorkerSchedulerOptions,
    pub save: String,
    pub vuln_search: VulnerabilitiesSearchConfig,
}

#[derive(Deserialize)]
pub struct ServiceAnalyserRules {
    pub wappanalyser: String,
    pub ftp: String,
    pub ssh: String,
}

#[derive(Deserialize)]
pub struct VulnerabilitiesSearchConfig {
    pub exploitdb: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum ProxyVerify {
    Plain(String),
    Echo{base: String, pattern: String},
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, SimpleError> {
        let data = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data)?)
    }
    pub fn init() -> Self {
        let opts = CliOptions::parse();
        let mut config = Self::from_file(&opts.config).unwrap();
        config.role = opts.role.unwrap_or(config.role);
        if let Some(listen) = opts.listen {
            config.listen = listen;
        }
        
        if opts.workers.len() > 0 {
            config.workers = Some(opts.workers);
        }
        if opts.init {
            config.init = Some(true);
        }
        // let mut env: HashMap<String, String> = env::vars().collect();
        // if let Some(workers) = env.remove("NSCN_WORKERS") {
        //     config.workers = Some(serde_json::from_str::<Vec<String>>(&workers).unwrap());

        // }
        // config.role = match env.get("NSCN_ROLE").map(|s|s.as_str()) {
        //     Some("Master") => NodeRole::Master,
        //     Some("Standalone") => NodeRole::Standalone,
        //     Some("Worker") => NodeRole::Worker,
        //     _ => config.role,
        // };
        // config.listen = env.remove("NSCN_LISTEN").unwrap_or(config.listen);

        config
    }
}

#[derive(Clap)]
#[clap(version = "0.1.0", author = "SardineFish")]
#[clap(setting = AppSettings::ColoredHelp)]
struct CliOptions {
    #[clap(short, long, default_value="config.json")]
    config: String,

    #[clap(long, env="NSCN_LISTEN")]
    listen: Option<String>,

    #[clap(long, arg_enum, env="NSCN_ROLE")]
    role: Option<NodeRole>,

    #[clap(long)]
    init: bool,

    #[clap()]
    workers: Vec<String>,
}

lazy_static!{
    pub static ref GLOBAL_CONFIG: Config = {
        Config::init()
    };
}