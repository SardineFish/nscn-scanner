use std::{collections::HashMap, fmt::{self, Display, Formatter}};

use clap::{Clap, AppSettings};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use crate::error::*;



#[derive(Deserialize, Clone)]
pub struct Config {
    pub mongodb: String,
    pub redis: String,
    pub listen: String,
    pub role: NodeRole,
    pub workers: Option<Vec<String>>,
    pub master: Option<String>,
    pub init: Option<bool>,
    pub proxy_pool: ProxyPoolConfig,
    pub scanner: ScannerConfig,
    pub analyser: ServiceAnalyserOptions,
    pub stats: StatsConfig,
    pub test: Option<HashMap<String, String>>,
}

#[derive(Deserialize, Clap, Debug, PartialEq, Clone)]
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

#[derive(Deserialize, Clone)]
pub struct StatsConfig {
    pub net_interface: Option<String>,
    pub sys_update_interval: u64, //ms
    pub scheduler_update_interval: u64, // ms
}

#[derive(Deserialize, Clone)]
pub struct ProxyPoolConfig {
    pub update_http_proxy: bool,
    pub fetch_addr: String,
    pub update_interval: u64,
    pub http_validate: Vec<ProxyVerify>,
    pub https_validate: String,
    pub socks5: Socks5ProxyOptions,
}

#[derive(Deserialize, Clone)]
pub struct Socks5ProxyOptions {
    pub enabled: bool,
    pub first_fetch: Option<String>,
    pub fetch: String,
    pub pool_size: usize,
    pub validate: Option<String>,
    pub servers: Option<Vec<String>>,
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct WorkerSchedulerOptions {
    pub enabled: bool,
    pub max_tasks: usize,
    pub fetch_count: usize,
    pub fetch_threshold: usize,
}

#[derive(Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum ResultSavingOption {
    SingleCollection(String),
    Independent{http: String, https: String, tcp: String, },
}

#[derive(Deserialize, Clone, PartialEq, Eq)]
pub struct ScannerConfig {
    #[serde(flatten)]
    pub config: HashMap<String, UniversalScannerOption>,
    pub http: UniversalScannerOption,
    pub https: UniversalScannerOption,
    pub ssh: UniversalScannerOption,
    pub ftp: UniversalScannerOption,
    pub tcp: TCPScannerOptions,
    pub task: TaskOptions,
    pub scheduler: WorkerSchedulerOptions,
    pub save: ResultSavingOption,
}

#[derive(Deserialize, Clone, PartialEq, Eq)]
pub struct TCPScannerOptions {
    pub enabled: bool,
    pub ports: HashMap<u16, Vec<String>>,
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct UniversalScannerOption {
    pub enabled: bool,
    pub use_proxy: bool,
    pub socks5: Option<bool>,
    pub timeout: u64,
}
#[derive(Deserialize, Clone, PartialEq, Eq)]
pub struct TaskOptions {
    pub fetch: bool,
    pub clear_old_tasks: bool,
    pub addr_src: Vec<String>,
    pub proxy: Option<String>,
}

#[derive(Deserialize, Clone, PartialEq, Eq)]
pub struct ServiceAnalyserOptions {
    pub analyse_on_scan: bool,
    pub externals: ServiceAnalyserRules,
    pub scheduler: WorkerSchedulerOptions,
    pub save: String,
    pub vuln_search: VulnerabilitiesSearchConfig,
}

#[derive(Deserialize, Clone, PartialEq, Eq)]
pub struct ServiceAnalyserRules {
    pub wappanalyser_rules: String,
    pub ftp_rules: String,
    pub ssh_rules: String,
    pub city_coords: String,
}

#[derive(Deserialize, Clone, PartialEq, Eq)]
pub struct VulnerabilitiesSearchConfig {
    pub exploitdb: String,
}

#[derive(Deserialize, Clone)]
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
        config.redis = opts.redis.unwrap_or(config.redis);
        config.mongodb = opts.db.unwrap_or(config.mongodb);
        if let Some(master_addr) = opts.master {
            config.master = Some(master_addr);
        }

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

    #[clap(long, env="NSCN_MASTER")]
    master: Option<String>,

    #[clap(long)]
    init: bool,

    #[clap()]
    workers: Vec<String>,

    #[clap(long, env="NSCN_DB")]
    db: Option<String>,

    #[clap(long, env="NSCN_REDIS")]
    redis: Option<String>,
}

lazy_static!{
    pub static ref GLOBAL_CONFIG: Config = {
        Config::init()
    };
}