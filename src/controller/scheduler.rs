use serde::{Serialize, Deserialize};
use actix_web::{get, post, web::{Data, Json, Path, Query, ServiceConfig, scope}};
use nscn::{GLOBAL_CONFIG, MasterService, ScannerConfig, ServiceAnalyserOptions, UniversalScannerOption, WorkerSchedulerOptions, WorkerService, error::{LogError, SimpleError}};

use crate::{error::ServiceError, misc::responder::{ApiResult, Response}};

#[derive(Debug, Deserialize)]
struct FecthCount {
    count: usize,
}

#[derive(Deserialize, Serialize)]
struct WorkerSetupConfig {
    #[serde(default = "String::default")]
    master_addr: String,
    #[serde(default = "default_scanner_config")]
    scanner: WorkerScannerConfig,
    #[serde(default = "default_analyser_config")]
    analyser: WorkerAnalyserConfig,
}

fn default_scanner_config() -> WorkerScannerConfig {
    WorkerScannerConfig::from(GLOBAL_CONFIG.scanner.clone())
}

fn default_analyser_config() -> WorkerAnalyserConfig {
    WorkerAnalyserConfig::from(GLOBAL_CONFIG.analyser.clone())
}

#[derive(Deserialize, Serialize)]
struct WorkerScannerConfig {
    http: UniversalScannerOption,
    https: UniversalScannerOption,
    ssh: UniversalScannerOption,
    ftp: UniversalScannerOption,
    scheduler: WorkerSchedulerOptions,
}

impl From<ScannerConfig> for WorkerScannerConfig {
    fn from(config: ScannerConfig) -> Self {
        Self {
            ftp: config.ftp,
            http: config.http,
            https: config.https,
            scheduler: config.scheduler,
            ssh: config.ssh,
        }
    }
}

#[derive(Deserialize, Serialize)]
struct WorkerAnalyserConfig {
    scheduler: WorkerSchedulerOptions,
}

impl From<ServiceAnalyserOptions> for WorkerAnalyserConfig {
    fn from(config: ServiceAnalyserOptions) -> Self {
        Self {
            scheduler: config.scheduler,
        }
    }
}

#[post("{task_key}/fetch")]
async fn fetch_tasks(path: Path<String>, query: Query<FecthCount>, service: Data<MasterService>) -> ApiResult<Vec<String>> {
    // log::info!("Fetch {}", path.as_str());
    let task = match path.as_str() {
        "scanner" => {
            service.scanner().scheduler().fetch_tasks(query.count).await?
        },
        "analyser" => {
            service.analyser().fetch_tasks(query.count).await?
        },
        _ => {
            Err(ServiceError::DataNotFound)?
        }
    };

    Ok(Response(task))
}

#[post("{task_key}/complete")]
async fn complete_task(path: Path<String>, data: Json<Vec<String>>, service: Data<MasterService>) -> ApiResult<()> {
    match path.as_str() {
        "scanner" => {
            service.scanner().complete_addr_list(data.into_inner()).await?;
        },
        "analyser" => {
            service.analyser().completed_tasks(data.into_inner()).await?;
        },
        _ => {
            Err(ServiceError::DataNotFound)?
        }
    };
    
    Ok(Response(()))
}

#[post("/setup")]
async fn register_master(data: Json<WorkerSetupConfig>, service: Data<WorkerService>) -> ApiResult<()> {
    let config = data.into_inner();
    log::info!("Received connection from master {}", config.master_addr);
    let mut scanner_config = service.config().scanner.clone();
    let mut analyser_config = service.config().analyser.clone();
    scanner_config.http = config.scanner.http;
    scanner_config.https = config.scanner.https;
    scanner_config.ftp = config.scanner.ftp;
    scanner_config.ssh = config.scanner.ssh;
    scanner_config.scheduler = config.scanner.scheduler;
    analyser_config.scheduler = config.analyser.scheduler;
    service.start(config.master_addr, scanner_config, analyser_config).await?;
    log::info!("Worker started.");

    Ok(Response(()))
}

#[post("/worker")]
async fn register_worker(data: Json<String>, service: Data<MasterService>) -> ApiResult<()> {
    service.add_worker(data.0).await?;
    Ok(Response(()))
}

#[post("/{worker_addr}/setup")]
async fn setup_specific_worker(data: Json<WorkerSetupConfig>, path: Path<String>, service: Data<MasterService>) -> ApiResult<()> {
    let mut config = data.into_inner();
    config.master_addr = GLOBAL_CONFIG.listen.clone();
    service.http_client().post(format!("http://{}/api/scheduler/setup", path))
        .json(&config)
        .send()
        .await
        .log_error_consume("setup-specific-worker");

    Ok(Response(()))
}

#[get("/workers")]
async fn get_workers(service: Data<MasterService>) -> ApiResult<Vec<String>> {
    Ok(Response(service.workers().await))
}

#[get("/status")]
async fn get_worker_status(service: Data<WorkerService>) -> ApiResult<Option<WorkerSetupConfig>> {
    let config = service.current_state().await
        .map(|state| WorkerSetupConfig {
            master_addr: state.master_addr,
            analyser: state.analyser_config.into(),
            scanner: state.scanner_config.into()
        });
    Ok(Response(config))
}

#[get("/{worker_addr}/status")]
async fn get_specific_worker_status(path: Path<String>, service: Data<MasterService>) -> ApiResult<Option<WorkerSetupConfig>> {
    let response = service.http_client().get(format!("http://{}/api/scheduler/status", path))
        .send()
        .await
        .map_err(SimpleError::from)?;
    let config = response.json::<Option<WorkerSetupConfig>>()
        .await
        .map_err(SimpleError::from)?;
    Ok(Response(config))
}

pub fn config(cfg: &mut ServiceConfig) {
    cfg.service(scope("/scheduler")
        .service(fetch_tasks)
        .service(complete_task)
        .service(register_master)
        .service(setup_specific_worker)
        .service(register_worker)
        .service(get_workers)
        .service(get_worker_status)
        .service(get_specific_worker_status)
    );
}