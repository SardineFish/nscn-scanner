use actix_web::{get, web::{Data, Path, ServiceConfig, scope}};
use nscn::{MasterService, WorkerService, WorkerStats};

use crate::{error::ServiceError, misc::responder::{ApiResult, Response}};

#[get("/all")]
async fn get_stats(service: Data<WorkerService>) -> ApiResult<WorkerStats> {
    Ok(Response(WorkerStats {
        system: service.sys_stats().await,
        analyser: service.analyser().stats().await,
        scanner: service.scanner().stats().await,
    }))
}

#[get("/{worker}/all")]
async fn get_worker_sys_stats(worker_addr: Path<String>, service: Data<MasterService>) -> ApiResult<WorkerStats> {
    let workers = service.workers().await;
    if workers.contains(&worker_addr) {
        Ok(Response(service.get_worker_stats(&worker_addr).await?))
    } else {
        Err(ServiceError::DataNotFound)?
    }
}

pub fn config(cfg: &mut ServiceConfig){
    cfg.service(scope("/stats")
        .service(get_stats)
        .service(get_worker_sys_stats)
    );
}