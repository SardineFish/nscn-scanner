use actix_web::{get, web::{Data, ServiceConfig, scope}};
use nscn::{ScannerService, SchedulerStatsReport, SystemStats};

use crate::misc::responder::{ApiResult, Response};

#[get("/system")]
async fn get_sys_stats(service: Data<ScannerService>) -> ApiResult<SystemStats>
{
    let stats = service.sys_stats().await;
    Ok(Response(stats))
}

#[get("/scheduler")]
async fn get_scheduler_stats(service: Data<ScannerService>) -> ApiResult<SchedulerStatsReport> {
    let stats = service.scheduler_stats().await;

    Ok(Response(stats))
}

pub fn config(cfg: &mut ServiceConfig){
    cfg.service(scope("/stats")
        .service(get_sys_stats)
        .service(get_scheduler_stats)
    );
}