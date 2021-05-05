use actix_web::{get, web::{Data, ServiceConfig, scope}};
use serde::{Serialize};
use nscn::{WorkerService, SchedulerStatsReport, SystemStats, SchedulerStats};

use crate::misc::responder::{ApiResult, Response};

#[derive(Serialize)]
struct AllSchedulerStats {
    scanner: SchedulerStatsReport,
    analyser: SchedulerStats,
}

#[get("/system")]
async fn get_sys_stats(service: Data<WorkerService>) -> ApiResult<SystemStats>
{
    let stats = service.sys_stats().await;
    Ok(Response(stats))
}

#[get("/scheduler")]
async fn get_scheduler_stats(service: Data<WorkerService>) -> ApiResult<AllSchedulerStats> {
    let stats = AllSchedulerStats {
        scanner: service.scheduler_stats().await,
        analyser: service.analyser().stats().await,
    };

    Ok(Response(stats))
}

pub fn config(cfg: &mut ServiceConfig){
    cfg.service(scope("/stats")
        .service(get_sys_stats)
        .service(get_scheduler_stats)
    );
}