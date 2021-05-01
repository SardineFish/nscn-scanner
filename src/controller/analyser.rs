use actix_web::{post, web::{Data, ServiceConfig, scope}};
use nscn::ScannerService;
use serde::{Serialize};
use crate::{misc::responder::{ApiResult, Response}, model::Model};

#[derive(Serialize)]
struct ScheduleResult {
    tasks: usize,
}

#[post("/all")]
async fn analyse_all(service: Data<ScannerService>, model: Data<Model>) -> ApiResult<ScheduleResult> {
    let docs = model.get_scaned_addr(0..u32::MAX, 0, 0, true).await?;
    let mut tasks = 0;
    for doc in docs {
        service.analyser().enqueue_task_addr(&doc.addr).await?;
        tasks += 1;
    }
    Ok(Response(ScheduleResult {
        tasks,
    }))
}

pub fn config(cfg: &mut ServiceConfig) {
    cfg.service(scope("/analyser")
        .service(analyse_all)
    );
}