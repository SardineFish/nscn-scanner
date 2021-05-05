use actix_web::{post, web::{Data, ServiceConfig, scope}};
use nscn::{MasterService};
use serde::{Serialize};
use crate::{misc::responder::{ApiResult, Response}, model::Model};

#[derive(Serialize)]
struct ScheduleResult {
    tasks: usize,
}

#[post("/all")]
async fn analyse_all(service: Data<MasterService>, model: Data<Model>) -> ApiResult<ScheduleResult> {
    let docs = model.get_scaned_addr(0..u32::MAX, 0, 0, true).await?;
    let tasks = docs.len();
    let addrs: Vec<String> = docs.into_iter()
        .map(|doc|doc.addr)
        .collect();
    service.analyser().dispathcer().enqueue_tasks(addrs).await?;
    Ok(Response(ScheduleResult {
        tasks,
    }))
}

pub fn config(cfg: &mut ServiceConfig) {
    cfg.service(scope("/analyse")
        .service(analyse_all)
    );
}