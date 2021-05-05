use serde::{Serialize, Deserialize};
use actix_web::{get, post, web::{Data, Json, Path, Query, ServiceConfig, scope}};
use nscn::{MasterService, WorkerService};

use crate::{error::ServiceError, misc::responder::{ApiResult, Response}};

#[derive(Debug, Deserialize)]
struct FecthCount {
    count: usize,
}

#[post("{task_key}/fetch")]
async fn fetch_tasks(path: Path<String>, query: Query<FecthCount>, service: Data<MasterService>) -> ApiResult<Vec<String>> {
    log::info!("Fetch {}", path.as_str());
    let task = match path.as_str() {
        "scanner" => {
            service.scanner().fetch_tasks(query.count).await?
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
            service.scanner().completed_tasks(data.into_inner()).await?
        },
        "analyser" => {
            service.analyser().completed_tasks(data.into_inner()).await?
        },
        _ => {
            Err(ServiceError::DataNotFound)?
        }
    };
    
    Ok(Response(()))
}

#[post("/master")]
async fn register_master(data: Json<String>, service: Data<WorkerService>) -> ApiResult<()> {
    log::info!("Received connection from master {}", data);
    service.start(data.into_inner())?;
    log::info!("Worker started.");

    Ok(Response(()))
}

pub fn config(cfg: &mut ServiceConfig) {
    cfg.service(scope("/scheduler")
        .service(fetch_tasks)
        .service(complete_task)
        .service(register_master)
    );
}