use std::{collections::HashMap, net::Ipv4Addr, str::FromStr};

use actix_web::{get, delete, http::StatusCode, post, web::{Data, Json, Path, Query, ServiceConfig, scope}};
use nscn::{ MasterService, WorkerService, error::SimpleError, parse_ipv4_cidr};
use serde::{Deserialize, Serialize};

use crate::{error::{ApiError}, misc::responder::{ApiResult, Response}, model::{Model, ScanAnalyseResult, ScanResultBreif, ScanStats}};

#[derive(Serialize)]
struct HTTPResponseData {
    status: i32,
    heder: HashMap<String, String>,
}

#[derive(Deserialize)]
pub struct QueryParameters {
    pub skip: usize,
    pub count: usize,
    pub online_only: Option<i32>,
}

#[derive(Deserialize)]
struct ScanningRequest {
    fetch_urls: Option<Vec<String>>,
    addr_ranges: Option<Vec<String>>,
}

#[derive(Serialize)]
struct ScanningRequestResult {
    tasks: usize,
}

#[derive(Serialize)]
struct TaskRemoveResult {
    removed_tasks: usize,
}

#[get("/stats")]
async fn get_stats(service: Data<WorkerService>, model: Data<Model>) -> ApiResult<ScanStats> {
    let mut stats = model.get_stats().await?;
    stats.scan_per_seconds = service.scanner().stats().await.tasks_per_second;

    Ok(Response(stats))
}

#[get("/{addr}")]
async fn get_by_ip(addr_str: Path<String>, model: Data<Model>) -> ApiResult<Vec<ScanAnalyseResult>> {
    let addr = parse_ip(&addr_str).map_err(|_|ApiError(StatusCode::BAD_REQUEST, "Invalid address format".to_owned()))?;
    let result = model.get_details_by_ip(addr).await?;

    Ok(Response(vec![result.into()]))
}

#[get("/{addr}/{cidr}")]
async fn get_range_by_cidr(path: Path<(String, String)>, query: Query<QueryParameters>, model: Data<Model>) -> ApiResult<Vec<ScanResultBreif>> {
    let (addr_str, cidr) = path.into_inner();
    let range = parse_ipv4_cidr(&format!("{}/{}", addr_str, cidr))
        .map_err(|_|ApiError(StatusCode::BAD_REQUEST, "Invalid CIDR notation format".to_owned()))?;

    let online_only = match query.online_only {
        Some(x) if x > 0 => true,
        _ => false,
    };
    
    let result = model.get_by_ip_range(range, query.skip, query.count, online_only).await?;

    Ok(Response(result))
}

#[post("/{addr}")]
async fn request_scan(addr_str: Path<String>, service: Data<MasterService>) -> ApiResult<ScanningRequestResult> {
    service.scanner().enqueue_addr_list(vec![format!("{}/32", addr_str)]).await?;

    Ok(Response(ScanningRequestResult {
        tasks: 1
    }))
}

#[post("/{addr}/{cidr}")]
async fn request_scan_range(path: Path<(String, String)>, service: Data<MasterService>) -> ApiResult<ScanningRequestResult> {
    let (addr_str, cidr) = path.into_inner();
    let range = parse_ipv4_cidr(&format!("{}/{}", addr_str, cidr))
        .map_err(|_|ApiError(StatusCode::BAD_REQUEST, "Invalid CIDR notation format".to_owned()))?;
    service.scanner().enqueue_addr_list(vec![format!("{}/{}", addr_str, cidr)]).await?;

    Ok(Response(ScanningRequestResult {
        tasks: range.len()
    }))
}

#[post("/list")]
async fn request_scan_by_list(request: Json<ScanningRequest>, service: Data<MasterService>) -> ApiResult<ScanningRequestResult> {
    let mut tasks = 0;
    if let Some(url_list) = &request.fetch_urls {
        for url in url_list {
            let task_list = service.fetch_address_list(url.as_str()).await
                .map_err(|err|ApiError(StatusCode::BAD_REQUEST, format!("Faild to fetch address list from '{}': {}", url, err.msg)))?;

            tasks += service.scanner().enqueue_addr_list(task_list).await?;
        }
    }
    if let Some(list) = request.into_inner().addr_ranges {
        tasks += service.scanner().enqueue_addr_list(list).await?;
    }

    Ok(Response(ScanningRequestResult {
        tasks,
    }))
}

#[get("/task")]
async fn request_pending_tasks(query: Query<QueryParameters>, service: Data<MasterService>) -> ApiResult<Vec<String>> {
    let tasks = service.scanner().scheduler().dispathcer().get_pending_tasks(query.skip as isize, query.count as isize).await?;

    Ok(Response(tasks))
}

#[delete("/task/{ip}")]
async fn remove_pending_task_ip(ip: Path<String>, service: Data<MasterService>) -> ApiResult<TaskRemoveResult> {
    let count = service.scanner().remove_tasks(vec![format!("{}/32", ip)]).await?;

    Ok(Response(TaskRemoveResult {
        removed_tasks: count
    }))
}

#[delete("/task/{ip}/{cidr}")]
async fn remove_pending_task(path: Path<(String, String)>, service: Data<MasterService>) -> ApiResult<TaskRemoveResult> {
    let (ip, cidr) = path.into_inner();
    let addr = format!("{}/{}", ip, cidr);
    let count = service.scanner().remove_tasks(vec![addr]).await?;

    Ok(Response(TaskRemoveResult{
        removed_tasks: count,
    }))
}

#[delete("/task/all")]
async fn clear_pending_tasks(service: Data<MasterService>) -> ApiResult<TaskRemoveResult> {
    let count = service.scanner().clear_tasks().await?;

    Ok(Response(TaskRemoveResult{
        removed_tasks: count
    }))
}

fn parse_ip(addr: &str) -> Result<u32, SimpleError> {
    let ip: u32 = Ipv4Addr::from_str(addr)?.into();
    Ok(ip)
}

pub fn config(cfg: &mut ServiceConfig) {
    cfg.service(
        scope("/scan")
            .service(request_pending_tasks)
            .service(get_stats)
            .service(get_by_ip)
            .service(get_range_by_cidr)
            .service(clear_pending_tasks)
            .service(remove_pending_task)
            .service(remove_pending_task_ip)
            .service(request_scan_by_list)
            .service(request_scan)
            .service(request_scan_range)
    );
}
