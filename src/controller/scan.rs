use std::{collections::HashMap, net::Ipv4Addr, str::FromStr};

use actix_web::{get, delete, http::StatusCode, post, web::{Data, Json, Path, Query, ServiceConfig, scope}};
use nscn::{FTPScanResult, HttpResponseData, HttpsResponse, SSHScannResult, ScanTaskInfo, ScannerService, ServiceAnalyseResult, VulnInfo, error::SimpleError, parse_ipv4_cidr};
use serde::{Deserialize, Serialize};

use crate::{error::{ApiError}, misc::responder::{ApiResult, Response}, model::{Model, ScanAnalyseResult, ScanStats}};

use super::search::ScanResultBreif;

#[derive(Serialize)]
struct ScanResult {
    addr: String,
    opened_ports: Vec<u16>,
    last_update: i64,
    services: HashMap<String, ServiceAnalyseResult>,
    http_results: Vec<ScanTaskInfo<HttpResponseData>>,
    https_results: Vec<ScanTaskInfo<HttpsResponse>>,
    ftp_results: Vec<ScanTaskInfo<FTPScanResult>>,
    ssh_results: Vec<ScanTaskInfo<SSHScannResult>>,
    vulns: HashMap<String, VulnInfo>,
}
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

pub fn get_opened_ports(result: &ScanAnalyseResult) -> Vec<i16> {
    let mut ports = Vec::new();
    match &result.scan.scan.http {
        Some(http) if http.success > 0 => {
            ports.push(80);
        },
        _ => ()
    }
    match &result.scan.scan.https {
        Some(https) if https.success > 0 => {
            ports.push(443);
        },
        _ => ()
    }
    if let Some(tcp) = &result.scan.scan.tcp {
        match tcp.get("21") {
            Some(tcp_result) => match &tcp_result.ftp {
                Some(ftp_result) if ftp_result.success > 0 => {
                    ports.push(21);
                },
                _ =>(),
            },
            _ => (),
        }
    }
    if let Some(tcp) = &result.scan.scan.tcp {
        match tcp.get("22") {
            Some(tcp_result) => match &tcp_result.ssh {
                Some(ssh_result) if ssh_result.success > 0 => {
                    ports.push(22);
                },
                _ =>(),
            },
            _ => (),
        }
    }
    ports
}

impl From<ScanAnalyseResult> for ScanResult {
    fn from(mut result: ScanAnalyseResult) -> Self {
        let mut ports: Vec<u16> = Vec::new();
        let mut ftp_results: Vec<ScanTaskInfo<FTPScanResult>> = Vec::new();
        let mut ssh_results: Vec<ScanTaskInfo<SSHScannResult>> = Vec::new();
        let mut services: HashMap<String, ServiceAnalyseResult> = HashMap::new();
        let mut http_response: Vec<ScanTaskInfo<HttpResponseData>> = Vec::new();
        let mut https_response: Vec<ScanTaskInfo<HttpsResponse>> = Vec::new();
        match result.scan.scan.http {
            Some(http) => {
                if http.success > 0 {
                    ports.push(80);
                }
                http_response.extend(http.results);
            },
            _ => ()
        }
        match result.scan.scan.https {
            Some(https) => {
                if https.success > 0 {
                    ports.push(443);
                }
                https_response.extend(https.results);
            },
            _ => ()
        }
        if let Some(tcp) = &mut result.scan.scan.tcp {
            match tcp.remove("21") {
                Some(tcp_result) => match tcp_result.ftp {
                    Some(ftp_result) => {
                        if ftp_result.success > 0 {
                            ports.push(21);
                        }
                        ftp_results.extend(ftp_result.results);
                    },
                    _ =>(),
                },
                _ => (),
            }
        }
        if let Some(tcp) = &mut result.scan.scan.tcp {
            match tcp.remove("22") {
                Some(tcp_result) => match tcp_result.ssh {
                    Some(ssh_result) => {
                        if ssh_result.success > 0 {
                            ports.push(22);
                        }
                        ssh_results.extend(ssh_result.results);
                    },
                    _ =>(),
                },
                _ => (),
            }
        }
        if let Some(service) = result.analyse {
            if let Some(ssh_service) = service.ssh {

                services.extend(ssh_service);
            }
            if let Some(web_service) = service.web {
                services.extend(web_service);
            }
            if let Some(ftp_service) = service.ftp {
                services.extend(ftp_service);
            }
        }

        Self {
            addr: result.scan.addr,
            opened_ports: ports,
            ftp_results,
            last_update: result.scan.last_update.timestamp_millis(),
            http_results: http_response,
            https_results: https_response,
            ssh_results,
            services,
            vulns: result.vulns.unwrap_or(HashMap::new()),
        }
    }
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
async fn get_stats(service: Data<ScannerService>, model: Data<Model>) -> ApiResult<ScanStats> {
    let mut stats = model.get_stats().await?;
    stats.scan_per_seconds = service.scheduler_stats().await.ip_per_second;

    Ok(Response(stats))
}

#[get("/{addr}")]
async fn get_by_ip(addr_str: Path<String>, model: Data<Model>) -> ApiResult<Vec<ScanResult>> {
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

    Ok(Response(result.into_iter().map(ScanResultBreif::from).collect()))
}

#[post("/{addr}")]
async fn request_scan(addr_str: Path<String>, service: Data<ScannerService>) -> ApiResult<ScanningRequestResult> {
    service.scheculer().enqueue_addr_range(&format!("{}/32", addr_str)).await?;

    Ok(Response(ScanningRequestResult {
        tasks: 1
    }))
}

#[post("/{addr}/{cidr}")]
async fn request_scan_range(path: Path<(String, String)>, service: Data<ScannerService>) -> ApiResult<ScanningRequestResult> {
    let (addr_str, cidr) = path.into_inner();
    let range = parse_ipv4_cidr(&format!("{}/{}", addr_str, cidr))
        .map_err(|_|ApiError(StatusCode::BAD_REQUEST, "Invalid CIDR notation format".to_owned()))?;
    service.scheculer().enqueue_addr_range(&format!("{}/{}", addr_str, cidr)).await?;

    Ok(Response(ScanningRequestResult {
        tasks: range.len()
    }))
}

#[post("/list")]
async fn request_scan_by_list(request: Json<ScanningRequest>, service: Data<ScannerService>) -> ApiResult<ScanningRequestResult> {
    let mut tasks = 0;
    let scheduler = service.scheculer();
    if let Some(lists) = &request.fetch_urls {
        for url in lists {
            let list = service.fetch_address_list(url.as_str()).await
                .map_err(|_|ApiError(StatusCode::BAD_REQUEST, format!("Faild to fetch address list from '{}'", url)))?;

            for addr in list {
                let range = parse_ipv4_cidr(&addr)
                    .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "Invalid address list format".to_owned()))?;
                scheduler.enqueue_addr_range(&addr).await?;
                tasks += range.len();
            }
        }
    }
    if let Some(list) = &request.addr_ranges {
        for addr_range in list {
            let range = parse_ipv4_cidr(&addr_range)?;
            scheduler.enqueue_addr_range(&addr_range).await?;
            tasks+=range.len();
        }
    }

    Ok(Response(ScanningRequestResult {
        tasks,
    }))
}

#[get("/task")]
async fn request_pending_tasks(query: Query<QueryParameters>, service: Data<ScannerService>) -> ApiResult<Vec<String>> {
    let tasks = service.scheculer().get_pending_tasks(query.skip as isize, query.count as isize).await?;

    Ok(Response(tasks))
}

#[delete("/task/{ip}")]
async fn remove_pending_task_ip(ip: Path<String>, service: Data<ScannerService>) -> ApiResult<TaskRemoveResult> {
    let count = service.scheculer().remove_task(&format!("{}/32", ip)).await?;

    Ok(Response(TaskRemoveResult {
        removed_tasks: count
    }))
}

#[delete("/task/{ip}/{cidr}")]
async fn remove_pending_task(path: Path<(String, String)>, service: Data<ScannerService>) -> ApiResult<TaskRemoveResult> {
    let (ip, cidr) = path.into_inner();
    let addr = format!("{}/{}", ip, cidr);
    let count = service.scheculer().remove_task(&addr).await?;

    Ok(Response(TaskRemoveResult{
        removed_tasks: count,
    }))
}

#[delete("/task/all")]
async fn clear_pending_tasks(service: Data<ScannerService>) -> ApiResult<TaskRemoveResult> {
    let count = service.scheculer().clear_tasks().await?;

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
