use std::{collections::HashMap, net::Ipv4Addr, str::FromStr};

use actix_web::{Responder, dev::Handler, get, http::StatusCode, post, web::{Data, Path, Query, ServiceConfig, scope}};
use mongodb::Database;
use nscn::{error::SimpleError, parse_ipv4_cidr};
use serde::{Deserialize, Serialize};

use crate::{error::{ApiError, ServiceError}, misc::responder::{ApiResult, Response}, model::{Model, ScanAnalyseResult}};

#[derive(Serialize)]
struct ScanResult {
    addr: String,
    services: HashMap<String, ServiceResult>,
}
#[derive(Serialize)]
struct ServiceResult {
    name: String,
    version: String,
    vulnerabilities: Vec<ServiceVulnerability>,
}

#[derive(Serialize)]
struct ServiceVulnerability {
    id: String,
    title: String,
    url: String,
}

#[derive(Deserialize)]
struct QueryParameters {
    skip: usize,
    count: usize,
}

impl From<ScanAnalyseResult> for ScanResult {
    fn from(result: ScanAnalyseResult) -> Self {
    }
}

#[get("/{addr}")]
async fn get_by_ip(addr_str: Path<String>, service:Data<Database>, model: Data<Model>) -> ApiResult<Vec<ScanResult>> {
    let addr = parse_ip(&addr_str).map_err(|_|ApiError(StatusCode::BAD_REQUEST, "Invalid address format".to_owned()))?;
    let result = model.get_by_ip(addr).await?;

    Ok(Response(vec![result.into()]))
}

#[get("/{addr}/{cidr}")]
async fn get_range_by_cidr(path: Path<(String, String)>, query: Query<QueryParameters>, service:Data<Database>, model: Data<Model>) -> ApiResult<Vec<ScanResult>> {
    let (addr_str, cidr) = path.into_inner();
    let range = parse_ipv4_cidr(&format!("{}/{}", addr_str, cidr))
        .map_err(|_|ApiError(StatusCode::BAD_REQUEST, "Invalid CIDR notation format".to_owned()))?;
    
    let result = model.get_by_ip_range(range, query.skip, query.count).await?;

    Ok(Response(result.into_iter().map(ScanResult::from).collect()))
}

#[post("/{addr}")]
async fn request_scan() -> ApiResult<()> {
    Ok(Response(()))
}

#[post("/{addr}/{cidr}")]
async fn request_scan_range() -> ApiResult<()> {
    Ok(Response(()))
}

fn parse_ip(addr: &str) -> Result<u32, SimpleError> {
    let ip: u32 = Ipv4Addr::from_str(addr)?.into();
    Ok(ip)
}

pub fn config(cfg: &mut ServiceConfig) {
    cfg.service(
        scope("/scan")
            .service(get_by_ip)
            .service(get_range_by_cidr)
            .service(request_scan)
            .service(request_scan_range),
    );
}
