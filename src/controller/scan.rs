use std::collections::HashMap;

use actix_web::{
    get, post,
    web::{scope, ServiceConfig},
    Responder,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::ServiceError,
    misc::responder::{ApiResult, Response},
};

#[derive(Serialize)]
struct ScanRsult {
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

#[get("/{addr}")]
async fn get_by_ip() -> ApiResult<Vec<ScanRsult>> {
    Ok(Response(()))
}

#[get("/{addr}/{cidr}")]
async fn get_range_by_cidr() -> ApiResult<Vec<ScanRsult>> {
    Ok(Response(()))
}

#[post("/{addr}")]
async fn request_scan() -> ApiResult<()> {
    Ok(Response(()))
}

#[post("/{addr}/{cidr}")]
async fn request_scan_range() -> ApiResult<()> {
    Ok(Response(()))
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
