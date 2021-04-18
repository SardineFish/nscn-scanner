use actix_web::{get, web::{ServiceConfig, scope}};
use serde::{Serialize};

use crate::misc::responder::ApiResult;
use crate::misc::responder::Response;

#[derive(Serialize)]
struct ScanResultPreview {
    addr: String,
    opened_ports: Vec<i16>,
    services: Vec<String>,
    vulnerabilities: i32,
}

#[get("/all")]
async fn get_all_available() -> ApiResult<Vec<ScanResultPreview>> {

    Ok(Response(()))
}

#[get("/service/{service_name}")]
async fn search_by_service() -> ApiResult<Vec<ScanResultPreview>> {
    Ok(Response(()))
}

#[get("/service/{service_name}/{version}")]
async fn search_by_service_version() -> ApiResult<Vec<ScanResultPreview>> {
    Ok(Response(()))
}

pub fn config(cfg: &mut ServiceConfig) {
    cfg.service(
        scope("/search")
            .service(get_all_available)
            .service(search_by_service)
            .service(search_by_service_version)
    );
}