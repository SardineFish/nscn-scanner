use actix_web::{get, http::StatusCode, web::{Data, Path, Query, ServiceConfig, scope}};
use serde::{Serialize};

use crate::{error::ApiError, misc::responder::ApiResult, model::{AnalyseGeometryStats, Model, ScanAnalyseResult}, parse_ipv4_cidr};
use crate::misc::responder::Response;

use super::scan::{QueryParameters, get_opened_ports};

#[derive(Serialize)]
pub struct ScanResultBreif {
    addr: String,
    last_update: i64,
    opened_ports: Vec<i16>,
    services: Vec<String>,
    vulnerabilities: usize,
}

impl From<ScanAnalyseResult> for ScanResultBreif {
    fn from(result: ScanAnalyseResult) -> Self {
        let ports = get_opened_ports(&result);
        let mut services = Vec::new();
        let mut vulns = 0;
        if let Some(analyse_result) = result.analyse {
            if let Some(web) = analyse_result.web {
                vulns += web.iter().map(|(_, service)| service.vulns.len()).sum::<usize>();
                services.extend(web.into_iter().map(|(name, service)| format!("{} {}", name, service.version)));
            }
            if let Some(ftp) = analyse_result.ftp {
                vulns += ftp.iter().map(|(_, service)| service.vulns.len()).sum::<usize>();
                services.extend(ftp.into_iter().map(|(name, service)| format!("{} {}", name, service.version)));
            }
            if let Some(ssh) = &analyse_result.ssh {
                vulns += ssh.iter().map(|(_, service)| service.vulns.len()).sum::<usize>();
                services.extend(ssh.into_iter().map(|(name, service)| format!("{} {}", name, service.version)));
            }
        }

        Self {
            addr: result.scan.addr,
            opened_ports: ports,
            last_update: result.scan.last_update.timestamp_millis(),
            services,
            vulnerabilities: vulns
        }
    }
}

#[get("/all")]
async fn get_all_available(query: Query<QueryParameters>, model: Data<Model>) -> ApiResult<Vec<ScanResultBreif>> {
    let results = model.get_by_ip_range(0..u32::max_value(),query.skip, query.count, true).await?;

    Ok(Response(results.into_iter().map(ScanResultBreif::from).collect()))
}

#[get("/service/{service_name}")]
async fn search_by_service(service_name: Path<String>, query: Query<QueryParameters>, model: Data<Model>) -> ApiResult<Vec<ScanResultBreif>> {
    let results = model.get_by_service_name(&service_name, query.skip, query.count).await?;
    
    Ok(Response(results.into_iter().map(ScanResultBreif::from).collect()))
}

#[get("/service/{service_name}/{version}")]
async fn search_by_service_version(path: Path<(String, String)>, query: Query<QueryParameters>, model: Data<Model>) -> ApiResult<Vec<ScanResultBreif>> {
    let (service_name, version) = path.into_inner();
    let results = model.get_by_service_version(&service_name, &version, query.skip, query.count).await?;

    Ok(Response(results.into_iter().map(ScanResultBreif::from).collect()))
}

#[get("/port/{port}")]
async fn search_by_port(path: Path<u16>, query: Query<QueryParameters>, model: Data<Model>) -> ApiResult<Vec<ScanResultBreif>> {
    let results = match path.into_inner() {
        80 => model.get_by_scanner("http", query.skip, query.count).await?,
        443 => model.get_by_scanner("https", query.skip, query.count).await?,
        21 => model.get_by_scanner("tcp.21.ftp", query.skip, query.count).await?,
        22 => model.get_by_scanner("tcp.22.ssh", query.skip, query.count).await?,
        port => Err(ApiError(StatusCode::BAD_REQUEST, format!("Invalid port '{}'", port)))?,
    };
    Ok(Response(results.into_iter().map(ScanResultBreif::from).collect()))
}

#[get("/geo_stats/all")]
async fn geo_stats_all(model: Data<Model>) -> ApiResult<Vec<AnalyseGeometryStats>> {
    let results = model.geo_stats_by_ip_range(0..u32::max_value()).await?;
    Ok(Response(results))
}
#[get("/geo_stats/{ip}/{cidr}")]
async fn geo_stats_by_ip_range(path: Path<(String, String)>, model: Data<Model>) -> ApiResult<Vec<AnalyseGeometryStats>> {
    let (addr_str, cidr) = path.into_inner();
    let range = parse_ipv4_cidr(&format!("{}/{}", addr_str, cidr))
        .map_err(|_|ApiError(StatusCode::BAD_REQUEST, "Invalid CIDR notation format".to_owned()))?;
    let results = model.geo_stats_by_ip_range(range).await?;
    Ok(Response(results))
}
#[get("/geo_stats/service/{service_name}")]
async fn geo_stats_by_service_name(service_name: Path<String>, model: Data<Model>) -> ApiResult<Vec<AnalyseGeometryStats>> {
    let results = model.geo_stats_by_service_name(&service_name).await?;
    Ok(Response(results))
}
#[get("/geo_stats/service/{service_name}/{version}")]
async fn geo_stats_by_service_version(path: Path<(String, String)>, model: Data<Model>) -> ApiResult<Vec<AnalyseGeometryStats>> {
    let (service_name, version) = path.into_inner();
    let results = model.geo_stats_by_service_version(&service_name, &version).await?;
    Ok(Response(results))
}
#[get("/geo_stats/port/{port}")]
async fn geo_stats_by_port(path: Path<u16>, model: Data<Model>) -> ApiResult<Vec<AnalyseGeometryStats>> {
    let results = match path.into_inner() {
        80 => model.geo_stats_by_scanner("http").await?,
        443 => model.geo_stats_by_scanner("https").await?,
        21 => model.geo_stats_by_scanner("tcp.21.ftp").await?,
        22 => model.geo_stats_by_scanner("tcp.22.ssh").await?,
        port => Err(ApiError(StatusCode::BAD_REQUEST, format!("Invalid port '{}'", port)))?,
    };
    Ok(Response(results))
}

pub fn config(cfg: &mut ServiceConfig) {
    cfg.service(
        scope("/search")
            .service(get_all_available)
            .service(search_by_service)
            .service(search_by_service_version)
            .service(search_by_port)
            .service(geo_stats_all)
            .service(geo_stats_by_service_name)
            .service(geo_stats_by_service_version)
            .service(geo_stats_by_port)
            .service(geo_stats_by_ip_range)
    );
}