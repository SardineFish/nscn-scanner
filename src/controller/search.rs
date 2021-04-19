use actix_web::{get, web::{Data, Path, Query, ServiceConfig, scope}};
use serde::{Serialize};

use crate::{misc::responder::ApiResult, model::{Model, ScanAnalyseResult}};
use crate::misc::responder::Response;

use super::scan::{QueryParameters, get_opened_ports};

#[derive(Serialize)]
struct ScanResultBreif {
    addr: String,
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
            services,
            vulnerabilities: vulns
        }
    }
}

#[get("/all")]
async fn get_all_available(query: Query<QueryParameters>, model: Data<Model>) -> ApiResult<Vec<ScanResultBreif>> {
    let results = model.get_all_available(query.skip, query.count).await?;

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

pub fn config(cfg: &mut ServiceConfig) {
    cfg.service(
        scope("/search")
            .service(get_all_available)
            .service(search_by_service)
            .service(search_by_service_version)
    );
}