use std::{collections::HashMap, net::Ipv4Addr, str::FromStr};

use actix_web::{get, http::StatusCode, post, web::{Data, Path, Query, ServiceConfig, scope}};
use nscn::{FTPAccess, ScannerService, ServiceAnalyseResult, error::SimpleError, parse_ipv4_cidr};
use serde::{Deserialize, Serialize};

use crate::{error::{ApiError}, misc::responder::{ApiResult, Response}, model::{Model, ScanAnalyseResult}};

#[derive(Serialize)]
struct ScanResult {
    addr: String,
    opened_ports: Vec<u16>,
    services: HashMap<String, ServiceAnalyseResult>,
    http_response: Option<HTTPResponseData>,
    https_certificate: Option<String>,
    ftp_access: Option<FTPAccess>,
    ssh_server: Option<String>,
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
        let mut cert: Option<String> = None;
        let mut ftp_access: Option<FTPAccess> = None;
        let mut ssh_server: Option<String> = None;
        let mut services: HashMap<String, ServiceAnalyseResult> = HashMap::new();
        let mut http_response: Option<HTTPResponseData> = None;
        match result.scan.scan.http {
            Some(http) if http.success > 0 => {
                ports.push(80);
                if let Some(http) = http.results.into_iter().rev().find_map(|http|http.result.ok()) {
                    let mut response = HTTPResponseData {
                        heder: HashMap::new(),
                        status: http.status,
                    };
                    for (name, mut value) in http.headers {
                        if value.len() > 0 {
                            response.heder.insert(name, value.remove(0));
                        }
                    }
                    http_response = Some(response);
                }
            },
            _ => ()
        }
        match result.scan.scan.https {
            Some(https) if https.success > 0 => {
                ports.push(443);
                let https = https.results.into_iter().rev().find_map(|https|https.result.ok());
                cert = https.map(|https|https.cert);
            },
            _ => ()
        }
        if let Some(tcp) = &mut result.scan.scan.tcp {
            match tcp.remove("21") {
                Some(tcp_result) => match tcp_result.ftp {
                    Some(ftp_result) if ftp_result.success > 0 => {
                        ports.push(21);
                        let ftp = ftp_result.results.into_iter().rev().find_map(|ftp|ftp.result.ok());
                        ftp_access = ftp.map(|ftp|ftp.access);
                    },
                    _ =>(),
                },
                _ => (),
            }
        }
        if let Some(tcp) = &mut result.scan.scan.tcp {
            match tcp.remove("22") {
                Some(tcp_result) => match tcp_result.ssh {
                    Some(ssh_result) if ssh_result.success > 0 => {
                        ports.push(21);
                    },
                    _ =>(),
                },
                _ => (),
            }
        }
        if let Some(service) = result.analyse {
            if let Some(ssh_service) = service.ssh {
                if let Some((name, service_info)) = ssh_service.iter().next() {
                    ssh_server = Some(format!("{} {}", name, service_info.version));
                }

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
            ftp_access,
            http_response,
            https_certificate: cert,
            ssh_server,
            services,
        }
    }
}

#[get("/{addr}")]
async fn get_by_ip(addr_str: Path<String>, model: Data<Model>) -> ApiResult<Vec<ScanResult>> {
    let addr = parse_ip(&addr_str).map_err(|_|ApiError(StatusCode::BAD_REQUEST, "Invalid address format".to_owned()))?;
    let result = model.get_by_ip(addr).await?;

    Ok(Response(vec![result.into()]))
}

#[get("/{addr}/{cidr}")]
async fn get_range_by_cidr(path: Path<(String, String)>, query: Query<QueryParameters>, model: Data<Model>) -> ApiResult<Vec<ScanResult>> {
    let (addr_str, cidr) = path.into_inner();
    let range = parse_ipv4_cidr(&format!("{}/{}", addr_str, cidr))
        .map_err(|_|ApiError(StatusCode::BAD_REQUEST, "Invalid CIDR notation format".to_owned()))?;
    
    let result = model.get_by_ip_range(range, query.skip, query.count).await?;

    Ok(Response(result.into_iter().map(ScanResult::from).collect()))
}

#[post("/{addr}")]
async fn request_scan(addr_str: Path<String>, service: Data<ScannerService>) -> ApiResult<()> {
    service.scheculer().enqueue_addr_range(&format!("{}/32", addr_str)).await?;

    Ok(Response(()))
}

#[post("/{addr}/{cidr}")]
async fn request_scan_range(path: Path<(String, String)>, service: Data<ScannerService>) -> ApiResult<()> {
    let (addr_str, cidr) = path.into_inner();
    service.scheculer().enqueue_addr_range(&format!("{}/{}", addr_str, cidr)).await?;

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
