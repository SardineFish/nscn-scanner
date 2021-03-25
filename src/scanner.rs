use std::collections::HashMap;

use mongodb::bson;
use serde::{Serialize};

use crate::{http_scanner::HttpResponseData, https_scanner::HttpsResponse, tcp_scanner::scanner::TCPScanResult};

#[derive(Serialize)]
pub struct NetScanRecord {
    pub addr: String,
    pub proxy: String,
    pub time: bson::DateTime,
    pub scan: NetScanResult,
}

#[derive(Serialize)]
#[serde(tag="result", content="data")]
pub enum ScanResult<T> {
    Ok(T),
    Err(String),
}

#[derive(Serialize)]
pub struct NetScanResult {
    pub http: Option<ScanResult<HttpResponseData>>,
    pub https: Option<ScanResult<HttpsResponse>>,
    pub tcp: Option<HashMap<u16, TCPScanResult>>,
}

pub trait DispatchScanTask {
    fn dispatch(self) -> usize;
}
