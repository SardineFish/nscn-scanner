pub mod web;
pub mod scheduler;
pub mod ftp;
pub mod ssh;
pub mod ip_geo;

use serde::{Deserialize, Serialize};

pub struct ServiceInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceAnalyseResult {
    pub name: String,
    pub version: String,
    pub vulns: Vec<String>,
}

impl ServiceAnalyseResult {
    pub fn new(name: String, version: String) -> Self {
        Self {
            name,
            version,
            vulns: Vec::new(),
        }
    }
}