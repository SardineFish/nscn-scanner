
use serde::{Serialize, Deserialize};

use crate::{net_scanner::{result_handler::NetScanResultSet, scanner::{TcpScanTask}, scheduler::{ScannerResources}}};
use crate::config::GLOBAL_CONFIG;

use super::{ftp::{FTPScanResult, FTPScanTask}, ssh::{SSHScanTask, SSHScannResult}};

pub struct TCPScanTask {
    pub addr: String,
    pub resources: ScannerResources,
}

impl TCPScanTask {
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TCPScanResult {
    pub ftp: Option<NetScanResultSet<FTPScanResult>>,
    pub ssh: Option<NetScanResultSet<SSHScannResult>>,
}