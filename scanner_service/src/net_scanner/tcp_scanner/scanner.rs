
use serde::{Serialize, Deserialize};

use crate::{net_scanner::{scheduler::{ScannerResources}}};

use super::{ftp::{FTPScanResult}, ssh::{SSHScannResult}};

pub struct TCPScanTask {
    pub addr: String,
    pub resources: ScannerResources,
}

impl TCPScanTask {
}

// #[derive(Serialize, Deserialize, Debug)]
// pub struct TCPScanResult {
//     pub ftp: Option<NetScanResultSet<FTPScanResult>>,
//     pub ssh: Option<NetScanResultSet<SSHScannResult>>,
// }