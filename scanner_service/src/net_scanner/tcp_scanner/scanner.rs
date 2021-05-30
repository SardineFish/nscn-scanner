
use serde::{Serialize, Deserialize};

use crate::{net_scanner::{result_handler::NetScanResultSet, scanner::{TcpScanTask}, scheduler::{ScannerResources}}};
use crate::config::GLOBAL_CONFIG;

use super::{ftp::{FTPScanResult, FTPScanTask}, ssh::{SSHScanTask, SSHScannResult}};

pub struct TCPScanTask {
    pub addr: String,
    pub resources: ScannerResources,
}

impl TCPScanTask {
    pub async fn dispatch(addr: String, task_pool: &mut crate::scheduler::TaskPool<ScannerResources>) {
        for (port, scanners) in &GLOBAL_CONFIG.scanner.tcp.ports {
            for scanner in scanners {
                if GLOBAL_CONFIG.scanner.config.contains_key(scanner) {
                    Self::dispatch_with_scanner(addr.clone(), *port, scanner, task_pool).await;
                }
            }
        }
    }

    async fn dispatch_with_scanner(addr: String, port: u16, scanner: &str, task_pool: &mut crate::scheduler::TaskPool<ScannerResources>) {
        match scanner {
            "ftp" => TcpScanTask::new(addr, port, FTPScanTask).schedule(task_pool).await,
            "ssh" => TcpScanTask::new(addr, port, SSHScanTask).schedule(task_pool).await,
            _ => (),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TCPScanResult {
    pub ftp: Option<NetScanResultSet<FTPScanResult>>,
    pub ssh: Option<NetScanResultSet<SSHScannResult>>,
}