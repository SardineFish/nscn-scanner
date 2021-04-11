
use serde::{Serialize, Deserialize};

use crate::{net_scanner::{result_handler::NetScanResultSet, scheduler::{ScannerResources, TaskPool}}};
use crate::config::GLOBAL_CONFIG;

use super::{ftp::{FTPScanResult, FTPScanTask}, ssh::{SSHScanTask, SSHScannResult}};

pub struct TCPScanTask {
    pub addr: String,
    pub resources: ScannerResources,
}

impl TCPScanTask {
    pub async fn dispatch(addr: &str, resources: &ScannerResources, task_pool: &mut TaskPool) {
        for (port, scanners) in &GLOBAL_CONFIG.scanner.tcp.ports {
            for scanner in scanners {
                match scanner.as_str() {
                    "ftp" if GLOBAL_CONFIG.scanner.ftp.enabled => {
                        let task = FTPScanTask {
                            host: addr.to_owned(),
                            port: *port,
                            resources: resources.clone()
                        };
                        task_pool.spawn("ftp", task.start()).await;
                    },
                    "ssh" if GLOBAL_CONFIG.scanner.ssh.enabled => {
                        let task = SSHScanTask {
                            host: addr.to_owned(),
                            port: *port,
                            resources: resources.clone()
                        };
                        task_pool.spawn("ssh", task.start()).await;
                    },
                    _ => (),
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct TCPScanResult {
    pub ftp: Option<NetScanResultSet<FTPScanResult>>,
    pub ssh: Option<NetScanResultSet<SSHScannResult>>,
}