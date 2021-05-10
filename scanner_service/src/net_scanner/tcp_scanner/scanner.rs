
use serde::{Serialize, Deserialize};

use crate::{net_scanner::{result_handler::NetScanResultSet, scheduler::{ScannerResources}}};
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
                match scanner.as_str() {
                    "ftp" if GLOBAL_CONFIG.scanner.ftp.enabled => {
                        let task = FTPScanTask {
                            host: addr.to_owned(),
                            port: *port,
                        };
                        task_pool.spawn("ftp-scan", FTPScanTask::start, task).await;
                    },
                    "ssh" if GLOBAL_CONFIG.scanner.ssh.enabled => {
                        let task = SSHScanTask {
                            host: addr.to_owned(),
                            port: *port,
                        };
                        task_pool.spawn("ssh", SSHScanTask::start, task).await;
                    },
                    _ => (),
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TCPScanResult {
    pub ftp: Option<NetScanResultSet<FTPScanResult>>,
    pub ssh: Option<NetScanResultSet<SSHScannResult>>,
}