
use serde::{Serialize};

use crate::{net_scanner::scheduler::{ScannerResources, TaskPool}};
use crate::config::GLOBAL_CONFIG;
use super::super::result_handler::ScanTaskInfo;

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

#[derive(Serialize)]
pub struct TCPScanResult {
    ftp: Option<ScanTaskInfo<FTPScanResult>>,
    ssh: Option<ScanTaskInfo<SSHScannResult>>,
}