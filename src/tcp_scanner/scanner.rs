use tokio::{sync::mpsc::Sender};
use tokio::io::{AsyncRead, AsyncWrite};
use serde::{Serialize};

use crate::scanner::{DispatchScanTask, ScanResult, ScannerResources, Scheduler, TaskPool};
use crate::config::GLOBAL_CONFIG;

use super::{ftp::{FTPScanResult, FTPScanTask}, ssh::{SSHScanTask, SSHScannResult}};

pub struct TCPScanTask {
    pub addr: String,
    pub resources: ScannerResources,
}

impl TCPScanTask {
    pub async fn dispatch(addr: &str, resources: &ScannerResources, task_pool: &mut TaskPool) {
        for port in &GLOBAL_CONFIG.scanner.tcp.ports {
            if GLOBAL_CONFIG.scanner.ftp.enabled {
                let task = FTPScanTask {
                    host: addr.to_owned(),
                    port: *port,
                    resources: resources.clone()
                };
                task_pool.spawn(task.start()).await;
            }
            if GLOBAL_CONFIG.scanner.ssh.enabled {
                let task = SSHScanTask {
                    host: addr.to_owned(),
                    port: *port,
                    resources: resources.clone()
                };
                task_pool.spawn(task.start()).await;
            }
        }
    }
}

#[derive(Serialize)]
pub struct TCPScanResult {
    ftp: Option<ScanResult<FTPScanResult>>,
    ssh: Option<ScanResult<SSHScannResult>>,
}