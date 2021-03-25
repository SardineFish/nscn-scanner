use tokio::{sync::mpsc::Sender};
use tokio::io::{AsyncRead, AsyncWrite};
use serde::{Serialize};

use crate::scanner::{DispatchScanTask, ScanResult};

use super::{ftp::FTPScanResult, ssh::SSHScannResult};

pub struct TCPScanTask {
    addr: String,
    complete: Sender<bool>,
}

impl TCPScanTask {
    async fn scan<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
        
    }
}

impl DispatchScanTask for TCPScanTask {
    fn dispatch(self) -> usize {
        1
    }
}

#[derive(Serialize)]
pub struct TCPScanResult {
    ftp: Option<ScanResult<FTPScanResult>>,
    ssh: Option<ScanResult<SSHScannResult>>,
}