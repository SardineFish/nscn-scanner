use std::fmt;
use std::marker::PhantomData;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::UniversalScannerOption;
use crate::{ScanTaskInfo, error::SimpleError, scheduler::TaskPool};
use crate::config::GLOBAL_CONFIG;

use super::result_handler::SerializeScanResult;
use super::scheduler::ScannerResources;

#[async_trait]
pub trait Connector<S: AsyncRead + AsyncWrite + Sync + Send + 'static> {
    async fn connect(self, addr: &str, port: u16) -> Result<S, SimpleError>;
}

struct TcpConnector;
#[async_trait]
impl Connector<TcpStream> for TcpConnector {
    async fn connect(self, addr: &str, port: u16) -> Result<TcpStream, SimpleError> {
        Ok(TcpStream::connect((addr, port)).await?)
    }
}

pub struct TcpScanTask<T, R>
{
    addr: String,
    port: u16,
    config: UniversalScannerOption,
    task: T,
    _phantom: PhantomData<R>,
}

pub type TcpScanResult = Box<dyn SerializeScanResult + Send + Sync + 'static>;

impl<T, R> TcpScanTask<T, R> 
where 
    T: ScanTask<R> + Send + 'static, 
    R: Serialize + DeserializeOwned + Unpin + Send + Sync + fmt::Debug + 'static 
{
    pub fn new(addr: String, port: u16, task: T) -> Self {
        Self {
            addr,
            port,
            task,
            config: GLOBAL_CONFIG.scanner.config.get(T::scanner_name())
                .map(|cfg|cfg.clone())
                .unwrap_or(Default::default()),
            _phantom: PhantomData::default(),
        }
    }
    pub fn config(mut self, cfg: UniversalScannerOption) -> Self {
        self.config = cfg;
        self
    }
    pub async fn schedule(self, task_pool: &mut TaskPool<ScannerResources>) -> JoinHandle<TcpScanResult> {
        task_pool.spawn(T::scanner_name(), Self::start, self).await
    }

    async fn start(self, resources: &mut ScannerResources) -> TcpScanResult {
        let mut result = ScanTaskInfo::new(self.addr.clone(), self.port).scanner(T::scanner_name());

        let scan_result = match self.config.use_proxy {
            true => {
                let proxy = resources.proxy_pool.get_socks5_proxy().await;
                result = result.proxy(proxy.addr.clone());
                self.scan_with_connector(proxy).await
            },
            false => {
                self.scan_with_connector(TcpConnector).await
            },
        };
        let result = match scan_result {
            Ok(scan_result) => result.success(scan_result),
            Err(err) => result.err(err),
        };
        Box::new(result)
        // bson::to_bson(&result).ok()
        // resources.result_handler.save_scan_results(result).await;
    }

    async fn scan_with_connector<S: AsyncRead + AsyncWrite + Sync + Send + Unpin + 'static, C: Connector<S>>(self, connector: C) -> Result<R, SimpleError> {
        timeout(Duration::from_secs(self.config.timeout), async move {
            match connector.connect(&self.addr, self.port).await {
                Ok(mut stream) => self.task.scan(&mut stream).await,
                Err(err) => Err(err),
            }
        }).await?
    }
}

#[async_trait]
pub trait ScanTask<T> {
    async fn scan<S: Send + Sync + AsyncRead + AsyncWrite + Unpin + 'static>(self, stream: &mut S) -> Result<T, SimpleError>;
    fn scanner_name() -> &'static str;
}
