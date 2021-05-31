use std::marker::PhantomData;
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::UniversalScannerOption;
use crate::{ScanTaskInfo, error::SimpleError, scheduler::TaskPool};
use crate::config::GLOBAL_CONFIG;

use super::scheduler::ScannerResources;

pub struct TcpScanTask<T, R>
{
    addr: String,
    port: u16,
    config: UniversalScannerOption,
    task: T,
    _phantom: PhantomData<R>,
}

impl<T, R> TcpScanTask<T, R> where T: ScanTask<R> + Send + 'static, R: Serialize + Send + 'static {
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
    pub async fn schedule(self, task_pool: &mut TaskPool<ScannerResources>) {
        task_pool.spawn(T::scanner_name(), Self::start, self).await
    }

    async fn start(self, resources: &mut ScannerResources) {
        let proxy = resources.proxy_pool.get_socks5_proxy().await;
        let proxy_addr = proxy.addr.clone();
        let target = format!("{}:{}", &self.addr, self.port);
        let task = self.task;
        let timeout = self.config.timeout;
        let result = tokio::time::timeout(Duration::from_secs(timeout), async move {
            match proxy.connect(&target, timeout).await {
                Ok(mut stream) => task.scan(&mut stream).await,
                Err(err) => Err(err),
            }
        }).await;
        let result = match result {
            Ok(Ok(result)) => ScanTaskInfo::with_proxy(proxy_addr, result),
            Ok(Err(err)) => ScanTaskInfo::err_with_proxy(proxy_addr, err),
            Err(err) => ScanTaskInfo::err_with_proxy(proxy_addr, "Timeout"),
        };
        resources.result_handler.save_scan_results(T::scanner_name(), &self.addr, result).await;
    }
}

#[async_trait]
pub trait ScanTask<T> {
    async fn scan<S: Send + Sync + AsyncRead + AsyncWrite + Unpin + 'static>(self, stream: &mut S) -> Result<T, SimpleError>;
    fn scanner_name() -> &'static str;
}
