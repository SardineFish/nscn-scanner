use std::marker::PhantomData;

use async_trait::async_trait;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{ScanTaskInfo, error::SimpleError, scheduler::TaskPool};

use super::scheduler::ScannerResources;

pub struct TcpScanTask<T, R>
{
    addr: String,
    port: u16,
    timeout: u64,
    task: T,
    _phantom: PhantomData<R>,
}

impl<T, R> TcpScanTask<T, R> where T: ScanTask<R> + Send + 'static, R: Serialize + Send + 'static {
    pub fn new(addr: String, port: u16, task: T) -> Self {
        Self {
            addr,
            port,
            task,
            timeout: 5,
            _phantom: PhantomData::default(),
        }
    }
    pub fn timeout(&mut self, timeout: u64) -> &mut Self {
        self.timeout = timeout;
        self
    }
    pub async fn start(self, resources: &mut ScannerResources) {
        let proxy = resources.proxy_pool.get_socks5_proxy().await;
        let result = match proxy.connect(&format!("{}:{}", self.addr, self.port), self.timeout).await {
            Ok(mut stream) => match self.task.scan(&mut stream).await {
                Ok(result) => ScanTaskInfo::with_proxy(proxy.addr, result),
                Err(err) => ScanTaskInfo::err_with_proxy(proxy.addr, err),
            }
            Err(err) => ScanTaskInfo::err_with_proxy(proxy.addr, err),
        };

        resources.result_handler.save_scan_results(T::scanner_name(), &self.addr, result).await;
    }
    pub async fn schedule(self, task_pool: &mut TaskPool<ScannerResources>) {
        task_pool.spawn(T::scanner_name(), Self::start, self).await
    }
}

// impl<'r, 's, F, Task, T, S>  TcpScanTask<'r, 's, F, Task, T, S>
// where 
//     F: FnOnce(Task, &'s mut S, &'r mut ScannerResources) -> T,
//     T: Future + Send + 'static,
//     T::Output: Send + 'static,
//     S: Send + AsyncRead + AsyncWrite + 'static,
// {
//     fn new(addr: String, port: u16, func: F) -> Self {
//         Self {
//             addr,
//             port,
//             func,
//             timeout: 5,
//             _phantom: PhantomData::default(),
//         }
//     }

//     pub async fn scan(self, resources: &'r mut ScannerResources) {
//         let proxy = resources.proxy_pool.get_socks5_proxy().await;
//         match proxy.connect(format!("{}:{}", self.addr, self.port), self.timeout).await {
//             Ok(stream) => {
//                 self.func()
//             }
//         }
//     }
// }

#[async_trait]
pub trait ScanTask<T> {
    async fn scan<S: Send + Sync + AsyncRead + AsyncWrite + Unpin + 'static>(self, stream: &mut S) -> Result<T, SimpleError>;
    fn scanner_name() -> &'static str;
}
