use std::time::{Duration, Instant};

use serde::{Serialize};
use openssl::ssl::Ssl;
use tokio::{io::{AsyncRead, AsyncWrite}, task::{self, JoinHandle}, time::{timeout}};
use mongodb::{bson};

use crate::{config::GLOBAL_CONFIG, net_scanner::scheduler::{ScannerResources, TaskPool}};
use crate::error::*;
use crate::ssl::ssl_context::SSL_CONTEXT;
use crate::ssl::async_ssl;
use super::scheduler::ScanResult;

pub struct HttpsScanTask {
    addr: String,
    resources: ScannerResources,
}
impl HttpsScanTask {
    pub async fn spawn(addr: &str, resources: &ScannerResources, task_pool: &mut TaskPool) {
        let task = HttpsScanTask {
            addr: addr.to_owned(),
            resources: resources.clone(),
        };
        task_pool.spawn(task.run()).await
    }
    fn run(self) -> JoinHandle<()> {
        task::spawn(async move {
            let start = Instant::now();
            let mut proxy_addr = String::new();
            let result = match self.try_scan(&mut proxy_addr).await {
                Ok(data) => {
                    log::info!("HTTPS is enabled at {}", self.addr);
                    ScanResult::Ok(data)
                },
                Err(err) => ScanResult::Err(err.msg), //log::warn!("HTTPS scan failed at {}: {}", self.addr, err.msg),
            };
            let end = Instant::now();
            {
                let mut guard = self.resources.stats.lock().await;
                guard.https_time += (end - start).as_secs_f64();
                guard.https_tasks += 1;
            }
            self.resources.result_handler.save("https", &self.addr, &proxy_addr, result).await;
        })
    }
    async fn try_scan(&self, proxy_addr: &mut String) -> Result<HttpsResponse, SimpleError> {
        let target_addr = format!("{}:443", self.addr);
        match GLOBAL_CONFIG.scanner.https.socks5 {
            Some(true) => {
                let proxy = self.resources.proxy_pool.get_socks5_proxy().await;
                let mut stream = proxy.connect(&target_addr, GLOBAL_CONFIG.scanner.https.timeout).await?;
                *proxy_addr = proxy.addr;
                self.scan(&mut stream).await
            },
            _ => {
                let client = self.resources.proxy_pool.get_tunnel_client().await;
                let mut stream = client.establish(&target_addr).await?;
                *proxy_addr = client.proxy_addr;
                self.scan(&mut stream).await
            }
        }
    }
    async fn scan<S: AsyncRead + AsyncWrite + Unpin>(&self, stream: S) -> Result<HttpsResponse, SimpleError> {
        // log::info!("Scan HTTPS {} through {}", self.addr, client.proxy_addr);
        timeout(Duration::from_secs(GLOBAL_CONFIG.scanner.https.timeout), async move {
            let stream = self.connect_ssl(stream).await?;

            match stream.sync_ssl().peer_certificate() {
                None => Err("No certificate")?,
                Some(cert) => {
                    let pem = cert.to_pem()?;
                    Ok(HttpsResponse {
                        cert: std::str::from_utf8(&pem[..])?.to_owned(),
                    })
                }
            }
        }).await.map_err(|_|"Timeout")?
    }
    async fn connect_ssl<S: AsyncRead + AsyncWrite + Unpin>(&self, stream: S) -> Result<async_ssl::SslStream<S>, SimpleError> {
        // log::info!("ESTABLISHED");
        let ssl = Ssl::new(&SSL_CONTEXT)?;
        let mut stream = async_ssl::SslStream::new(ssl, stream)?;
        match timeout(tokio::time::Duration::from_secs(GLOBAL_CONFIG.scanner.https.timeout), stream.connect()).await{
            Ok(Ok(())) => Ok(stream),
            Ok(Err(err)) => Err(err)?,
            Err(_) => Err("SSL Handshake timeout.")?,
        }
    }
}

#[derive(Serialize)]
struct HttpsScanRecord {
    address: String,
    proxy: String,
    time: bson::DateTime,
    result: ScanResult<HttpsResponse>,
}

#[derive(Serialize)]
pub struct HttpsResponse {
    cert: String,
}
