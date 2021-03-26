use std::{ops::Range};
use chrono::Utc;
use serde::{Serialize};
use openssl::ssl::Ssl;
use redis::{AsyncCommands, RedisError, pipe};
use tokio::{net::TcpStream, sync::mpsc::{Receiver, Sender, channel}, task::{self, JoinHandle}, time::{sleep, timeout}};
use mongodb::{Collection, Database, bson};

use crate::{config::GLOBAL_CONFIG, proxy::{ProxyPool, tunnel_proxy::TunnelProxyClient}, net_scanner::scanner::{DispatchScanTask, ScanResult, ScannerResources, Scheduler, TaskPool}};
use crate::error::*;
use crate::ssl::ssl_context::SSL_CONTEXT;
use crate::ssl::async_ssl;

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
            let client = self.resources.proxy_pool.get_tunnel_client().await;
            let result = self.scan(&client).await;
            let result = match result {
                Ok(data) => {
                    log::info!("HTTPS is enabled at {}", self.addr);
                    ScanResult::Ok(data)
                },
                Err(err) => ScanResult::Err(err.msg), //log::warn!("HTTPS scan failed at {}: {}", self.addr, err.msg),
            };
            self.resources.result_handler.save("https", &self.addr, &client.proxy_addr, result).await;
        })
    }
    async fn scan(&self, client: &TunnelProxyClient) -> Result<HttpsResponse, SimpleError> {
        // log::info!("Scan HTTPS {} through {}", self.addr, client.proxy_addr);

        let stream = self.connect_ssl(client).await?;


        match stream.sync_ssl().peer_certificate() {
            None => Err("No certificate")?,
            Some(cert) => {
                let pem = cert.to_pem()?;
                Ok(HttpsResponse {
                    cert: std::str::from_utf8(&pem[..])?.to_owned(),
                })
            }
        }
    }
    async fn connect_ssl(&self, client: &TunnelProxyClient) -> Result<async_ssl::SslStream<TcpStream>, SimpleError> {
        let stream = client.establish(&self.addr).await?;
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
