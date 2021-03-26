use std::{ops::Range};
use chrono::Utc;
use serde::{Serialize};
use openssl::ssl::Ssl;
use redis::{AsyncCommands, RedisError, pipe};
use tokio::{net::TcpStream, sync::mpsc::{Receiver, Sender, channel}, task::{self, JoinHandle}, time::{sleep, timeout}};
use mongodb::{Collection, Database, bson};

use crate::{async_ssl, config::GLOBAL_CONFIG, http_scanner::ScanResult, proxy::{ProxyPool, tunnel_proxy::TunnelProxyClient}, scanner::{DispatchScanTask, ScannerResources, Scheduler, TaskPool}};
use crate::error::*;
use crate::ssl_context::SSL_CONTEXT;

const KEY_TASK_QUEUE: &str = "https:task_queue";
const COLLECTION_RESULT: &str = "https";

pub struct HttpsScanner {
    db: Database,
    proxy_pool: ProxyPool,
}

impl HttpsScanner {
    pub async fn new(db: Database, proxy_pool: ProxyPool) -> Result<Self, SimpleError> {
        Ok(Self {
            db,
            proxy_pool,
        })
    }
    pub async fn start(self) -> Sender<Range<u32>> {
        let (sender, receiver) = channel::<Range<u32>>(256);
        task::spawn(async move {
            self.dispatch_tasks().await.log_error_consume("https_scanner_spawn");
        });
        task::spawn(async move {
            Self::enqueue_tasks(receiver).await.log_error_consume("https_scanner_spawn");
        });

        sender
    }
    async fn dispatch_tasks(self) -> Result<(), SimpleError> {
        let mut redis = redis::Client::open(GLOBAL_CONFIG.redis.as_str())?
            .get_async_connection().await?;
        let (complete_sender, mut complete_receiver) = 
            channel::<bool>(GLOBAL_CONFIG.scanner.https.max_tasks);
        let mut active_tasks = 0;
        let collection = self.db.collection(COLLECTION_RESULT);
        let mut startup = true;

        loop {
            if active_tasks >= GLOBAL_CONFIG.scanner.https.max_tasks {
                startup = false;
                match (&mut complete_receiver).recv().await {
                    Some(_) => active_tasks -= 1,
                    None => log::error!("Channel closed"),
                }
            }
            if startup {
                let interval = (GLOBAL_CONFIG.scanner.https.timeout as f64) / (GLOBAL_CONFIG.scanner.https.max_tasks as f64);
                sleep(tokio::time::Duration::from_secs_f64(interval)).await;
            }

            let result: Result<(String, String), RedisError> = redis.brpop(KEY_TASK_QUEUE, 0).await;
            match result {
                Err(err) if err.is_timeout() => (),
                Err(err) => log::error!("Failed to pop https scanning task: {}", err),
                Ok((_, addr)) => {
                    let task = HttpsScanTask {
                        addr: format!("{}:443", addr),
                        collection: collection.clone(),
                        complete: complete_sender.clone(),
                        proxy_pool: self.proxy_pool.clone(),
                    };
                    task.run();
                    active_tasks += 1;
                }
            }

        }
    }
    async fn enqueue_tasks(mut receiver: Receiver<Range<u32>>) -> Result<(), SimpleError> {
        let mut redis = redis::Client::open(GLOBAL_CONFIG.redis.as_str())?
            .get_async_connection().await?;

        loop {
            match (&mut receiver).recv().await {
                Some(range) => {
                    
                    while redis.llen::<'_, _, i64>(KEY_TASK_QUEUE).await? > 5_000_000 {
                        sleep(tokio::time::Duration::from_secs(60)).await;
                    }
                    let mut pipe = pipe();
                    for ip in range {
                        let addr = std::net::Ipv4Addr::from(ip).to_string();
                        pipe.lpush(KEY_TASK_QUEUE, &addr).ignore();
                    }
                    let result: Result<(), RedisError> = pipe.query_async(&mut redis).await;
                    if let Err(err) = result {
                        log::error!("Failed to enqueue http scan range: {}", err);
                    }
                }
                None => return Err("Failed to receive task: Channel closed.")?,
            }
        }
    }
}

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
            let client = self.proxy_pool.get_tunnel_client().await;
            let result = self.scan(&client).await;
            match &result {
                Ok(_) => log::info!("HTTPS is enabled at {}", self.addr),
                Err(_err) => (), //log::warn!("HTTPS scan failed at {}: {}", self.addr, err.msg),
            }
            match self.save_result(client.proxy_addr, result).await {
                Ok(_) => (),
                Err(err) => log::error!("Saving https scanning task failed: {}", err.msg),
            }
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
    async fn save_result(self, proxy_addr: String, result: Result<HttpsResponse, SimpleError>) -> Result<(), SimpleError> {
        let record = HttpsScanRecord {
            address: self.addr,
            proxy: proxy_addr,
            time: Utc::now().into(),
            result: match result {
                Ok(response) => ScanResult::Ok(response),
                Err(err) => ScanResult::Err(err.msg),
            }
        };

        self.collection.insert_one(bson::to_document(&record)?, None).await?;

        self.complete.send(true).await?;
        Ok(())
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
