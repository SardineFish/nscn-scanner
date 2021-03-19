use std::{ops::Range};
use chrono::Utc;
use reqwest::StatusCode;
use serde::{Serialize};
use openssl::x509::X509;
use openssl::ssl::Ssl;
use redis::{AsyncCommands, Commands, RedisError, pipe};
use tokio::{sync::mpsc::{Receiver, Sender, channel}, task::{self, JoinHandle}};
use mongodb::{Collection, Database, bson};

use crate::{async_ssl, config::GLOBAL_CONFIG, http_scanner::ScanResult, proxy::{ProxyPool, TunnelProxyClient}};
use crate::error::*;
use crate::ssl_context::SSL_CONTEXT;

const KEY_TASK_QUEUE: &str = "https:task_queue";
const COLLECTION_RESULT: &str = "https";

pub struct HttpsScanner {
    db: Database,
    proxy_pool: ProxyPool,
}

impl HttpsScanner {
    async fn new(db: Database, proxy_pool: ProxyPool) -> Result<Self, SimpleError> {
        Ok(Self {
            db,
            proxy_pool,
        })
    }
    pub async fn start(self) -> Sender<Range<u32>> {
        let (sender, receiver) = channel::<Range<u32>>(256);
        task::spawn(async move {
            self.dispatch_tasks().await;
        });
        task::spawn(Self::enqueue_tasks(receiver));

        sender
    }
    async fn dispatch_tasks(self) -> Result<(), SimpleError> {
        let mut redis = redis::Client::open(GLOBAL_CONFIG.redis.as_str())?
            .get_async_connection().await?;
        let (complete_sender, mut complete_receiver) = channel::<bool>(GLOBAL_CONFIG.max_tasks);
        let mut active_tasks = 0;
        let collection = self.db.collection(COLLECTION_RESULT);

        loop {
            if active_tasks >= GLOBAL_CONFIG.max_tasks {
                match complete_receiver.recv().await {
                    Some(r) => active_tasks -= 1,
                    None => log::error!("Channel closed"),
                }
            }

            let result: Result<(String, String), RedisError> = redis.brpop(KEY_TASK_QUEUE, 0).await;
            match result {
                Err(err) if err.is_timeout() => (),
                Err(err) => log::error!("Failed to pop https scanning task: {}", err),
                Ok((_, addr)) => {
                    let task = HttpsScanTask {
                        addr: addr,
                        collection: collection.clone(),
                        complete: complete_sender.clone(),
                        proxy_pool: self.proxy_pool.clone(),
                    };
                    task.dispatch();
                    active_tasks += 1;
                }
            }

        }
    }
    async fn enqueue_tasks(mut receiver: Receiver<Range<u32>>) -> Result<(), SimpleError> {
        let mut redis = redis::Client::open(GLOBAL_CONFIG.redis.as_str())?
            .get_async_connection().await?;

        loop {
            match receiver.recv().await {
                Some(range) => {
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

struct HttpsScanTask {
    addr: String,
    complete: Sender<bool>,
    collection: Collection,
    proxy_pool: ProxyPool,
}
impl HttpsScanTask {
    fn dispatch(self) -> JoinHandle<()> {
        task::spawn(async move {
            let client = self.proxy_pool.get_tunnel_client().await;
            let result = self.scan(&client).await;
            match self.save_result(client.proxy_addr, result).await {
                Ok(_) => (),
                Err(err) => log::error!("Https scanning task failed: {}", err.msg),
            }
            
        })
    }
    async fn scan(&self, client: &TunnelProxyClient) -> Result<HttpsResponse, SimpleError> {
        let stream = client.establish(&self.addr).await?;
        let ssl = Ssl::new(&SSL_CONTEXT)?;
        let mut stream = async_ssl::SslStream::new(ssl, stream)?;
        stream.connect().await?;

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
struct HttpsResponse {
    cert: String,
}
