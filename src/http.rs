use std::{collections::HashMap, time::Duration};

use chrono::Utc;
use mongodb::{Collection, Database, bson};
use redis::{AsyncCommands, RedisError, aio::MultiplexedConnection};
use reqwest::{Client, Response, StatusCode, header::HeaderMap};
use serde::{Serialize, Deserialize};
use tokio::{sync::mpsc::{Sender, channel}, task::{self, JoinHandle}};
use std::sync::Arc;
use crate::{error::{*, self}, proxy::ProxyPool, redis_pool::{ RedisPool}};
use crate::config::GLOBAL_CONFIG;


#[derive(Serialize, Deserialize)]
struct HttpScanResult {
    address: String,
    time: bson::DateTime,
    result: ScanResult<ResponseData>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag="state", content="response")]
enum ScanResult<T> {
    Ok(T),
    Err(String),
}

#[derive(Serialize, Deserialize)]
struct ResponseData {
    status: i32,
    headers: HashMap<String, Vec<String>>,
    body: String,
}

impl ResponseData {
    async fn from_response(response: Response) -> Self {
        Self {
            headers: response.headers().serialize(),
            status: response.status().as_u16() as i32,
            body: response.text().await.unwrap_or("Failed to parse body".to_owned()),
        }
    }
}

trait SerializeHeaders {
    fn serialize(&self) -> HashMap<String, Vec<String>>;
}

impl SerializeHeaders for HeaderMap {
    fn serialize(&self) -> HashMap<String, Vec<String>> {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for key in self.keys() {
            let values = self.get_all(key).iter()
                .filter_map(|value| value.to_str().ok().map(str::to_owned))
                .collect();
            map.insert(key.to_string(), values);
        }
        map
    }
}


const COLLECTION: &str = "http";
const TASK_QUEUE: &str = "http:task_queue";

#[derive(Clone)]
pub struct HttpScanner {
    collection: Collection,
    redis_url: String,
    proxy_pool: ProxyPool,
    dispatcher_conn: MultiplexedConnection,
}

impl HttpScanner {
    pub async fn open(db: Database, redis_url: &str, proxy_pool: ProxyPool) -> Self {
        Self {
            collection: db.collection(COLLECTION),
            redis_url: redis_url.to_owned(),
            proxy_pool,
            dispatcher_conn: redis::Client::open(redis_url).unwrap().get_multiplexed_tokio_connection().await.unwrap(),
        }
    }
    pub async fn enqueue(&self, address: &str) -> Result<(), ErrorMsg> {
        let mut conn = self.dispatcher_conn.clone();
        let result: Result<i32, RedisError> = conn.lpush(TASK_QUEUE, address).await;
        if let Err(err) = result {
            log::error!("Failed to enqueue http scan task: {}", err);
        }
        Ok(())
    }
    pub fn start(&self) -> JoinHandle<()> {
        let redis = redis::Client::open(self.redis_url.as_str()).unwrap();
        let scanner = self.clone();

        task::spawn(async move {
            let (sender, mut receiver) = channel::<()>(1024);

            let mut task_count = 0;
            
            log::info!("Start http scanner");

            loop {
                while task_count < GLOBAL_CONFIG.max_tasks
                {
                    let result: Result<(String, String), redis::RedisError> = redis.get_async_connection().await.unwrap()
                        .brpop(TASK_QUEUE, 0).await;
                    match result {
                        Err(err) if err.is_timeout() => (),
                        Err(err) => log::error!("Failed to execute cmd BRPOP :{}", err),
                        Ok((_, addr)) => {
                            scanner.spawn_task(addr, &sender);
                            task_count += 1;
                        },
                    };
                }
                if let Some(_) = receiver.recv().await {
                    task_count -= 1;
                }
            }
        })
    }
    
    fn spawn_task(&self, addr: String, complete_sender: &Sender<()>) {
        log::debug!("Start http scanning for {}", addr);
        let task = HttpScanTask {
            address: addr,
            collection: self.collection.clone(),
            complete: complete_sender.clone(),
            proxy_pool: self.proxy_pool.clone(),
        };

        task::spawn(async move {
            task.run().await;
        });
    }
}

struct HttpScanTask {
    address: String,
    collection: Collection,
    complete: Sender<()>,
    proxy_pool: ProxyPool,
}

impl HttpScanTask {
    async fn run(&self) {
        let result = self.scan().await;
        match result {
            Ok(_) => (),
            Err(err) => log::error!("{} {}", self.address, err.msg),
        }
        if let Err(err) = self.complete.send(()).await{
            log::error!("Failed to send task complete signal: {}", err);
        }
    }
    async fn scan(&self) -> Result<(), ErrorMsg> {
        // let proxy_addr = self.proxy_pool.get().await;
        // let proxy = reqwest::Proxy::http(format!("http://{}", proxy_addr))?;
        // log::debug!("Use http proxy {}", proxy_addr);
        
        // log::info!("Http scan {} through {}", self.address, proxy_addr);

        let client = self.proxy_pool.get_client().await;

        let result = client.get(format!("http://{}", self.address))
            .send()
            .await;

        let scan_result = HttpScanResult {
            address: self.address.to_owned(),
            time: Utc::now().into(),
            result: match result {
                Ok(response) => {
                    log::info!("GET {} - {}", self.address, response.status());
                    ScanResult::Ok(ResponseData::from_response(response).await)
                },
                Err(err) => ScanResult::Err(err.to_string())
            },
        };

        let doc = bson::to_document(&scan_result)?;
        self.collection.insert_one(doc, None)
            .await?;

        Ok(())
    }
}