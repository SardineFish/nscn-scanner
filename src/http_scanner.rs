use std::{collections::HashMap, ops::Range};

use chrono::Utc;
use mongodb::{Collection, Database, bson};
use redis::{AsyncCommands, RedisError, aio::MultiplexedConnection};
use reqwest::{ Response, header::HeaderMap};
use serde::{Serialize, Deserialize};
use tokio::{sync::mpsc::{Sender, channel}, task::{self, JoinHandle}, time::sleep};
use crate::{error::{*}, proxy::ProxyPool};
use crate::config::GLOBAL_CONFIG;


#[derive(Serialize, Deserialize)]
struct HttpScanResult {
    address: String,
    proxy: String,
    time: bson::DateTime,
    result: ScanResult<HttpResponseData>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag="state", content="response")]
pub enum ScanResult<T> {
    Ok(T),
    Err(String),
}

#[derive(Serialize, Deserialize)]
pub struct HttpResponseData {
    status: i32,
    headers: HashMap<String, Vec<String>>,
    body: String,
}

impl HttpResponseData {
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
    pub async fn clear_task_queue(&self) -> Result<(), SimpleError> {
        let mut conn = self.dispatcher_conn.clone();
        let result: Result<i32, RedisError> = conn.del(TASK_QUEUE).await;
        if let Err(err) = result {
            log::error!("Failed to enqueue http scan task: {}", err);
        }
        log::info!("Task queue cleared.");
        Ok(())
    }
    pub async fn enqueue(&self, address: &str) -> Result<(), SimpleError> {
        let mut conn = self.dispatcher_conn.clone();
        let result: Result<i32, RedisError> = conn.lpush(TASK_QUEUE, address).await;
        if let Err(err) = result {
            log::error!("Failed to enqueue http scan task: {}", err);
        }
        Ok(())
    }
    pub async fn enqueue_range(&self, range: Range<u32>) -> Result<(), SimpleError> {
        let mut conn = self.dispatcher_conn.clone();
        while conn.llen::<'_, _, i64>(TASK_QUEUE).await? > 5_000_000 {
            sleep(tokio::time::Duration::from_secs(60)).await;
        }
        let mut pipe = redis::pipe();
        for ip in range {
            let addr = std::net::Ipv4Addr::from(ip).to_string();
            pipe.lpush(TASK_QUEUE, &addr).ignore();
        }
        let result: Result<(), RedisError> = pipe.query_async(&mut conn).await;
        if let Err(err) = result {
            log::error!("Failed to enqueue http scan range: {}", err);
        }
        Ok(())
    }
    pub fn start(&self) -> JoinHandle<()> {
        let redis = redis::Client::open(self.redis_url.as_str()).unwrap();
        let scanner = self.clone();

        task::spawn(async move {
            let (sender, mut receiver) = channel::<()>(1024);
            let mut conn =  redis.get_async_connection().await.unwrap();

            let mut task_count = 0;
            
            log::info!("Start http scanner");

            loop {
                while task_count < GLOBAL_CONFIG.scanner.http.max_tasks
                {
                    let result: Result<(String, String), redis::RedisError> = conn.brpop(TASK_QUEUE, 0).await;
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
    async fn scan(&self) -> Result<(), SimpleError> {
        // let proxy_addr = self.proxy_pool.get().await;
        // let proxy = reqwest::Proxy::http(format!("http://{}", proxy_addr))?;
        // log::debug!("Use http proxy {}", proxy_addr);
        
        // log::info!("Http scan {} through {}", self.address, proxy_addr);

        let client = self.proxy_pool.get_http_client().await;

        let result = client.client.get(format!("http://{}", self.address))
            .send()
            .await;

        let scan_result = HttpScanResult {
            address: self.address.to_owned(),
            time: Utc::now().into(),
            proxy: client.proxy_addr,
            result: match result {
                Ok(response) => {
                    log::info!("GET {} - {}", self.address, response.status());
                    ScanResult::Ok(HttpResponseData::from_response(response).await)
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