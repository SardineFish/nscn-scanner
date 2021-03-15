use std::collections::HashMap;

use chrono::Utc;
use mongodb::{Collection, Database, bson};
use redis::{AsyncCommands, RedisError, aio::MultiplexedConnection};
use reqwest::{Client, Response, header::HeaderMap};
use serde::{Serialize, Deserialize};
use tokio::{sync::mpsc::{Sender, channel}, task};
use crate::error::{*, self};


#[derive(Serialize, Deserialize)]
struct HttpScanResult {
    address: String,
    time: bson::DateTime,
    result: Result<ResponseData, String>,
}

#[derive(Serialize, Deserialize)]
struct ResponseData {
    headers: HashMap<String, Vec<String>>,
    body: String,
}

impl ResponseData {
    async fn from_response(response: Response) -> Self {
        Self {
            headers: response.headers().serialize(),
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
const MAX_TASKS: usize = 4;

pub struct HttpScanner {
    collection: Collection,
    redis: MultiplexedConnection,
}

impl HttpScanner {
    pub fn new(db: Database, redis: MultiplexedConnection) -> Self {
        Self {
            collection: db.collection(COLLECTION),
            redis,
        }
    }
    pub async fn enqueue(&self, address: &str) {
        let result: Result<i32, RedisError> = self.redis.clone().lpush(TASK_QUEUE, address).await;
        if let Err(err) = result {
            log::error!("Failed to enqueue http scan task: {}", err);
        }
    }
    pub async fn start(&self) {
        let redis = self.redis.clone();

        let (sender, mut receiver) = channel::<()>(1024);

        let mut task_count = 0;

        loop {
            while task_count < MAX_TASKS
            {
                let result: Result<String, redis::RedisError> = redis.clone().brpop(TASK_QUEUE, 1000).await;
                match result {
                    Err(err) if err.is_timeout() => (),
                    Err(err) => log::error!("{}", err),
                    Ok(addr) => {
                        let sender = sender.clone();
                        let collection = self.collection.clone();
                        task::spawn(async {
                            Self::run(addr, collection, sender).await;
                        });
                        task_count += 1;
                    },
                };
            }
            if let Some(_) = receiver.recv().await {
                task_count -= 1;
            }
        }

    }
    async fn run(address: String, collection: Collection, complete: Sender<()>) {
        let result = Self::scan(&address, collection).await;
        match result {
            Ok(_) => (),
            Err(err) => log::error!("{} {}", address, err.msg),
        }
        if let Err(err) = complete.send(()).await{
            log::error!("Failed to send task complete signal: {}", err);
        }
    }
    async fn scan(address: &str, collection: Collection) -> Result<(), ErrorMsg> {
        let result = reqwest::get(format!("http://{}", address))
            .await;

        let scan_result = HttpScanResult {
            address: address.to_owned(),
            time: Utc::now().into(),
            result: match result {
                Ok(response) => Ok(ResponseData::from_response(response).await),
                Err(err) => Err(err.to_string())
            },
        };

        let doc = bson::to_document(&scan_result)?;
        collection.insert_one(doc, None)
            .await?;

        Ok(())
    }
}