#![allow(dead_code)]

mod http_scanner;
mod scheduler;
mod error;
mod proxy;
mod config;
mod address;
mod http;
mod ssl_context;
mod async_ssl;
mod https_scanner;

#[allow(dead_code)]
mod redis_pool;

use address::{fetch_address_list};
use config::Config;
use http_scanner::HttpScanner;
use mongodb::Database;
use proxy::ProxyPool;
use config::GLOBAL_CONFIG;
use tokio::{task, time::sleep};

#[tokio::main]
async fn main()
{
    env_logger::init();

    let config = Config::from_file("config.json").await.unwrap();

    let mongodb = mongodb::Client::with_uri_str(&config.mongodb).await.unwrap();
    let db = mongodb.database("nscn");
    // let redis_pool = Arc::new(RedisPool::open(&config.redis));
    // let redis = redis::Client::open(config.redis.as_str()).unwrap();
    // let conn = redis.get_multiplexed_tokio_connection().await.unwrap();
    let proxy_pool = ProxyPool::new();
    proxy_pool.start().await;
    let http_scanner = HttpScanner::open(db.clone(), &config.redis, proxy_pool).await;
    let join = http_scanner.start();
    
    // http_scanner.enqueue("47.102.198.236").await.unwrap();
    task::spawn(async move {
        qps(db.clone()).await
    });

    try_dispatch_address(&http_scanner).await;

    // let range = parse_ipv4_cidr("47.102.198.0/24").unwrap();
    // for ip in range {
    //     let addr = std::net::Ipv4Addr::from(ip);
    //     http_scanner.enqueue(addr.to_string().as_str()).await;
    // }


    join.await.unwrap();
}

async fn qps(db: Database) {
    loop {
        let count_start = db.collection("http").estimated_document_count(None).await.unwrap();
        sleep(tokio::time::Duration::from_secs(10)).await;
        let count_end = db.collection("http").estimated_document_count(None).await.unwrap();
        log::info!("{}/s", (count_end - count_start) / 10);
    }
}

async fn try_dispatch_address(scanner: &HttpScanner) {
    if !GLOBAL_CONFIG.dispatch_task {
        return;
    }
    log::info!("Start dispatching http scan address");
    if GLOBAL_CONFIG.reset_task_queue {
        if let Err(err) = scanner.clear_task_queue().await {
            log::error!("Failed to reset task queue: {}", err.msg);
        } else {
        }
    }
    for url in &GLOBAL_CONFIG.addr_src {
        match fetch_address_list(&url).await {
            Err(err) => log::error!("Failed to fetch address list from '{}': {}", url, err.msg),
            Ok(list) => {
                let mut count = 0;
                log::info!("Get {} address range from {}", list.len(), url);
                for range in list {
                    count += range.len();
                    // for ip in range {
                    //     let addr = std::net::Ipv4Addr::from(ip);
                    //     // log::info!("{}", addr.to_string());
                    //     if let Err(err) = scanner.enqueue(addr.to_string().as_str()).await {
                    //         log::error!("Failed to enqueue http scan task: {}", err.msg);
                    //     }
                    // }
                    if let Err(err) = scanner.enqueue_range(range).await {
                        log::error!("Failed to enqueue http scan task: {}", err.msg);
                    }
                }
                log::info!("Enqueue {} address", count);
            }
        }
    }
}