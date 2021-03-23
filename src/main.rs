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
mod tcp_scanner;

#[allow(dead_code)]
mod redis_pool;

use std::ops::Range;

use address::{fetch_address_list};
use config::Config;
use http_scanner::HttpScanner;
use https_scanner::HttpsScanner;
use mongodb::Database;
use proxy::ProxyPool;
use config::GLOBAL_CONFIG;
use tokio::{sync::mpsc::Sender, task, time::sleep};

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
    let http_scanner = HttpScanner::open(db.clone(), &config.redis, proxy_pool.clone()).await;
    let join = http_scanner.start();
    let https_scanner = HttpsScanner::new(db.clone(), proxy_pool.clone()).await.unwrap();
    let https_task_sender = https_scanner.start().await;
    
    // http_scanner.enqueue("47.102.198.236").await.unwrap();
    task::spawn(async move {
        qps(db.clone()).await
    });

    try_dispatch_address(&http_scanner, &https_task_sender).await;

    // let range = parse_ipv4_cidr("47.102.198.0/24").unwrap();
    // for ip in range {
    //     let addr = std::net::Ipv4Addr::from(ip);
    //     http_scanner.enqueue(addr.to_string().as_str()).await;
    // }


    join.await.unwrap();
}

async fn qps(db: Database) {
    loop {
        let http_start = db.collection("http").estimated_document_count(None).await.unwrap();
        let https_start = db.collection("https").estimated_document_count(None).await.unwrap();
        sleep(tokio::time::Duration::from_secs(10)).await;
        let http_end = db.collection("http").estimated_document_count(None).await.unwrap();
        let https_end = db.collection("https").estimated_document_count(None).await.unwrap();
        log::info!("HTTP: {}/s, HTTPS: {}/s", (http_end - http_start) / 10, (https_end - https_start) / 10);
    }
}

async fn try_dispatch_address(scanner: &HttpScanner, https_task_sender: &Sender<Range<u32>>) {
    if !GLOBAL_CONFIG.scanner.task.dispatch {
        return;
    }
    log::info!("Start dispatching http scan address");
    if GLOBAL_CONFIG.scanner.task.clear_old_tasks {
        if let Err(err) = scanner.clear_task_queue().await {
            log::error!("Failed to reset task queue: {}", err.msg);
        }
    }
    for url in &GLOBAL_CONFIG.scanner.task.addr_src {
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
                    if let Err(err) = scanner.enqueue_range(range.clone()).await {
                        log::error!("Failed to enqueue http scan task: {}", err.msg);
                    }
                    if let Err(err) = https_task_sender.send(range).await {
                        log::error!("Failed to enqueue https scan task: {}", err);
                    }
                }
                log::info!("Enqueue {} address", count);
            }
        }
    }
}