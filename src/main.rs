

mod http;
mod scheduler;
mod error;
mod proxy;
mod config;
mod address;

#[allow(dead_code)]
mod redis_pool;

use address::{fetch_address_list};
use config::Config;
use http::HttpScanner;
use proxy::ProxyPool;
use config::GLOBAL_CONFIG;
use tokio::time::sleep;

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
    let _ = http_scanner.start();
    
    // http_scanner.enqueue("47.102.198.236").await.unwrap();

    try_dispatch_address(&http_scanner).await;

    // let range = parse_ipv4_cidr("47.102.198.0/24").unwrap();
    // for ip in range {
    //     let addr = std::net::Ipv4Addr::from(ip);
    //     http_scanner.enqueue(addr.to_string().as_str()).await;
    // }

    loop {
        let count_start = db.collection("http").estimated_document_count(None).await.unwrap();
        sleep(tokio::time::Duration::from_secs(10)).await;
        let count_end = db.collection("http").estimated_document_count(None).await.unwrap();
        log::info!("{}/s", (count_end - count_start) / 10);
    }

    // join.await.unwrap();
}

async fn try_dispatch_address(scanner: &HttpScanner) {
    for url in &GLOBAL_CONFIG.addr_src {
        match fetch_address_list(&url).await {
            Err(err) => log::error!("Failed to fetch address list from '{}': {}", url, err.msg),
            Ok(list) => {
                let mut count = 0;
                log::info!("Get {} address range from {}", list.len(), url);
                for range in list {
                    count += range.len();
                    for ip in range {
                        let addr = std::net::Ipv4Addr::from(ip);
                        // log::info!("{}", addr.to_string());
                        if let Err(err) = scanner.enqueue(addr.to_string().as_str()).await {
                            log::error!("Failed to enqueue http scan task: {}", err.msg);
                        }
                    }
                }
                log::info!("Enqueue {} address", count);
            }
        }
    }
}