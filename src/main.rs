#![feature(generators, generator_trait)]

mod http;
mod scheduler;
mod error;
mod proxy;
mod config;
mod address;
mod redis_pool;

use address::{fetch_address_list, parse_ipv4_cidr};
use config::Config;
use http::HttpScanner;
use proxy::ProxyPool;
use redis::aio::MultiplexedConnection;
use redis_pool::RedisPool;
use tokio::task;
use std::sync::Arc;

#[tokio::main]
async fn main()
{
    env_logger::init();

    let config = Config::from_file("config.json").await.unwrap();

    let mongodb = mongodb::Client::with_uri_str(&config.mongodb).await.unwrap();
    let db = mongodb.database("nscn");
    let redis_pool = Arc::new(RedisPool::open(&config.redis));
    let redis = redis::Client::open(config.redis.as_str()).unwrap();
    let conn = redis.get_multiplexed_tokio_connection().await.unwrap();
    let proxy_pool = ProxyPool::new(&config.proxy_pool);
    let http_scanner = HttpScanner::open(db, &config.redis, proxy_pool).await;
    let join = http_scanner.start();
    
    http_scanner.enqueue("47.102.198.236").await;

    for url in config.addr_src {
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
                        http_scanner.enqueue(addr.to_string().as_str()).await;
                    }
                }
                log::info!("Enqueue {} address", count);
            }
        }
    }

    // let range = parse_ipv4_cidr("47.102.198.0/24").unwrap();
    // for ip in range {
    //     let addr = std::net::Ipv4Addr::from(ip);
    //     http_scanner.enqueue(addr.to_string().as_str()).await;
    // }

    join.await.unwrap();
}