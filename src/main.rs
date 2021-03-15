mod http;
mod scheduler;
mod error;
mod proxy;
mod config;

use config::Config;
use http::HttpScanner;
use proxy::ProxyPool;
use redis::aio::MultiplexedConnection;
use tokio::task;

#[tokio::main]
async fn main()
{
    env_logger::init();

    let config = Config::from_file("config.json").await.unwrap();


    let mongodb = mongodb::Client::with_uri_str(&config.mongodb).await.unwrap();
    let db = mongodb.database("nscn");
    let redis = redis::Client::open(config.redis.as_str()).unwrap();
    let conn = redis.get_multiplexed_tokio_connection().await.unwrap();
    let proxy_pool = ProxyPool::new(&config.proxy_pool);
    let http_scanner = HttpScanner::new(db, conn, proxy_pool);
    let join = http_scanner.start();
    
    http_scanner.enqueue("47.102.198.236").await;

    join.await.unwrap();
}