mod http;
mod scheduler;
mod error;

use http::HttpScanner;
use redis::aio::MultiplexedConnection;
use tokio::task;

#[tokio::main]
async fn main()
{
    env_logger::init();

    let mongodb = mongodb::Client::with_uri_str("mongo://localhost").await.unwrap();
    let db = mongodb.database("nscn");
    let redis = redis::Client::open("redis://localhost").unwrap();
    let conn = redis.get_multiplexed_tokio_connection().await.unwrap();
    let http_scanner = HttpScanner::new(db, conn);
    let join = task::spawn(async move {
        http_scanner.start().await;
    });

    

    join.await.unwrap();
}