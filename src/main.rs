#![allow(dead_code)]

mod error;
mod proxy;
mod config;
mod address;
mod http;
mod ssl;
mod net_scanner;
mod utils;

#[allow(dead_code)]
mod redis_pool;

use std::time::Duration;

use address::{fetch_address_list};
use config::Config;
use proxy::ProxyPool;
use config::GLOBAL_CONFIG;
use net_scanner::scheduler::{NetScanner, SchedulerController};
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
    let scanner = NetScanner::new(&config.redis, &db, &proxy_pool);
    let scheduler = scanner.start().unwrap();
    
    // http_scanner.enqueue("47.102.198.236").await.unwrap();
    
    stats(&scheduler);

    try_dispatch_address(&scheduler).await;

    // let range = parse_ipv4_cidr("47.102.198.0/24").unwrap();
    // for ip in range {
    //     let addr = std::net::Ipv4Addr::from(ip);
    //     http_scanner.enqueue(addr.to_string().as_str()).await;
    // }

    scheduler.join().await;
}

fn stats(scheduler: &SchedulerController) {
    let scheduler = scheduler.clone();
    let interval = 10.0;
    task::spawn(async move {
        loop {
            sleep(tokio::time::Duration::from_secs_f64(interval)).await;
            let stats = scheduler.reset_stats().await;
            log::info!("Scan speed: {:.2} IP/s, {:.2} Tasks/s", stats.dispatched_addrs as f64 / interval, stats.dispatched_tasks as f64 / interval);
            
                // log::info!("HTTP {} avg. {:.2}s, HTTPS {} avg. {:.2}s, FTP {} avg. {:.2}s, SSH {} avg. {:.2}s, TASK {} {} avg. {:.5}s, Spawn {:.5}s, Send {:.5}s",
                //     stats.http_tasks, stats.http_time / stats.http_tasks as f64, 
                //     stats.https_tasks, stats.https_time / stats.https_tasks as f64, 
                //     stats.ftp_tasks, stats.ftp_time / stats.ftp_tasks as f64, 
                //     stats.ssh_tasks, stats.ssh_time / stats.ssh_tasks as f64,
                //     stats.dispatched_tasks, stats.active_tasks, stats.task_time / stats.dispatched_tasks as f64,
                //     stats.spawn_time / stats.dispatched_tasks as f64,
                //     stats.send_time / stats.dispatched_tasks as f64,
                // );
            
        }
    });
}

async fn try_dispatch_address(scheduler: &SchedulerController) {
    let scheduler = scheduler.clone();
    if !GLOBAL_CONFIG.scanner.task.fetch {
        return;
    }
    log::info!("Start dispatching http scan address");
    if GLOBAL_CONFIG.scanner.task.clear_old_tasks {
        if let Err(err) = scheduler.clear_tasks().await {
            log::error!("Failed to reset task queue: {}", err.msg);
        }
    }
    for url in &GLOBAL_CONFIG.scanner.task.addr_src {
        let list = loop {
            match fetch_address_list(&url).await {
                Err(err) => log::error!("Failed to fetch address list from '{}': {}", url, err.msg),
                Ok(list) => {
                    break list
                }
            };
            sleep(Duration::from_secs(1)).await;
        };
        
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
            if let Err(err) = scheduler.enqueue_range(range).await {
                log::error!("Failed to enqueue http scan task: {}", err.msg);
            }
        }
        log::info!("Enqueue {} address", count);
    }
}