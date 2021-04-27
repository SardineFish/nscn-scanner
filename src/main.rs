mod controller;
mod misc;
mod model;
mod utils;

pub use misc::error;
use model::Model;

use std::{ops::Range, str::FromStr};

use actix_web::{middleware::Logger, App};
use futures::stream::StreamExt;
use mongodb::bson::{doc, Document};
use mongodb::Database;
use nscn::error::*;
use nscn::{self, ScannerService};
use tokio::{
    self, task,
    time::{sleep, Duration},
};

#[actix_web::main]
async fn main() {
    env_logger::init();

    let scanner = ScannerService::start().await.unwrap();
    let mongodb = mongodb::Client::with_uri_str(&scanner.config().mongodb)
        .await
        .unwrap();
    let db = mongodb.database("nscn");
    let model = Model::new(db.clone());

    task::spawn(try_dispatch_address(scanner.clone()));
    task::spawn(try_dispatch_analysing(db.clone(), scanner.clone()));

    actix_web::HttpServer::new(move || {
        App::new()
            .data(scanner.clone())
            .data(model.clone())
            .wrap(Logger::new("%s - %r %Dms"))
            .configure(controller::config)
    })
    .bind("127.0.0.1:3000")
    .unwrap()
    .run()
    .await
    .unwrap();

    // scanner.join().await;
}

async fn try_dispatch_address(scanner: ScannerService) {
    let scheduler = scanner.scheculer();
    if !scanner.config().scanner.task.fetch {
        return;
    }
    log::info!("Start dispatching http scan address");
    if scanner.config().scanner.task.clear_old_tasks {
        if let Err(err) = scheduler.clear_tasks().await {
            log::error!("Failed to reset task queue: {}", err.msg);
        }
    }
    for url in &scanner.config().scanner.task.addr_src {
        let list = loop {
            match scanner.fetch_address_list(&url).await {
                Err(err) => log::error!("Failed to fetch address list from '{}': {}", url, err.msg),
                Ok(list) => break list,
            };
            sleep(Duration::from_secs(1)).await;
        };

        let mut count = 0;
        log::info!("Get {} address range from {}", list.len(), url);
        for ip_cidr in list {
            let range = match parse_ipv4_cidr(&ip_cidr) {
                Err(err) => {
                    log::error!("{}", err.msg);
                    continue;
                }
                Ok(range) => range,
            };
            count += range.len();
            if let Err(err) = scheduler.enqueue_addr_range(&ip_cidr).await {
                log::error!("Failed to enqueue http scan task: {}", err.msg);
            }
        }
        log::info!("Enqueue {} address", count);
    }
}

async fn try_dispatch_analysing(db: Database, scanner: ScannerService) {
    let mut scheduler = scanner.analyser();
    let query = doc! {
        "addr": "0.0.0.0",
        "$or": [
            {"scan.http.success": { "$gt": 0}},
            {"scan.tcp.21.ftp.success": { "$gt": 0}},
            {"scan.tcp.22.ssh.success": { "$gt": 0}},
        ],
    };
    let mut cursor = db
        .collection::<Document>("scan")
        .find(query, None)
        .await
        .unwrap();
    while let Some(Ok(doc)) = cursor.next().await {
        let addr = doc.get_str("addr").unwrap();
        scheduler.enqueue_task_addr(addr).await.unwrap();
    }
}

pub fn parse_ipv4_cidr(cidr: &str) -> Result<Range<u32>, SimpleError> {
    let slices: Vec<&str> = cidr.split("/").collect();
    if slices.len() < 2 {
        log::warn!("Invalid CIDR address");
        Err("Invalid CIDR address.")?
    } else {
        let base_ip: u32 = std::net::Ipv4Addr::from_str(slices[0]).unwrap().into();

        let cidr: i32 = slices[1].parse().unwrap();
        let offset = 32 - cidr;
        Ok(base_ip..base_ip + (1 << offset))
    }
}
