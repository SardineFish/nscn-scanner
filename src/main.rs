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
use nscn::{GLOBAL_CONFIG, MasterService, error::*};
use nscn::{self, WorkerService};
use tokio::{
    self, task,
    time::{sleep, Duration},
};

#[actix_web::main]
async fn main() {
    env_logger::init();

    log::info!("Run as {}", GLOBAL_CONFIG.role);
    
    let mongodb = mongodb::Client::with_uri_str(&GLOBAL_CONFIG.mongodb)
        .await
        .unwrap();
    let db = mongodb.database("nscn");
    let model = Model::new(db.clone());

    if let Some(true) = GLOBAL_CONFIG.init {
        model.init().await.log_error_consume("init");
        log::info!("Initialzed database");
    }

    let worker = WorkerService::new().await.unwrap();

    
    let master = match GLOBAL_CONFIG.role {
        nscn::NodeRole::Worker => None,
        nscn::NodeRole::Master | nscn::NodeRole::Standalone => {
            Some(MasterService::new().await.unwrap())
        }
    };

    let moved_master = master.clone();

    let server = actix_web::HttpServer::new(move || {
        let mut app = App::new();
        app = match &moved_master {
            Some(moved_master) => app.data(moved_master.clone()),
            None => app
        };

        app
            .data(worker.clone())
            .data(model.clone())
            .wrap(Logger::new("%s - %r %Dms"))
            .configure(controller::config)
    })
    .bind(&GLOBAL_CONFIG.listen)
    .unwrap()
    .run();

    let join = task::spawn(server);

    if let Some(master) = master {
        task::spawn(try_dispatch_address(master.clone()));
        task::spawn(try_dispatch_analysing(db.clone(), master.clone()));
        task::spawn(connect_workers(master));
    }

    join.await.unwrap().unwrap();

    // scanner.join().await;
}

async fn connect_workers(master: MasterService) {
    let mut workers = GLOBAL_CONFIG.workers.clone().unwrap_or(Vec::new());
    if let nscn::NodeRole::Standalone = GLOBAL_CONFIG.role {
        workers.push(GLOBAL_CONFIG.listen.to_owned());
    }

    loop {
        log::info!("Connecting to {} workers", workers.len());
        let count = master.update_workers(workers.clone()).await;
        if count == workers.len() {
            log::info!("All workers is active.");
            break;
        }
        log::warn!("{} workers not available, retry in 5s.", workers.len() - count);
        sleep(Duration::from_secs(1)).await;
    }
}

async fn try_dispatch_address(service: MasterService) {
    let dispatcher = service.scanner().scheduler().dispathcer();
    if !service.config().scanner.task.fetch {
        return;
    }
    log::info!("Start dispatching http scan address");
    if service.config().scanner.task.clear_old_tasks {
        if let Err(err) = dispatcher.clear_tasks().await {
            log::error!("Failed to reset task queue: {}", err.msg);
        }
    }
    for url in &service.config().scanner.task.addr_src {
        let list = loop {
            match service.fetch_address_list(&url).await {
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
            if let Err(err) = dispatcher.enqueue_task(&ip_cidr).await {
                log::error!("Failed to enqueue http scan task: {}", err.msg);
            }
        }
        log::info!("Enqueue {} address", count);
    }
}

async fn try_dispatch_analysing(db: Database, scanner: MasterService) {
    let dispatcher = scanner.analyser().dispathcer();
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
        dispatcher.enqueue_task(addr).await.unwrap();
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
