use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use chrono::Utc;
use mongodb::{Database, bson::{self, Document, doc}, options::{FindOneAndUpdateOptions}};
use serde::{Serialize, Deserialize, de::DeserializeOwned};

use crate::{ServiceAnalyseResult, config::{GLOBAL_CONFIG}};
use crate::error::*;

use super::{http_scanner::HttpResponseData, https_scanner::HttpsResponse, tcp_scanner::scanner::TCPScanResult};

#[derive(Serialize, Deserialize, Debug)]
pub struct NetScanRecord {
    pub addr_int: i64,
    pub addr: String,
    pub last_update: bson::DateTime,
    pub scan: NetScanResult,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag="result", content="data")]
pub enum ScanResult<T> {
    Ok(T),
    Err(String),
}

impl<T> ScanResult<T> {
    pub fn ok(self) -> Option<T> {
        match self {
            ScanResult::Ok(result) => Some(result),
            _ => None
        }
    }
    pub fn as_ref(&self) -> ScanResult<&T> {
        match self {
            ScanResult::Ok(result) => ScanResult::Ok(result),
            ScanResult::Err(err) => ScanResult::Err(err.to_owned()),
        }
    }
    pub fn success(&self) -> bool {
        match self {
            ScanResult::Ok(_) => true,
            _ => false
        }
    }
}

impl<T: Serialize> From<Result<T, SimpleError>> for ScanResult<T> {
    fn from(result: Result<T, SimpleError>) -> Self {
        match result {
            Ok(data) => Self::Ok(data),
            Err(err) => Self::Err(err.msg),
        }
    }
}



#[derive(Serialize, Deserialize, Debug)]
pub struct ScanTaskInfo<T> {
    pub addr_int: i64,
    pub addr: String,
    pub port: i32,
    pub scanner: String,
    pub proxy: Option<String>,
    pub time: bson::DateTime,
    #[serde(flatten)]
    pub result: ScanResult<T>,
}

impl ScanTaskInfo<()> {
    pub fn new(addr: String, port: u16) -> ScanTaskInfoBuilder {
        ScanTaskInfoBuilder::new(addr, port)
    }
}

pub struct ScanTaskInfoBuilder {
    pub addr_int: i64,
    pub addr: String,
    pub port: u16,
    pub scanner: &'static str,
    pub proxy: Option<String>,
    pub time: bson::DateTime,
}

impl ScanTaskInfoBuilder {
    fn new(addr: String, port: u16) -> Self {
        Self {
            addr_int: u32::from(std::net::Ipv4Addr::from_str(&addr)
                .unwrap_or(Ipv4Addr::UNSPECIFIED)) as i64,
            addr,
            port,
            proxy: None,
            time: Utc::now().into(),
            scanner: "",
        }
    }
    pub fn scanner(self, scanner: &'static str) -> Self {
        Self {
            scanner,
            ..self
        }
    }
    pub fn proxy(mut self, proxy_addr: String) -> Self {
        self.proxy = Some(proxy_addr);
        self
    }
    pub fn success<T>(self, result: T) -> ScanTaskInfo<T> {
        ScanTaskInfo::<T> {
            result: ScanResult::Ok(result),
            addr: self.addr,
            addr_int: self.addr_int,
            port: self.port as i32,
            proxy: self.proxy,
            scanner: self.scanner.to_owned(),
            time: self.time,
        }
    }
    pub fn err<T, E: Into<SimpleError>>(self, err: E) -> ScanTaskInfo<T> {
        ScanTaskInfo::<T> {
            result: ScanResult::Err(<E as Into<SimpleError>>::into(err).msg),
            addr: self.addr,
            addr_int: self.addr_int,
            port: self.port as i32,
            proxy: self.proxy,
            scanner: self.scanner.to_owned(),
            time: self.time,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NetScanResult {
    pub http: Option<NetScanResultSet<HttpResponseData>>,
    pub https: Option<NetScanResultSet<HttpsResponse>>,
    pub tcp: Option<HashMap<String, TCPScanResult>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NetScanResultSet<T> {
    pub success: i32,
    pub results: Vec<ScanTaskInfo<T>>,
}

#[derive(Clone)]
pub struct ResultHandler {
    pub(super) db: Database,
}

impl ResultHandler {
    pub async fn save_scan_results<T: Serialize + DeserializeOwned + Unpin + fmt::Debug>(&self, task_result: ScanTaskInfo<T>) {
        let future = self.try_save(task_result);
        match tokio::time::timeout(std::time::Duration::from_secs(300), async move {
            future.await.log_error_consume("result-saving");
        }).await {
            Ok(_) => (),
            Err(_) => log::error!("Result saving timeout"),
        }
    }
    pub async fn save_analyse_results(&self, ip_addr: &str, service_key: &str, services: HashMap<String, ServiceAnalyseResult>) -> Result<(), SimpleError> {
        let collecion = self.db.collection::<Document>(&GLOBAL_CONFIG.analyser.save);

        let addr_int: u32 = std::net::Ipv4Addr::from_str(ip_addr)?.into();
        let query = doc! {
            "addr_int": addr_int,
        };
        let update = doc! {
            "$set": {
                service_key: bson::to_bson(&services)?,
                "last_update": bson::to_bson(&bson::DateTime::from(Utc::now()))?,
            },
            "$setOnInsert": match service_key {
                "web" => doc!{
                    "addr": ip_addr,
                    "ftp": {},
                    "ssh": {},
                    "addr_int": addr_int,
                },
                "ftp" => doc!{
                    "addr": ip_addr,
                    "web": {},
                    "ssh": {},
                    "addr_int": addr_int,
                },
                "ssh" => doc!{
                    "addr": ip_addr,
                    "ftp": {},
                    "web": {},
                    "addr_int": addr_int,
                },
                _ => doc!{
                    "addr": ip_addr,
                    "ftp": {},
                    "ssh": {},
                    "web": {},
                    "addr_int": addr_int,
                },
            }
        };

        let mut opts = FindOneAndUpdateOptions::default();
        opts.upsert = Some(true);

        collecion.find_one_and_update(query, update, opts).await?;

        Ok(())

    }
    async fn try_save<T>(&self, task_result: ScanTaskInfo<T>) -> Result<(), SimpleError> where T: Serialize + DeserializeOwned + Unpin + fmt::Debug {
        let collection = self.db.collection::<ScanTaskInfo<T>>(&GLOBAL_CONFIG.scanner.save.collection);
        collection.insert_one(task_result, None).await?;

        Ok(())
    }
}