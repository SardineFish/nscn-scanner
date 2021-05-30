use std::collections::HashMap;
use std::str::FromStr;

use chrono::Utc;
use mongodb::{Database, bson::{self, Document, doc}, options::{FindOneAndUpdateOptions, UpdateOptions}};
use serde::{Serialize, Deserialize};

use crate::{ServiceAnalyseResult, config::{GLOBAL_CONFIG, ResultSavingOption}};
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
    pub proxy: String,
    pub time: bson::DateTime,
    #[serde(flatten)]
    pub result: ScanResult<T>,
}

impl<T> ScanTaskInfo<T> {
    pub fn new(result: ScanResult<T>) -> Self {
        Self {
            proxy : "".to_owned(),
            time: Utc::now().into(),
            result,
        }
    }
    pub fn with_proxy(proxy: String, result: T) -> Self {
        Self {
            proxy,
            time: Utc::now().into(),
            result: ScanResult::Ok(result),
        }
    }
    pub fn err_with_proxy<E: Into<SimpleError>>(proxy: String, err: E) -> Self {
        Self {
            proxy,
            time: Utc::now().into(),
            result: ScanResult::Err(<E as Into<SimpleError>>::into(err).msg),
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
    pub async fn save_scan_results<T: Serialize>(&self, key: &str, ip_addr: &str, task_result: ScanTaskInfo<T>) {
        let future = self.try_save(key, ip_addr, task_result);
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
    async fn try_save<T: Serialize>(&self, key: &str, ip_addr: &str, task_result: ScanTaskInfo<T>) -> Result<(), SimpleError> {
        let collection = match &GLOBAL_CONFIG.scanner.save {
            ResultSavingOption::SingleCollection(collection) => self.db.collection::<Document>(&collection),
            _ => panic!("Not implement"),
        };
        let result_key = format!("scan.{}.results", key);
        let success_key = format!("scan.{}.success", key);
        let success: i32 = match &task_result.result {
            ScanResult::Ok(_) => 1,
            ScanResult::Err(_) => 0,
        };

        let current_time = bson::DateTime::from(Utc::now());
        let addr_int: u32 = std::net::Ipv4Addr::from_str(ip_addr)?.into();
        let doc = match success {
            1 => bson::doc! {
                "$set": {
                    "addr": ip_addr,
                    "addr_int": addr_int as i64,
                    "last_update": bson::to_bson(&current_time)?,
                    "any_available": true,
                },
                "$inc": {
                    success_key: success,
                },
                "$push": {
                    result_key: bson::to_bson(&task_result)?
                },
            },
            _ => bson::doc! {
                "$set": {
                    "addr": ip_addr,
                    "addr_int": addr_int as i64,
                    "last_update": bson::to_bson(&bson::DateTime::from(Utc::now()))?,
                },
                "$inc": {
                    success_key: success,
                },
                "$push": {
                    result_key: bson::to_bson(&task_result)?
                }
            }
        };
        let query = bson::doc! {
            "addr_int": addr_int as i64,
        };
        let mut opts = UpdateOptions::default();
        opts.upsert = Some(true);
        collection.update_one(query, doc, opts).await?;

        Ok(())
    }
}