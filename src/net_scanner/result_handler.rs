use std::collections::HashMap;

use chrono::Utc;
use mongodb::{Database, bson, options::UpdateOptions};
use serde::{Serialize, Deserialize};

use crate::config::{GLOBAL_CONFIG, ResultSavingOption};
use crate::error::*;

use super::{http_scanner::HttpResponseData, https_scanner::HttpsResponse, tcp_scanner::scanner::TCPScanResult};

#[derive(Serialize, Deserialize)]
pub struct NetScanRecord {
    pub addr: String,
    pub last_update: bson::DateTime,
    pub scan: NetScanResult,
}

#[derive(Serialize, Deserialize)]
#[serde(tag="result", content="data")]
pub enum ScanResult<T> {
    Ok(T),
    Err(String),
}

impl<T: Serialize> From<Result<T, SimpleError>> for ScanResult<T> {
    fn from(result: Result<T, SimpleError>) -> Self {
        match result {
            Ok(data) => Self::Ok(data),
            Err(err) => Self::Err(err.msg),
        }
    }
}



#[derive(Serialize, Deserialize)]
pub struct ScanTaskInfo<T> {
    pub proxy: String,
    pub time: bson::DateTime,
    #[serde(flatten)]
    pub result: ScanResult<T>,
}

impl<T> ScanTaskInfo<T> {
    fn new(result: ScanResult<T>) -> Self {
        Self {
            proxy: "".to_owned(),
            time: Utc::now().into(),
            result,
        }
    }
    fn with_proxy(proxy: &str, result: ScanResult<T>) -> Self {
        Self {
            proxy: proxy.to_owned(),
            time: Utc::now().into(),
            result,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct NetScanResult {
    pub http: Option<NetScanResultSet<HttpResponseData>>,
    pub https: Option<NetScanResultSet<HttpsResponse>>,
    pub tcp: Option<HashMap<u16, TCPScanResult>>,
}

#[derive(Serialize, Deserialize)]
pub struct NetScanResultSet<T> {
    pub success: i32,
    pub results: Vec<ScanTaskInfo<T>>,
}

#[derive(Clone)]
pub struct ResultHandler {
    pub(super) db: Database,
}

impl ResultHandler {
    pub async fn save<T: Serialize>(&self, key: &str, ip_addr: &str, proxy: &str, result: ScanResult<T>) {
        self.try_save(key, ip_addr, proxy, result).await.log_error_consume("result-saving");
    }
    async fn try_save<T: Serialize>(&self, key: &str, ip_addr: &str, proxy: &str, result: ScanResult<T>) -> Result<(), SimpleError> {
        let collection = match &GLOBAL_CONFIG.scanner.save {
            ResultSavingOption::SingleCollection(collection) => self.db.collection(&collection),
            _ => panic!("Not implement"),
        };
        let result_key = format!("scan.{}.results", key);
        let success_key = format!("scan.{}.success", key);
        let success: i32 = match result {
            ScanResult::Ok(_) => 1,
            ScanResult::Err(_) => 0,
        };
        let info = ScanTaskInfo {
            proxy: proxy.to_owned(),
            time: Utc::now().into(),
            result,
        };

        let doc = bson::doc! {
            "$set": {
                "addr": ip_addr,
                "last_update": bson::to_bson(&bson::DateTime::from(Utc::now()))?,
            },
            "$inc": {
                success_key: success,
            },
            "$push": {
                result_key: bson::to_bson(&info)?,
            }
        };
        let query = bson::doc! {
            "addr": ip_addr,
        };
        let mut opts = UpdateOptions::default();
        opts.upsert = Some(true);
        collection.update_one(query, doc, opts).await?;

        Ok(())
    }
}