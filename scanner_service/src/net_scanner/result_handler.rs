use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;

use chrono::Utc;
use mongodb::options::UpdateOptions;
use mongodb::{Database, bson::{self, Document, doc}, options::{FindOneAndUpdateOptions}};
use serde::{Serialize, Deserialize};

use crate::FTPScanResult;
use crate::SSHScannResult;
use crate::{ServiceAnalyseResult, config::{GLOBAL_CONFIG}};
use crate::error::*;

use super::scanner::TcpScanResult;
use super::{http_scanner::HttpResponseData, https_scanner::HttpsResponse};

#[derive(Serialize, Deserialize, Debug)]
pub struct NetScanRecord {
    pub addr_int: i64,
    pub addr: String,
    pub online: Option<bool>,
    pub results: Vec<ScanTaskData>
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag="scanner")]
pub enum TcpScanResultType {
    #[serde(rename = "http")]
    Http(ScanResult<HttpResponseData>),
    #[serde(rename = "tls")]
    Tls(ScanResult<HttpsResponse>),
    #[serde(rename = "ftp")]
    Ftp(ScanResult<FTPScanResult>),
    #[serde(rename = "ssh")]
    SSH(ScanResult<SSHScannResult>),
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
pub struct ScanTaskData {
    pub port: i32,
    pub proxy: Option<String>,
    pub time: bson::DateTime,
    #[serde(flatten)]
    pub result: TcpScanResultType,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ScanTaskInfo<T> {
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
            port: self.port as i32,
            proxy: self.proxy,
            scanner: self.scanner.to_owned(),
            time: self.time,
        }
    }
    pub fn err<T, E: Into<SimpleError>>(self, err: E) -> ScanTaskInfo<T> {
        ScanTaskInfo::<T> {
            result: ScanResult::Err(<E as Into<SimpleError>>::into(err).msg),
            port: self.port as i32,
            proxy: self.proxy,
            scanner: self.scanner.to_owned(),
            time: self.time,
        }
    }
}

#[derive(Clone)]
pub struct ResultHandler {
    pub(super) db: Database,
}

pub trait SerializeScanResult {
    fn to_bson(&self) -> Result<bson::Bson, bson::ser::Error>;
    fn success(&self) -> bool;
}

impl<R: Serialize> SerializeScanResult for ScanTaskInfo<R> {
    fn to_bson(&self) -> Result<bson::Bson, bson::ser::Error> {
        bson::to_bson(&self)
    }
    fn success(&self) -> bool {
        match self.result {
            ScanResult::Ok(_) => true,
            _ => false,
        }
    }
}

impl ResultHandler {
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
    pub async fn save_scan_results_batch(&self, addr: String, results: Vec<TcpScanResult>) -> Result<(), SimpleError> {
        let collection  = self.db.collection::<Document>(&GLOBAL_CONFIG.scanner.save.collection);
        let addr_int: u32 = std::net::Ipv4Addr::from_str(&addr)?.into();
        let query = doc! {
            "addr_int": addr_int as i64
        };
        let is_online = results.iter().any(|r|r.success());
        let results = results.into_iter()
            .filter_map(|r| r.to_bson().log_error("serialize-result").ok())
            .collect::<Vec::<_>>();
        let mut update = doc! {
            "$setOnInsert": {
                "addr": bson::to_bson(&addr)?,
                "addr_int": addr_int as i64,
            },
            "$push": {
                "results": {
                    "$each": bson::to_bson(&results)?,
                }
            }
        };
        if is_online {
            update.insert("$set", doc! {
                "online": true,
            });
        }
        let opts = UpdateOptions::builder()
            .upsert(Some(true))
            .build();
        collection.update_one(query, update, opts).await?;
        Ok(())
    }
}