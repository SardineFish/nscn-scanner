use std::ops::Range;

use serde::{Deserialize, Serialize};
use mongodb::{Database, bson::{self, doc,  Document}};
use nscn::{NetScanRecord, ServiceRecord};
use futures::StreamExt;

use crate::error::ServiceError;

#[derive(Clone)]
pub struct Model {
    db: Database,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ScanAnalyseResult {
    pub scan: NetScanRecord,
    pub analyse: Option<ServiceRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BriefResult {

}

impl Model {
    pub fn new(db: Database) -> Self {
        Self {
            db
        }
    }

    pub async fn get_by_ip(&self, addr_int: u32) -> Result<ScanAnalyseResult, ServiceError>
    {
        let query = doc! {
            "addr_int": addr_int as i64
        };
        let scan_result = self.db.collection::<NetScanRecord>("scan").find_one(query.clone(), None).await?
            .ok_or(ServiceError::DataNotFound)?;

        let analyse_resut = self.db.collection::<ServiceRecord>("analyse").find_one(query, None).await?;

        Ok(ScanAnalyseResult {
            scan: scan_result,
            analyse: analyse_resut
        })
    }

    pub async fn get_by_ip_range(&self, range: Range<u32>, skip: usize, count: usize) -> Result<Vec<ScanAnalyseResult>, ServiceError> {
        let mut pipeline = Vec::<Document>::new();
        pipeline.push(doc! {
            "$match": {
                "addr_int": {
                    "$gte": range.start,
                    "$lt": range.end,
                }
            }
        });
        pipeline.push(doc! {
            "$skip": skip as i64,
        });
        pipeline.push(doc! {
            "$limit": count as i64,
        });
        pipeline.push(doc! {
            "$project": {
                "scan": "$$ROOT",
            }
        });
        pipeline.push(doc! {
            "$lookup": {
                "from": "analyse",
                "localField": "addr_int",
                "foreignField": "addr_int",
                "as": "analyse",
            }
        });
        let results: Vec<ScanAnalyseResult> = self.db.collection::<Document>("scan").aggregate(pipeline, None)
            .await?
            .filter_map(|doc|async move{ doc.ok().and_then(|doc|bson::from_document::<ScanAnalyseResult>(doc).ok())})
            .collect()
            .await;
        Ok(results)
    }

    pub async fn get_all_available(&self, skip: usize, count: usize) -> Result<Vec<ScanAnalyseResult>, ServiceError> {
        let mut pipeline = Vec::<Document>::new();

        pipeline.push(doc! {
            "$match": {
                "$or": [
                    {
                        "scan.http.success": {"$gt": 0},
                    },
                    {
                        "scan.https.success": {"$gt": 0},
                    },
                    {
                        "scan.tcp.21.ftp.success": {"$gt": 0},
                    },
                    {
                        "scan.tcp.22.ssh.success": {"$gt": 0},
                    }
                ]
            }
        });
        pipeline.push(doc! {
            "$skip": skip as i64,
        });
        pipeline.push(doc! {
            "$limit": count as i64,
        });
        pipeline.push(doc! {
            "$project": {
                "scan": "$$ROOT",
            }
        });
        pipeline.push(doc! {
            "$lookup": {
                "from": "analyse",
                "localField": "addr_int",
                "foreignField": "addr_int",
                "as": "analyse",
            }
        });
        pipeline.push(doc! {
            "$project": {
                "scan": "$scan",
                "analyse": {
                    "$arrayElemAt": ["$analyse", 0]
                }
            }
        });

        let results: Vec<ScanAnalyseResult> = self.db.collection::<Document>("scan").aggregate(pipeline, None)
            .await?
            .filter_map(|doc|async move{ doc.ok().and_then(|doc|bson::from_document::<ScanAnalyseResult>(doc).ok())})
            .collect()
            .await;
        Ok(results)
    }
 
    pub async fn get_by_service_name(&self, service_name: &str, skip: usize, count: usize) -> Result<Vec<ScanAnalyseResult>, ServiceError> {
        let mut pipeline = Vec::<Document>::new();
        let web_key = format!("web.{}", service_name);
        let ftp_key = format!("ftp.{}", service_name);
        let ssh_key = format!("ssh.{}", service_name);
        pipeline.push(doc! {
            "$match": {
                "$or": [
                    {
                        web_key: { "$gt": {} },
                    },
                    {
                        ftp_key: { "$gt": {} },
                    },
                    {
                        ssh_key: { "$gt": {} },
                    }
                    
                ]
            }
        });
        pipeline.push(doc! {
            "$skip": skip as i64,
        });
        pipeline.push(doc! {
            "$limit": count as i64,
        });
        pipeline.push(doc! {
            "$project": {
                "analyse": "$$ROOT",
            }
        });
        pipeline.push(doc! {
            "$lookup": {
                "from": "scan",
                "localField": "addr_int",
                "foreignField": "addr_int",
                "as": "scan",
            }
        });
        pipeline.push(doc! {
            "$project": {
                "analyse": "$analyse",
                "scan": {
                    "$arrayElemAt": ["$scan", 0]
                }
            }
        });

        let results: Vec<ScanAnalyseResult> = self.db.collection::<Document>("scan").aggregate(pipeline, None)
            .await?
            .filter_map(|doc|async move{ doc.ok().and_then(|doc|bson::from_document::<ScanAnalyseResult>(doc).ok())})
            .collect()
            .await;

        Ok(results)
    }

    pub async fn get_by_service_version(&self, service_name: &str, version: &str, skip: usize, count: usize) -> Result<Vec<ScanAnalyseResult>, ServiceError> {
        
        let mut pipeline = Vec::<Document>::new();
        let web_key = format!("web.{}.version", service_name);
        let ftp_key = format!("ftp.{}.version", service_name);
        let ssh_key = format!("ssh.{}.version", service_name);
        pipeline.push(doc! {
            "$match": {
                "$or": [
                    {
                        web_key: version,
                    },
                    {
                        ftp_key: version,
                    },
                    {
                        ssh_key: version,
                    }
                    
                ]
            }
        });
        pipeline.push(doc! {
            "$skip": skip as i64,
        });
        pipeline.push(doc! {
            "$limit": count as i64,
        });
        pipeline.push(doc! {
            "$project": {
                "analyse": "$$ROOT",
            }
        });
        pipeline.push(doc! {
            "$lookup": {
                "from": "scan",
                "localField": "addr_int",
                "foreignField": "addr_int",
                "as": "scan",
            }
        });
        pipeline.push(doc! {
            "$project": {
                "analyse": "$analyse",
                "scan": {
                    "$arrayElemAt": ["$scan", 0]
                }
            }
        });

        let results: Vec<ScanAnalyseResult> = self.db.collection::<Document>("scan").aggregate(pipeline, None)
            .await?
            .filter_map(|doc|async move{ doc.ok().and_then(|doc|bson::from_document::<ScanAnalyseResult>(doc).ok())})
            .collect()
            .await;

        Ok(results)
    }
}