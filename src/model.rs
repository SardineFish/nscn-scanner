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

#[derive(Serialize, Deserialize)]
pub struct ScanStats {
    pub total_scan: usize,
    pub scan_per_seconds: usize,
    pub available_servers: usize,
    pub total_vulnerabilities: usize,
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

    pub async fn get_by_ip_range(&self, range: Range<u32>, skip: usize, count: usize, online_only: bool) -> Result<Vec<ScanAnalyseResult>, ServiceError> {
        let mut pipeline = Vec::<Document>::new();
        pipeline.push(doc! {
            "$match": {
                "addr_int": {
                    "$gte": range.start as i64,
                    "$lt": range.end as i64,
                }
            }
        });
        if online_only {
            pipeline.push(doc! {
                "$match": {
                    "any_available": true,
                }
            })
        }
        self.query_union_scan_with_analyse(pipeline, skip, count).await
    }

    pub async fn get_by_scanner(&self, scanner: &str,skip: usize, count: usize) -> Result<Vec<ScanAnalyseResult>, ServiceError> {
        let mut pipeline = Vec::new();
        pipeline.push(doc! {
            "$match": {
                "any_available": true,
                format!("scan.{}.success", scanner): {"$gt": 0}
            }
        });
        self.query_union_scan_with_analyse(pipeline, skip, count).await
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
        self.query_union_analyse_with_scan(pipeline, skip, count).await
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
        self.query_union_analyse_with_scan(pipeline, skip, count).await
    }

    async fn query_union_scan_with_analyse(&self, mut pipeline: Vec<Document>, skip: usize, count: usize) -> Result<Vec<ScanAnalyseResult>, ServiceError> {
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
                "localField": "scan.addr_int",
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

    async fn query_union_analyse_with_scan(&self, mut pipeline: Vec<Document>, skip: usize, count: usize) -> Result<Vec<ScanAnalyseResult>, ServiceError> {
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
                "localField": "analyse.addr_int",
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

        let results: Vec<ScanAnalyseResult> = self.db.collection::<Document>("analyse").aggregate(pipeline, None)
            .await?
            .filter_map(|doc|async move{ doc.ok().and_then(|doc|bson::from_document::<ScanAnalyseResult>(doc).ok())})
            .collect()
            .await;

        Ok(results)
    }


    pub async fn get_stats(&self) -> Result<ScanStats, ServiceError> 
    {
        let total_scan = self.db.collection::<Document>("scan").estimated_document_count(None).await?;
        let total_available = self.db.collection::<Document>("analyse").estimated_document_count(None).await?;
        let mut pipeline = Vec::new();
        pipeline.push(doc! {
            "$replaceRoot": {
                "newRoot": {
                    "vulns": {
                        "$sum": {
                            "$map": {
                                "input": {
                                    "$concatArrays": [
                                        { "$objectToArray": "$web" },
                                        { "$objectToArray": "$ssh" },
                                        { "$objectToArray": "$ftp" },
                                    ],
                                },
                                "as": "service",
                                "in": {
                                    "$sum": { "$size": "$$service.v.vulns" }
                                }

                            }
                        }

                    },
                }
            }
        });
        pipeline.push(doc! {
            "$group": {
                "_id": null,
                "total_vulns": { "$sum": "$vulns"}
            }
        });
        let doc = self.db.collection::<Document>("analyse").aggregate(pipeline, None)
            .await?
            .next()
            .await
            .ok_or(ServiceError::InternalErr("Failed to get total vulns".to_owned()))??;
        let total_vulns = doc.get_i32("total_vulns")? as usize;

        Ok(ScanStats {
            total_scan: total_scan as usize,
            available_servers: total_available as usize,
            total_vulnerabilities: total_vulns as usize,
            scan_per_seconds: 0
        })
    }
}