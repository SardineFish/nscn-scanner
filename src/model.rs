use std::{collections::HashMap, ops::Range};

use serde::{Deserialize, Serialize};
use mongodb::{Database, bson::{self, doc,  Document}, options::{FindOptions, Hint}};
use nscn::{NetScanRecord, ServiceRecord, VulnInfo, error::SimpleError};
use futures::StreamExt;

use crate::error::ServiceError;

#[derive(Clone)]
pub struct Model {
    db: Database,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AddrOnlyDoc {
    pub addr: String,
    pub addr_int: i64,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ScanAnalyseResult {
    pub scan: NetScanRecord,
    pub analyse: Option<ServiceRecord>,
    pub vulns: Option<HashMap<String, VulnInfo>>,
}

#[derive(Serialize, Deserialize)]
pub struct ScanStats {
    pub total_scan: usize,
    pub scan_per_seconds: f64,
    pub available_servers: usize,
    pub total_vulnerabilities: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceDetails {
    pub name: String,
    pub version: String,
    pub vulns: Vec<VulnInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalyseVulnDetails {
    #[serde(flatten)]
    pub analyse: Option<ServiceRecord>,
    pub vulns: Option<HashMap<String, VulnInfo>>,
}


impl Model {
    pub fn new(db: Database) -> Self {
        Self {
            db
        }
    }

    pub async fn init(&self) -> Result<(), SimpleError> {
        self.db.run_command(doc! {
            "createIndexes": "scan",
            "indexes": [
                {
                    "key": {"addr": 1},
                    "name": "addr_1",
                    "unique": true,
                },
                {
                    "key": {"addr_int": 1},
                    "name": "addr_int_1",
                    "unique": true,
                },
                {
                    "key": {"any_available" : 1},
                    "name": "any_available_1",
                }
            ]
        }, None).await?;

        self.db.run_command(doc! {
            "createIndexes": "analyse",
            "indexes": [
                {
                    "key": {"addr": 1},
                    "name": "addr_1",
                    "unique": true,
                },
                {
                    "key": {"addr_int": 1},
                    "name": "addr_int_1",
                    "unique": true,
                },
            ]
        }, None).await?;

        self.db.run_command(doc! {
            "createIndexes": "vulns",
            "indexes": [
                {
                    "key": {"id": 1},
                    "name": "id_1",
                    "unique": true,
                },
            ]
        }, None).await?;


        Ok(())
    }


    pub async fn get_scaned_addr(&self, range: Range<u32>, skip: usize, count: usize, online_only: bool) -> Result<Vec<AddrOnlyDoc>, ServiceError> {
        let query = match online_only {
            true => doc! {
                "addr_int": {
                    "$gte": range.start as i64,
                    "$lt": range.end as i64,
                },
                "any_available": true,
            },
            false => doc! {
                "addr_int": {
                    "$gte": range.start as i64,
                    "$lt": range.end as i64,
                }
            }
        };
        let projection = doc! {
            "addr": 1,
            "addr_int": 1,
        };

        let mut opts = FindOptions::default();
        opts.skip = Some(skip as i64);
        if count > 0 {
            opts.limit = Some(count as i64);
        }
        opts.projection = Some(projection);
        if online_only {
            opts.hint = Some(Hint::Keys(doc! { "any_available": 1 }));
        }
        let docs: Vec<AddrOnlyDoc> = self.db.collection::<AddrOnlyDoc>("scan")
            .find(query, opts)
            .await?
            .filter_map(|t| async move { t.ok() })
            .collect()
            .await;

        Ok(docs)
    }

    pub async fn get_details_by_ip(&self, addr_int: u32) -> Result<ScanAnalyseResult, ServiceError>
    {
        let query = doc! {
            "addr_int": addr_int as i64
        };
        let scan_result = self.db.collection::<NetScanRecord>("scan").find_one(query.clone(), None).await?
            .ok_or(ServiceError::DataNotFound)?;

        let mut pipe = Vec::new();
        pipe.push(doc!{
            "$match": {
                "addr": "58.49.29.195",
            }
        });
        pipe.push(doc!{
            "$replaceRoot": {
                "newRoot": {
                    "$mergeObjects": ["$$ROOT", {
                        "vulns": {
                            "$reduce": {
                                "input": {
                                    "$map": {
                                        "input": {
                                            "$concatArrays": [
                                                { "$objectToArray": "$web" },
                                                { "$objectToArray": "$ssh" },
                                                { "$objectToArray": "$ftp" },
                                            ],
                                        },
                                        "as": "service",
                                        "in": "$$service.v.vulns"
                                    }
                                },
                                "initialValue": [],
                                "in": { "$concatArrays": ["$$value", "$$this"] }
                            }
                        }
                    }]
                }
            }
        });
        pipe.push(doc!{
            "$lookup": {
                "from": "vulns",
                "foreignField": "id",
                "localField": "vulns",
                "as": "vulns",
            }
        });
        pipe.push(doc!{
            "$replaceRoot": {
                "newRoot": {
                    "$mergeObjects": ["$$ROOT", {
                        "vulns": {
                            "$arrayToObject": {
                                "$map": {
                                    "input": "$vulns",
                                    "as": "vuln",
                                    "in": {
                                        "k": "$$vuln.id",
                                        "v": "$$vuln"
                                    }
                                }
                            }
                        }
                    }]
                }
            }
        });
        let doc = self.db.collection::<Document>("analyse")
            .aggregate(pipe, None)
            .await?
            .next()
            .await;
        if let Some(Ok(doc)) = doc {
            let analyse_result: AnalyseVulnDetails = bson::from_document(doc)?;
            Ok(ScanAnalyseResult {
                scan: scan_result,
                analyse: analyse_result.analyse,
                vulns: analyse_result.vulns,
            })
        } else {
            Ok(ScanAnalyseResult {
                scan: scan_result,
                analyse: None,
                vulns: None,
            })
        }
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
        if count > 0 {
            pipeline.push(doc! {
                "$limit": count as i64,
            });
        }
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
            scan_per_seconds: 0.0
        })
    }
}