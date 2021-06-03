use std::{collections::HashMap, ops::Range};

use serde::{Deserialize, Serialize};
use mongodb::{Database, bson::{self, Bson, Document, doc}, options::{FindOptions, Hint}};
use nscn::{IPGeoData, NetScanRecord, ServiceRecord, VulnInfo, error::SimpleError};
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


#[derive(Serialize, Deserialize)]
pub struct AnalyseGeometryStats {
    pub geo: IPGeoData,
    pub count: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ScanResultBreif {
    pub addr: String,
    pub ports: Vec<i32>,
    pub services: Vec<ServiceAnalyseResultBrif>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServiceAnalyseResultBrif {
    pub name: String,
    pub version: String,
    pub vulns: i32,
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
                    "key": {"addr_int": 1},
                    "name": "addr_int_1",
                    "unique": true,
                },
                {
                    "key": {
                        "online" : 1,
                    },
                    "name": "online",
                },
                {
                    "key": {
                        "results.result": 1,
                        "results.port": 1,
                        "addr": 1,
                    },
                    "name": "result_port",
                },
                {
                    "key": {
                        "results.scanner": 1,
                        "results.result": 1,
                    },
                    "name": "scanner_result",
                },
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
                {
                    "key": {"geo.location": "2dsphere"},
                    "name": "geo_location",
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
                "online": true,
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
        // if online_only {
        //     opts.hint = Some(Hint::Keys(doc! { "online": 1 }));
        // }
        let docs: Vec<AddrOnlyDoc> = self.db.collection::<AddrOnlyDoc>("scan")
            .find(query, opts)
            .await?
            .filter_map(|t| async move { t.ok() })
            .collect()
            .await;

        Ok(docs)
    }

    pub async fn get_details_by_ip(&self, addr_int: u32) -> Result<ScanAnalyseResult, ServiceError> {
        let query = doc! {
            "addr_int": addr_int as i64
        };
        let scan_result = self.db.collection::<NetScanRecord>("scan").find_one(query.clone(), None).await?
            .ok_or(ServiceError::DataNotFound)?;

        let mut pipe = Vec::new();
        pipe.push(doc!{
            "$match": {
                "addr_int": addr_int as i64,
            }
        });
        pipe.push(doc!{
            "$replaceRoot": {
                "newRoot": {
                    "$mergeObjects": ["$$ROOT", {
                        "vulns": {
                            "$reduce": {
                                "input": "$services",
                                "initialValue": [],
                                "in": { "$concatArrays": ["$$value", "$$this.vulns"] }
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

    pub async fn get_by_ip_range(&self, range: Range<u32>, skip: usize, count: usize, online_only: bool) -> Result<Vec<ScanResultBreif>, ServiceError> {
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
                    "online": true,
                }
            })
        }
        self.query_union_analyse_from_scan(pipeline, skip, count).await
    }

    pub async fn get_by_port(&self, port: u16, skip: usize, count: usize) -> Result<Vec<ScanResultBreif>, ServiceError> {
        let mut pipeline = Vec::new();
        pipeline.push(doc! {
            "$match": {
                "results": {
                    "$elemMatch": {
                        "port": port as i32,
                        "result": "Ok"
                    }
                }
            }
        });
        self.query_union_analyse_from_scan(pipeline, skip, count).await
    }

    pub async fn get_by_scanner(&self, scanner: &str,skip: usize, count: usize) -> Result<Vec<ScanResultBreif>, ServiceError> {
        let mut pipeline = Vec::new();
        pipeline.push(doc! {
            "$match": {
                "results": {
                    "$elemMatch": {
                        "scanner": scanner,
                        "result": "Ok"
                    }
                }
            }
        });
        self.query_union_analyse_from_scan(pipeline, skip, count).await
    }
 
    pub async fn get_by_service_name(&self, service_name: &str, skip: usize, count: usize) -> Result<Vec<ScanResultBreif>, ServiceError> {
        let mut pipeline = Vec::<Document>::new();
        pipeline.push(doc! {
            "$match": {
                "services": {
                    "$elemMatch": {
                        "name": service_name,
                    }
                }
            }
        });
        self.query_union_scan_from_analyse(pipeline, skip, count).await
    }

    pub async fn get_by_service_version(&self, service_name: &str, version: &str, skip: usize, count: usize) -> Result<Vec<ScanResultBreif>, ServiceError> {
        
        let mut pipeline = Vec::<Document>::new();
        pipeline.push(doc! {
            "$match": {
                "services": {
                    "$elemMatch": {
                        "name": service_name,
                        "version": version,
                    }
                }
            }
        });
        self.query_union_scan_from_analyse(pipeline, skip, count).await
    }

    pub async fn geo_stats_by_ip_range(&self, range: Range<u32>) -> Result<Vec<AnalyseGeometryStats>, ServiceError> {
        self.geo_count(vec![
            doc! {
                "$match": {
                    "addr_int": {
                        "$gte": range.start as i64,
                        "$lt": range.end as i64,
                    }
                }
            }
        ]).await
    }

    pub async fn geo_stats_by_service_name(&self, service_name: &str) -> Result<Vec<AnalyseGeometryStats>, ServiceError> {
        let web_key = format!("web.{}", service_name);
        let ftp_key = format!("ftp.{}", service_name);
        let ssh_key = format!("ssh.{}", service_name);

        self.geo_count(vec![
            doc!{
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
            }
        ]).await
    }

    pub async fn geo_stats_by_service_version(&self, service_name: &str, version: &str) -> Result<Vec<AnalyseGeometryStats>, ServiceError> {
        let web_key = format!("web.{}.version", service_name);
        let ftp_key = format!("ftp.{}.version", service_name);
        let ssh_key = format!("ssh.{}.version", service_name);

        self.geo_count(vec![
            doc! {
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
            }
        ]).await
    }

    pub async fn geo_stats_by_scanner(&self, scanner: &str) -> Result<Vec<AnalyseGeometryStats>, ServiceError> {
        self.geo_count(vec![
            doc! {
                "$match": {
                    "any_available": true,
                    format!("scan.{}.success", scanner): {"$gt": 0}
                }
            }
        ]).await
    }

    async fn geo_count(&self, mut pipeline: Vec<Document>) -> Result<Vec<AnalyseGeometryStats>, ServiceError> {
        pipeline.push(doc! {
            "$group": {
                "_id": "$geo.location",
                "count": {"$sum": 1},
                "geo": {"$first": "$geo"},
            }
        });
        let result: Vec<AnalyseGeometryStats> = self.db.collection::<Document>("analyse").aggregate(pipeline, None)
            .await?
            .filter_map(|doc| async move {doc.ok().and_then(|doc|bson::from_document::<AnalyseGeometryStats>(doc).ok())})
            .collect()
            .await;

        Ok(result)
    }

    async fn query_union_scan_from_analyse(&self, mut pipeline: Vec<Document>, skip: usize, count: usize) -> Result<Vec<ScanResultBreif>, ServiceError> {
        pipeline.push(doc! {
            "$skip": skip as i64,
        });
        if count > 0 {
            pipeline.push(doc! {
                "$limit": count as i64,
            });
        }
        pipeline.push(doc!{
            "$lookup": {
                "from": "scan",
                "localField": "addr_int",
                "foreignField": "addr_int",
                "as": "scan",
            }
        });
        pipeline.push(doc! {
            "$project": {
                "scan": { "$arrayElemAt": ["$scan", 0] },
                "services": "$services"
            }
        });
        pipeline.push(doc! {
            "$replaceRoot": {
                "newRoot": {
                    "addr": "$scan.addr",
                    "ports": {
                        "$reduce": {
                            "input": {
                                "$map": {
                                    "input": {
                                        "$filter": {
                                            "input": "$scan.results",
                                            "as": "result",
                                            "cond": { "$eq": ["$$result.result", "Ok"] }
                                        }
                                    },
                                    "as": "result",
                                    "in": "$$result.port"
                                }
                            },
                            "initialValue": [],
                            "in": { "$setUnion": ["$$value", ["$$this"]] }
                        }
                    },
                    "services": {
                        "$map": {
                            "input": "$services",
                            "as": "service",
                            "in": {
                                "name": "$$service.name",
                                "version": "$$service.version",
                                "vulns": { "$size": "$$service.vulns" }
                            }
                        }
                    },
                }
            }
        });

        let results: Vec<ScanResultBreif> = self.db.collection::<Document>("analyse").aggregate(pipeline, None)
            .await?
            .filter_map(|doc|async move{ doc.ok().and_then(|doc|bson::from_document::<ScanResultBreif>(doc).ok())})
            .collect()
            .await;
        Ok(results)
    }


    async fn query_union_analyse_from_scan(&self, mut pipeline: Vec<Document>, skip: usize, count: usize) -> Result<Vec<ScanResultBreif>, ServiceError> {
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
                "addr": 1,
                "addr_int": 1,
                "results.port": 1,
                "results.result": 1
            }
        });
        pipeline.push(doc! {
            "$replaceRoot": {
                "newRoot": {
                    "addr": "$addr",
                    "addr_int": "$addr_int",
                    "ports": {
                        "$reduce": {
                            "input": {
                                "$map": {
                                    "input": {
                                        "$filter": {
                                            "input": "$results",
                                            "as": "result",
                                            "cond": { "$eq": ["$$result.result", "Ok"] }
                                        }
                                    },
                                    "as": "result",
                                    "in": "$$result.port"
                                }
                            },
                            "initialValue": [],
                            "in": {"$setUnion": ["$$value", ["$$this"]]}
                        }
                    }
                }
            }
        });
        pipeline.push(doc! {
        "$replaceRoot": {
                "newRoot": {
                    "addr": "$addr",
                    "ports": "$ports",
                    "analyse": {
                        "$cond": {
                            "if": { "$eq": ["$ports", []] },
                            "then": Bson::Null,
                            "else": "$addr_int"
                        }
                    }
                }
            }
        });
        pipeline.push(doc! {
            "$lookup": {
                "from": "analyse",
                "localField": "analyse",
                "foreignField": "addr_int",
                "as": "analyse",
            }
        });
        pipeline.push(doc! {
            "$project": {
                "addr": "$addr",
                "ports": "$ports",
                "analyse": {
                    "$arrayElemAt": ["$analyse", 0],
                }
            }
        });
        pipeline.push(doc! {
            "$replaceRoot": {
                "newRoot": {
                    "addr": "$addr",
                    "ports": "$ports",
                    "services": {
                        "$map": {
                            "input": "$analyse.services",
                            "as": "service",
                            "in": {
                                "name": "$$service.name",
                                "version": "$$service.version",
                                "vulns": { "$size": "$$service.vulns" }
                            }
                        }
                    },
                }
            }
        });

        let results: Vec<ScanResultBreif> = self.db.collection::<Document>("scan").aggregate(pipeline, None)
            .await?
            .filter_map(|doc|async move{ doc.ok().and_then(|doc|bson::from_document::<ScanResultBreif>(doc).ok())})
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
        let total_vulns = self.db.collection::<Document>("analyse").aggregate(pipeline, None)
            .await?
            .next()
            .await
            .and_then(|doc| doc.ok().and_then(|doc| doc.get_i32("total_vulns").ok()))
            .unwrap_or(0);

        Ok(ScanStats {
            total_scan: total_scan as usize,
            available_servers: total_available as usize,
            total_vulnerabilities: total_vulns as usize,
            scan_per_seconds: 0.0
        })
    }
}