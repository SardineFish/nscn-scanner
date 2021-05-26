use std::{collections::HashMap, sync::Arc};

use mongodb::Database;
use serde::{Serialize, Deserialize};
use tokio::sync::Mutex;

use self::exploitdb::ExploitDBSearch;

use crate::{ServiceAnalyseResult, config::GLOBAL_CONFIG, error::SimpleError};

mod exploitdb;

use lazy_static::lazy_static;

#[derive(Default)]
pub(super) struct CacheHitRateStats {
    pub hit_count: usize,
    pub access_count: usize,
}

lazy_static! {
    pub(super) static ref HIT_RATE_STATS: Arc<Mutex<CacheHitRateStats>> = {
        let stats = Arc::new(Mutex::new(CacheHitRateStats::default()));
        let stats_clone = stats.clone();
        tokio::task::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                {
                    let guard = stats_clone.lock().await;
                    log::info!("Access: {}, Hit: {}, HitRate: {}", 
                        guard.access_count, 
                        guard.hit_count, 
                        guard.hit_count as f64 / guard.access_count as f64);
                }
            }
        });
        stats
    };
}


pub struct VulnerabilitiesSearch {
    edb_search: ExploitDBSearch,
}

impl VulnerabilitiesSearch {
    pub async fn new(redis: redis::Client, db: Database) -> Result<Self, SimpleError> {
        Ok(Self {
            edb_search: ExploitDBSearch::new(
                GLOBAL_CONFIG.analyser.vuln_search.exploitdb.to_owned(), 
                db, 
                redis
            ).await?,
        })
    }
    pub fn exploitdb(&mut self) -> &mut ExploitDBSearch
    {
        &mut self.edb_search
    }
    pub async fn search_all(&mut self, services: &mut HashMap<String, ServiceAnalyseResult>) {
        for (_, service) in services {
            match self.exploitdb().search(&service.name, &service.version).await {
                Ok(result) => service.vulns = result,
                Err(err)=> log::error!("Failed to search EDB for {}@{}: {}", service.name, service.version, err.msg),
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VulnInfo {
    pub id: String,
    pub title: String,
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceVulns {
    pub name: String,
    pub version: String,
    pub vulns: Vec<VulnInfo>,
}