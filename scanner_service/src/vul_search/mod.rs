use std::collections::HashMap;

use mongodb::Database;
use serde::{Serialize, Deserialize};

use self::exploitdb::ExploitDBSearch;

use crate::{ServiceAnalyseResult, config::GLOBAL_CONFIG, error::SimpleError};

mod exploitdb;


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