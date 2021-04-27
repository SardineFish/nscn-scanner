use std::collections::HashMap;

use self::exploitdb::ExploitDBSearch;

use crate::{ServiceAnalyseResult, config::GLOBAL_CONFIG};

mod exploitdb;

#[derive(Clone)]
pub struct VulnerabilitiesSearch {

}

impl VulnerabilitiesSearch {
    pub fn new() -> Self {
        Self {}
    }
    pub fn exploitdb(&self) -> ExploitDBSearch
    {
        ExploitDBSearch::new(GLOBAL_CONFIG.analyser.vuln_search.exploitdb.to_owned())
    }
    pub async fn search_all(&self, services: &mut HashMap<String, ServiceAnalyseResult>) {
        for (_, service) in services {
            match self.exploitdb().search(&service.name, &service.version).await {
                Ok(result) => service.vulns = result,
                Err(err)=> log::error!("Failed to search EDB for {}@{}: {}", service.name, service.version, err.msg),
            }
        }
    }
}