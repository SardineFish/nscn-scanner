use self::exploitdb::ExploitDBSearch;

use crate::config::GLOBAL_CONFIG;

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
}