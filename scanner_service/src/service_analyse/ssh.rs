use std::{collections::HashMap, fs, sync::Arc};

use super::{ServiceAnalyseResult, ftp::{UniversalServiceRule, UniversalServiceRuleParsed}};

use crate::{error::*, net_scanner::{result_handler::{NetScanResultSet, ScanResult}, tcp_scanner::ssh::SSHScannResult}, vul_search::VulnerabilitiesSearch};

#[derive(Clone)]
pub struct SSHServiceAnalyser {
    rules: Arc<Vec<UniversalServiceRuleParsed>>,
    vuln_searcher: VulnerabilitiesSearch,
}

impl SSHServiceAnalyser {
    pub fn from_json(json_file: &str) ->Result<Self, SimpleError> {
        let mut rules_list = Vec::new();
        let json_text = fs::read_to_string(json_file)?;
        let rules = serde_json::from_str::<HashMap<String, UniversalServiceRule>>(&json_text)?;
        for (name, rule) in rules {
            match UniversalServiceRuleParsed::try_parse(&name, rule) {
                Ok(rule) => rules_list.push(rule),
                Err(err) => log::error!("Failed to parse SSH rule {}: {}", name, err.msg),
            }
        }

        Ok(Self{
            rules: Arc::new(rules_list),
            vuln_searcher: VulnerabilitiesSearch::new(),
        })
    }

    pub async fn analyse(&self, result_set: &NetScanResultSet<SSHScannResult>) -> HashMap<String, ServiceAnalyseResult> {
        let mut services = HashMap::new();
        if result_set.success <= 0 {
            return services;
        }

        for scan_result in &result_set.results {
            let result = match &scan_result.result {
                ScanResult::Err(_) => continue,
                ScanResult::Ok(result) => result,
            };
            for rule in self.rules.as_ref() {
                match rule.try_match(&result.protocol.software) {
                    Some(version) => { 
                        services.insert(
                            rule.name.to_owned(), 
                            ServiceAnalyseResult::new(rule.name.to_owned(), version.to_owned())); 
                    },
                    _ => (),
                }
                match rule.try_match(&result.protocol.comments) {
                    Some(version) => { 
                        services.insert(
                            rule.name.to_owned(), 
                            ServiceAnalyseResult::new(rule.name.to_owned(), version.to_owned())); 
                        },
                    _ => (),
                }
            }
        }

        for (_, result) in &mut services {
            match self.vuln_searcher.exploitdb().search(&result.name, &result.version).await {
                Ok(vulns) => result.vulns = vulns,
                Err(err) => log::error!("Failed to search exploitdb: {}", err.msg),
            }
        }

        services
    }
}