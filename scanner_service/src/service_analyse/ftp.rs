use serde::{Deserialize};
use std::{collections::HashMap, fs, sync::Arc};

use regex::Regex;
use crate::{error::*, net_scanner::{result_handler::{NetScanResultSet, ScanResult}, tcp_scanner::ftp::FTPScanResult}, vul_search::VulnerabilitiesSearch};

use super::ServiceAnalyseResult;
#[derive(Deserialize)]
pub struct UniversalServiceRule {
    pattern: String,
    version: Option<usize>,
}
pub struct UniversalServiceRuleParsed {
    pub name: String,
    pattern: Regex,
    version_capture: Option<usize>,
}
impl UniversalServiceRuleParsed {
    pub fn try_parse(name: &str, rule: UniversalServiceRule) -> Result<Self, SimpleError> {
        Ok(Self {
            name: name.to_owned(),
            pattern: Regex::new(&rule.pattern)?,
            version_capture: rule.version
        })
    }
    pub fn try_match<'s>(&self, text: &'s str) -> Option<&'s str> {
        match (self.version_capture, self.pattern.captures(text)) {
            (Some(version_cap), Some(captures)) => Some(captures.get(version_cap).map(|m|m.as_str()).unwrap_or("")),
            (_, Some(_)) => Some(""),
            _ => None,
        }
    }
}

pub struct FTPServiceAnalyser {
    rules: Arc<Vec<UniversalServiceRuleParsed>>,
    vuln_searcher: VulnerabilitiesSearch,
}

impl FTPServiceAnalyser {
    pub fn from_json(json_file: &str, vuln_searcher: VulnerabilitiesSearch) -> Result<Self, SimpleError> {
        let json_text = fs::read_to_string(json_file)?;
        let rules = serde_json::from_str::<HashMap<String, UniversalServiceRule>>(&json_text)?;
        let mut rule_list = Vec::new();
        for (name, rule) in rules {
            match UniversalServiceRuleParsed::try_parse(&name, rule) {
                Ok(rule) => rule_list.push(rule),
                Err(err) => log::warn!("Failed to parse FTP rule {}: {}", name, err.msg),
            }
        }
        Ok(Self {
            rules: Arc::new(rule_list),
            vuln_searcher,
        })
    }
    pub async fn analyse(&self, results: &ScanResult<FTPScanResult>, services: &mut HashMap<String, ServiceAnalyseResult>) {
        let scan_result = match &results {
            ScanResult::Ok(result) => result,
            _ => return,
        };
        let _banner = &scan_result.handshake_text;
        for rule in self.rules.as_ref() {
            match rule.try_match(&scan_result.handshake_text) {
                Some(version) => { 
                    services.insert(
                        rule.name.to_owned(), 
                        ServiceAnalyseResult::new(rule.name.to_owned(), version.to_owned())); 
                },
                _ => (),
            }
        }
    }
    pub async fn analyse_results_set(&mut self, result_set: &NetScanResultSet<FTPScanResult>) -> HashMap<String, ServiceAnalyseResult> {
        let mut result = HashMap::new();
        if result_set.success <= 0 {
            return result;
        }

        let mut _banner = "";
        for scan_result in &result_set.results {
            self.analyse(&scan_result.result, &mut result).await;
        }

        for (_, result) in &mut result {
            match self.vuln_searcher.exploitdb().search(&result.name, &result.version).await {
                Ok(vulns) => result.vulns = vulns,
                Err(err) => log::error!("Failed to search exploitdb: {}", err.msg),
            }
        }

        result
    }
}