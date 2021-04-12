use std::{collections::HashMap, fs, sync::Arc};

use super::ftp::{UniversalServiceRule, UniversalServiceRuleParsed};

use crate::{error::*, net_scanner::{result_handler::{NetScanResultSet, ScanResult}, tcp_scanner::ssh::SSHScannResult}};

#[derive(Clone)]
pub struct SSHServiceAnalyser {
    rules: Arc<Vec<UniversalServiceRuleParsed>>,
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
            rules: Arc::new(rules_list)
        })
    }

    pub fn analyse(&self, result_set: &NetScanResultSet<SSHScannResult>) -> Option<HashMap<String, String>> {
        if result_set.success <= 0 {
            return None;
        }
        let mut services = HashMap::new();

        for scan_result in &result_set.results {
            let result = match &scan_result.result {
                ScanResult::Err(_) => continue,
                ScanResult::Ok(result) => result,
            };
            for rule in self.rules.as_ref() {
                match rule.try_match(&result.protocol.software) {
                    Some(version) => { services.insert(rule.name.to_owned(), version.to_owned()); },
                    _ => (),
                }
                match rule.try_match(&result.protocol.comments) {
                    Some(version) => { services.insert(rule.name.to_owned(), version.to_owned()); },
                    _ => (),
                }
            }
        }

        Some(services)
    }
}