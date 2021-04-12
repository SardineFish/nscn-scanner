use serde::{Deserialize};
use std::{collections::HashMap, fs, sync::Arc};

use regex::Regex;
use crate::{error::*, net_scanner::{result_handler::{NetScanResultSet, ScanResult}, tcp_scanner::ftp::FTPScanResult}};
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

#[derive(Clone)]
pub struct FTPServiceAnalyser {
    rules: Arc<Vec<UniversalServiceRuleParsed>>,
}

impl FTPServiceAnalyser {
    pub fn from_json(json_file: &str) -> Result<Self, SimpleError> {
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
            rules: Arc::new(rule_list)
        })
    }
    pub fn analyse(&self, result_set: &NetScanResultSet<FTPScanResult>) -> HashMap<String, String> {
        let mut result = HashMap::new();
        if result_set.success <= 0 {
            return result;
        }

        let mut _banner = "";
        for scan_result in &result_set.results {
            let scan_result = match &scan_result.result {
                ScanResult::Ok(result) => result,
                _ => continue,
            };
            _banner = &scan_result.handshake_text;
            for rule in self.rules.as_ref() {
                match rule.try_match(&scan_result.handshake_text) {
                    Some(version) => { result.insert(rule.name.to_owned(), version.to_owned()); },
                    _ => (),
                }
            }
        }

        // if result.len() <= 0 {
        //     log::warn!("Unknown FTP banner: {}", banner);
        // }

        result
    }
}