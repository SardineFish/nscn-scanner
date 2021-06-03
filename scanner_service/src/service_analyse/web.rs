use std::{collections::HashMap, sync::Arc};

use regex::Regex;
use serde::{Deserialize};
use crate::{ScanTaskInfo, net_scanner::{http_scanner::HttpResponseData, result_handler::{ScanResult}}, vul_search::VulnerabilitiesSearch};
use crate::error::*;

use super::ServiceAnalyseResult;

#[derive(Deserialize)]
struct WebServicePattern {
    regexp: Option<String>,
    text: Option<String>,
    version: Option<String>,
    offset: Option<usize>,
    certainty: Option<i32>,
    url: Option<String>,
}

#[derive(Deserialize)]
struct WebServiceRule {
    name: String,
    version: Option<String>,
    matches: Vec<WebServicePattern>,
    condition: Option<String>,
}


#[derive(Deserialize)]
#[serde(untagged)]
enum StringOrArray {
    String(String),
    Array(Vec<String>),
}

#[derive(Deserialize)]
struct WappanalyserTechnologies {
    technologies: HashMap<String, WappanalyserRule>
}

#[derive(Deserialize)]
struct WappanalyserRule {
    cookies: Option<HashMap<String, String>>,
    headers: Option<HashMap<String, String>>,
    html: Option<StringOrArray>,
}
#[derive(Default)]
struct WappanalyserRuleParsed {
    cookies: Option<HashMap<String, WappanalyserPattern>>,
    headers: Option<HashMap<String, WappanalyserPattern>>,
    body: Option<Vec<WappanalyserPattern>>,
}

struct WappanalyserPattern {
    regex: Regex,
    version: Option<i32>,
}

impl WappanalyserPattern {
    fn from_str(pattern: &str) -> Result<Self, SimpleError> {
        let mut slices = pattern.split("\\;");
        let regex = slices.next().ok_or("Invalid pattern string")?;
        let regex = Regex::new(&regex.replace("\\/", "/")
            .replace("\\'", "'")
            .replace("\\\"", "\""))?;
        let mut version_pos = None;
        for slice in slices {
            if slice.starts_with("version:") {
                match (&slice[9..]).parse::<i32>() {
                    Ok(idx) => version_pos = Some(idx),
                    Err(_) => (),
                }
            }
        }

        Ok(Self {
            regex,
            version: version_pos,
        })
    }
    fn analyse(&self, data: &str) -> Option<String> {
        match (self.version, self.regex.captures(data)) {
            (Some(version_cap), Some(cap)) => Some(cap.get(version_cap as usize).map(|m| m.as_str()).unwrap_or("").to_owned()),
            (None, Some(_)) => Some("".to_owned()),
            _ => None,
        }
    }
}

impl WappanalyserRuleParsed {
    fn try_parse(name: &str, rule: WappanalyserRule) -> Result<Self, SimpleError> {
        let mut result = Self {
            ..Default::default()
        };

        if let Some(cookie_pattern) = rule.cookies {
            let mut rules = HashMap::<String, WappanalyserPattern>::new();
            for (name, pattern) in cookie_pattern {
                match WappanalyserPattern::from_str(&pattern) {
                    Err(err) => log::warn!("Failed to parse {} cookie pattern: {}", name, err.msg),
                    Ok(pattern) => {
                        rules.insert(name, pattern);
                    }
                }
            }
            result.cookies = Some(rules);
        }
        if let Some(header_pattern) = rule.headers {
            let mut rules = HashMap::<String, WappanalyserPattern>::new();
            for (name, pattern) in header_pattern {
                match WappanalyserPattern::from_str(&pattern) {
                    Err(err) => log::warn!("Failed to parse {} header pattern: {}", name, err.msg),
                    Ok(pattern) => {
                        rules.insert(name, pattern);
                    }
                }
            }
            result.headers = Some(rules);
        }

        if let Some(body_pattern) = rule.html {
            let mut rules = Vec::<WappanalyserPattern>::new();
            match body_pattern {
                StringOrArray::String(pattern) => match WappanalyserPattern::from_str(&pattern) {
                    Err(err) => log::warn!("Failed to parse {} header pattern: {}", name, err.msg),
                    Ok(pattern) => {
                        rules.push(pattern);
                    }
                },
                StringOrArray::Array(pattern_list) => for pattern in pattern_list {
                    match WappanalyserPattern::from_str(&pattern) {
                        Err(err) => log::warn!("Failed to parse {} header pattern: {}", name, err.msg),
                        Ok(pattern) => {
                            rules.push(pattern);
                        }
                    }
                }
            }
            result.body = Some(rules);
        }

        Ok(result)
        
    }
    fn try_match(&self, data: &HttpResponseData) -> Result<Option<String>, SimpleError> {
        if let Some(header_rules) = &self.headers {
            for (name, pattern) in header_rules {
                let header = name.to_lowercase();
                if let Some(header_value) = data.headers.get(&header) {
                    match pattern.analyse(header_value) {
                        Some (version) => return Ok(Some(version)),
                        _ => (),
                    }
                }
            }
        }

        if let Some(body_rules) = &self.body {
            for pattern in body_rules {
                match pattern.analyse(&data.body) {
                    Some(version) => return Ok(Some(version)),
                    _ => (),
                }
            }
        }

        Ok(None)
    }
}


// impl From<WappanalyserRule> for WappanalyserRuleParsed {
//     fn from(rule: WappanalyserRule) -> Self {
//         match Self::try_parse(rule) {
//             Ok(rule) => rule,
//             Err(err) => {
//                 log::warn!("Failed to parse wappanalyser rule: {}", err.msg);
//                 Self::default()
//             }
//         }
//     }
// }


pub struct WebServiceAnalyser {
    rules: Arc<HashMap<String, WappanalyserRuleParsed>>,
    vuln_searcher: VulnerabilitiesSearch,
}

impl WebServiceAnalyser {
    pub fn init_from_json(wappanalyser_rules: &str, vuln_searcher: VulnerabilitiesSearch)-> Result<Self, SimpleError> {
        let json_text = std::fs::read_to_string(wappanalyser_rules)?;
        let rules = serde_json::from_str::<WappanalyserTechnologies>(&json_text)?;
        let mut parsed_rules = HashMap::<String, WappanalyserRuleParsed>::new();
        for (name, rule) in rules.technologies {
            match WappanalyserRuleParsed::try_parse(&name, rule) {
                Ok(rule) => { parsed_rules.insert(name, rule); },
                Err(err) => log::error!("Failed to parse {} rules: {}", name, err.msg),
            }
        }
        Ok(Self {
            rules: Arc::new(parsed_rules),
            vuln_searcher,
        })
    }

    pub fn analyse(&self, result: &HttpResponseData) -> HashMap<String, ServiceAnalyseResult> {
        let mut web_services: HashMap<String, ServiceAnalyseResult> = HashMap::new();
        for (name, rule) in self.rules.as_ref() {
            match rule.try_match(result) {
                Ok(Some(analysed_version)) => match web_services.get_mut(name) {
                        Some(service_version) => { service_version.version = analysed_version; },
                        None => { web_services.insert(name.to_owned(), ServiceAnalyseResult::new(name.to_owned(), analysed_version)); },
                    },
                Ok(None) => (),
                Err(err) => log::error!("Failed to analyse {}: {}", name, err.msg),
            }
        };
        web_services
    }

    pub async fn analyse_result_set(&mut self, scan_result: &ScanResult<HttpResponseData>) -> HashMap<String, ServiceAnalyseResult> {
        let mut services = match &scan_result {
            ScanResult::Err(_) => return HashMap::new(),
            ScanResult::Ok(result) => self.analyse(result),
        };

        for (_, result) in &mut services {
            match self.vuln_searcher.exploitdb().search(&result.name, &result.version).await {
                Ok(vulns) => result.vulns = vulns,
                Err(err) => log::error!("Failed to search exploitdb: {}", err.msg),
            }
        }

        services
    }
}