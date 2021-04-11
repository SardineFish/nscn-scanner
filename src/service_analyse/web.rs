use std::{collections::HashMap, sync::Arc};

use either::Either;
use redis::acl::Rule;
use regex::Regex;
use serde::{Deserialize};
use crate::{config::GLOBAL_CONFIG, net_scanner::{http_scanner::HttpResponseData, result_handler::{NetScanResultSet, ScanResult}}};
use crate::error::*;

use super::ServiceInfo;

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

#[derive(Clone)]
pub struct WebServiceAnalyser {
    rules: Arc<HashMap<String, WappanalyserRuleParsed>>,
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
        let regex = Regex::new(regex)?;
        let mut version_pos = None;
        for slice in slices {
            if slice.starts_with("version:") {
                match (&slice[10..]).parse::<i32>() {
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
            (Some(version_cap), Some(cap)) => cap.get(version_cap as usize).map(|m| m.as_str().to_owned()),
            (None, Some(cap)) => Some("".to_owned()),
            _ => None,
        }
    }
}

impl WappanalyserRuleParsed {
    fn try_parse(rule: WappanalyserRule) -> Result<Self, SimpleError> {
        let mut result = Self {
            ..Default::default()
        };

        if let Some(cookie_pattern) = rule.cookies {
            let mut rules = HashMap::<String, WappanalyserPattern>::new();
            for (name, pattern) in cookie_pattern {
                match WappanalyserPattern::from_str(&pattern) {
                    Err(err) => log::warn!("Failed to parse cookie pattern: {}", err.msg),
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
                    Err(err) => log::warn!("Failed to parse header pattern: {}", err.msg),
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
                    Err(err) => log::warn!("Failed to parse header pattern: {}", err.msg),
                    Ok(pattern) => {
                        rules.push(pattern);
                    }
                },
                StringOrArray::Array(pattern_list) => for pattern in pattern_list {
                    match WappanalyserPattern::from_str(&pattern) {
                        Err(err) => log::warn!("Failed to parse header pattern: {}", err.msg),
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
                if let Some(header_values) = data.headers.get(name) {
                    for header_value in header_values {
                        match pattern.analyse(header_value) {
                            Some (version) => return Ok(Some(version)),
                            _ => (),
                        }
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


impl From<WappanalyserRule> for WappanalyserRuleParsed {
    fn from(rule: WappanalyserRule) -> Self {
        match Self::try_parse(rule) {
            Ok(rule) => rule,
            Err(err) => {
                log::warn!("Failed to parse wappanalyser rule: {}", err.msg);
                Self::default()
            }
        }
    }
}

impl WebServiceAnalyser {
    pub fn init_from_json(wappanalyser_rules: &str)-> Result<Self, SimpleError> {
        let json_text = std::fs::read_to_string(wappanalyser_rules)?;
        let rules = serde_json::from_str::<WappanalyserTechnologies>(&json_text)?;
        let mut parsed_rules = HashMap::<String, WappanalyserRuleParsed>::new();
        for (name, rule) in rules.technologies {
            match WappanalyserRuleParsed::try_parse(rule) {
                Ok(rule) => { parsed_rules.insert(name, rule); },
                Err(err) => log::error!("Failed to parse {} rules: {}", name, err.msg),
            }
        }
        Ok(Self {
            rules: Arc::new(parsed_rules),
        })
    }

    pub fn analyse(&self, result_set: &NetScanResultSet<HttpResponseData>) -> Result<HashMap<String, String>, SimpleError> {
        let mut web_services: HashMap<String, String> = HashMap::new();
        if result_set.success <= 0 {
            return Ok(web_services);
        }
        for result in &result_set.results {
            let data = match &result.result {
                ScanResult::Ok(data) => data,
                _ => continue,
            };
            for (name, rule) in self.rules.as_ref() {
                match rule.try_match(data) {
                    Ok(Some(analysed_version)) => match web_services.get_mut(name) {
                            Some(service_version) => { *service_version = analysed_version; },
                            None => { web_services.insert(name.to_owned(), analysed_version); },
                        },
                    Ok(None) => (),
                    Err(err) => log::error!("Failed to analyse {}: {}", name, err.msg),
                }
            };
        }
        Ok(web_services)
    }
}