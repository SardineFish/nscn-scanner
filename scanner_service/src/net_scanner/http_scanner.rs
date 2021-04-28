use std::{collections::HashMap};

use reqwest::{ Response, header::HeaderMap};
use serde::{Serialize, Deserialize};
use crate::{ScanTaskInfo, ServiceAnalyseResult, error::LogError, net_scanner::scheduler::{ScannerResources, TaskPool}, proxy::{http_proxy::HttpProxyClient}};
use crate::config::GLOBAL_CONFIG;

use super::result_handler::ScanResult;

#[derive(Serialize, Deserialize, Debug)]
pub struct HttpResponseData {
    pub status: i32,
    pub headers: HashMap<String, Vec<String>>,
    pub body: String,
}

impl HttpResponseData {
    async fn from_response(response: Response) -> Self {
        Self {
            headers: response.headers().serialize(),
            status: response.status().as_u16() as i32,
            body: response.text().await.unwrap_or("Failed to parse body".to_owned()),
        }
    }
}

trait SerializeHeaders {
    fn serialize(&self) -> HashMap<String, Vec<String>>;
}

impl SerializeHeaders for HeaderMap {
    fn serialize(&self) -> HashMap<String, Vec<String>> {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for key in self.keys() {
            let values = self.get_all(key).iter()
                .filter_map(|value| value.to_str().ok().map(str::to_owned))
                .collect();
            map.insert(key.to_string(), values);
        }
        map
    }
}

pub struct HttpScanTask {
    address: String,
    resources: ScannerResources,
}

impl HttpScanTask {
    pub async fn dispatch(addr: &str, resources: &ScannerResources, task_pool: &mut TaskPool) {
        let task = HttpScanTask {
            address: addr.to_owned(),
            resources: resources.clone(),
        };
        task_pool.spawn("http", task.run()).await;
    }
    async fn run(self) {
        let mut client = match GLOBAL_CONFIG.scanner.http.socks5 {
            Some(true) => self.resources.proxy_pool.get_socks5_client().await,
            _ => self.resources.proxy_pool.get_http_client().await,
        };
        let result = self.scan(&mut client).await;
        let task_result = ScanTaskInfo::with_proxy(client.proxy_addr, result);
        self.resources.result_handler.save_scan_results("http", &self.address, &task_result).await;


        if  let (ScanResult::Ok(_), true) = (&task_result.result, GLOBAL_CONFIG.analyser.analyse_on_scan) {
            let mut services = HashMap::<String, ServiceAnalyseResult>::new();
            self.resources.analyser.web_analyser.analyse(&task_result.result, &mut services)
                .await
                .log_error_consume("web-analyse");

            self.resources.vuln_searcher.search_all(&mut services).await;
            
            self.resources.result_handler.save_analyse_results(&self.address, "web", services)
                .await
                .log_error_consume("web-result-saving");
        }
    }
    async fn scan(&self, client: &mut HttpProxyClient) -> ScanResult<HttpResponseData> {
        // let proxy_addr = self.proxy_pool.get().await;
        // let proxy = reqwest::Proxy::http(format!("http://{}", proxy_addr))?;
        // log::debug!("Use http proxy {}", proxy_addr);
        
        // log::info!("Http scan {} through {}", self.address, proxy_addr);


        let result = client.client.get(format!("http://{}", self.address))
            .send()
            .await;
        
        match result {
            Ok(response) => {
                log::info!("GET {} - {}", self.address, response.status());
                ScanResult::Ok(HttpResponseData::from_response(response).await)
            },
            Err(err) => ScanResult::Err(err.to_string())
        }
    }
}