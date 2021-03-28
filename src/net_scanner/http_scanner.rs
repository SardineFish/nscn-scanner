use std::{collections::HashMap};

use reqwest::{ Response, header::HeaderMap};
use serde::{Serialize, Deserialize};
use crate::{proxy::{http_proxy::HttpProxyClient}, net_scanner::scheduler::{ScannerResources, TaskPool}};
use crate::config::GLOBAL_CONFIG;

use super::result_handler::ScanResult;

#[derive(Serialize, Deserialize)]
pub struct HttpResponseData {
    status: i32,
    headers: HashMap<String, Vec<String>>,
    body: String,
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
        self.resources.result_handler.save("http", &self.address, &client.proxy_addr, result).await;
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