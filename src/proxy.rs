use serde::{Deserialize};
use tokio::time::sleep;

use crate::error::*;

#[derive(Deserialize)]
struct ProxyInfo {
    proxy: String,
}

#[derive(Clone)]
pub struct ProxyPool {
    addr: String,
}

impl ProxyPool {
    pub fn new(addr: &str) -> Self {
        Self {
            addr: addr.to_owned(),
        }
    }
    pub async fn get(&self) -> String {
        loop {
            match self.try_get().await {
                Ok(proxy) => return proxy,
                Err(err) => {
                    log::warn!("Failed to fetch a proxy server: {}", err.msg);
                }
            }
            sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }
    async fn try_get(&self) -> Result<String, ErrorMsg> {
        let proxy: ProxyInfo = reqwest::get(&self.addr).await?
            .json().await?;
        Ok(proxy.proxy)
    }
}