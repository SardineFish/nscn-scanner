use chrono::Utc;
use reqwest::{Proxy, StatusCode};

use crate::{error::*};
use crate::config::{GLOBAL_CONFIG, ProxyVerify};

#[derive(Clone)]
pub struct HttpProxyClient {
    pub proxy_addr: String,
    pub client: reqwest::Client,
}

impl HttpProxyClient {
    pub fn with_http_proxy(addr: &str) -> Result<Self, SimpleError> {
        let proxy_addr = format!("http://{}", addr);
        let client = reqwest::Client::builder()
            .proxy(Proxy::http(&proxy_addr)?)
            .proxy(Proxy::https(&proxy_addr)?)
            .timeout(std::time::Duration::from_secs(GLOBAL_CONFIG.scanner.http.timeout))
            .build()?;
        Ok(Self {
            proxy_addr: addr.to_owned(),
            client
        })
    }

    pub(super) async fn verify(&self) -> Result<bool, SimpleError> {
        for (idx, verify_method) in GLOBAL_CONFIG.proxy_pool.http_validate.iter().enumerate() {
            match verify_method {
                ProxyVerify::Plain(url) => {
                    let response = self.client.get(url)
                        .send()
                        .await?;
                    if response.status() != StatusCode::OK {
                        log::warn!("Verify {} stage {} failed {}", self.proxy_addr, idx, response.status());
                        return Ok(false);
                    }
                },
                ProxyVerify::Echo{base, pattern} => {
                    let url = pattern.replace("{challenge}", Utc::now().timestamp_millis().to_string().as_str());
                    let response = self.client.get(format!("{}{}", base, url))
                        .send()
                        .await?;

                    if response.status() != StatusCode::OK {
                        log::warn!("Verify {} stage {} failed {}", self.proxy_addr, idx, response.status());
                        return Ok(false);
                    }
                    let body = response.text().await?;
                    if body != url {
                        log::warn!("Verify {} stage {} failed {} != {}", self.proxy_addr, idx, url, body);
                        return Ok(false);
                    } 
                }
            }
        }

        log::info!("Proxy {} passed all tests.", self.proxy_addr);

        // let tunnel_proxy = TunnelProxyClient::new(&self.proxy_addr);
        // match tunnel_proxy.verify().await {
        //     Ok(_) => (),
        //     Err(err) => log::warn!("Proxy {} failed on tunnel verify: {}", self.proxy_addr, err.msg),
        // }

        Ok(true)
    }
}