use chrono::Utc;
use futures::FutureExt;
use rand::{RngCore, SeedableRng};
use reqwest::{Proxy, StatusCode};
use serde::{Deserialize};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::Mutex, task::{self, JoinHandle}, time::{sleep, timeout}};
use std::{collections::HashMap, mem::{self}, sync::Arc};
use openssl::{ssl, x509::X509, x509::X509Ref};
use crate::ssl_context::SSL_CONTEXT;
use crate::async_ssl;

use crate::{error::*, http::WriteRequest};
use crate::config::{GLOBAL_CONFIG, ProxyVerify};

#[derive(Clone, Deserialize)]
struct ProxyInfo {
    proxy: String,
}

#[derive(Clone)]
pub struct ProxyPool {
    http_client_pool: Arc<Mutex<Vec<HttpProxyClient>>>,
    tunnel_client_pool: Arc<Mutex<Vec<TunnelProxyClient>>>,
    rng: Arc<Mutex<rand::rngs::SmallRng>>,
}

impl ProxyPool {
    pub fn new() -> Self {
        Self {
            http_client_pool: Arc::new(Mutex::new(Vec::new())),
            tunnel_client_pool: Arc::new(Mutex::new(Vec::new())),
            rng: Arc::new(Mutex::new(rand::rngs::SmallRng::from_entropy())),
        }
    }
    pub async fn start(&self) -> JoinHandle<()> {
        let mut updater = ProxyPoolUpdator::new(self.http_client_pool.clone(), self.tunnel_client_pool.clone());
        let client_pool = self.http_client_pool.clone();
        if let Err(err) = updater.try_update().await {
            log::error!("Failed to initially update proxy pool: {}", err.msg);
        }
        task::spawn(async move {
            updater.update().await;
        })
    }
    
    pub async fn get_client(&self) -> reqwest::Client {
        self.get_http_client().await.client
    }
    pub async fn get_http_client(&self) -> HttpProxyClient {
        loop {
            let t = self.rng.lock().await.next_u32();
            {
                let guard = self.http_client_pool.lock().await;
                if guard.len() > 0 {
                    let idx = ((t as u64) * guard.len() as u64 / u32::MAX as u64) % (guard.len() as u64);
                    return guard[idx as usize].clone();
                }
            }
            log::warn!("Proxy pool is empty, retry in {}s", GLOBAL_CONFIG.proxy_pool.update_interval);
            sleep(tokio::time::Duration::from_secs(GLOBAL_CONFIG.proxy_pool.update_interval)).await;
        }
    }
    pub async fn get_tunnel_client(&self) -> TunnelProxyClient {
        loop {
            let t = self.rng.lock().await.next_u32();
            {
                let guard = self.tunnel_client_pool.lock().await;
                if guard.len() > 0 {
                    let idx = ((t as u64) * guard.len() as u64 / u32::MAX as u64) % (guard.len() as u64);
                    return guard[idx as usize].clone();
                }
            }
            log::warn!("Proxy pool is empty, retry in {}s", GLOBAL_CONFIG.proxy_pool.update_interval);
            sleep(tokio::time::Duration::from_secs(GLOBAL_CONFIG.proxy_pool.update_interval)).await;
        }
    }
}

struct ProxyPoolUpdator {
    client_map: HashMap<String, HttpProxyClient>,
    http_proxy_pool: Arc<Mutex<Vec<HttpProxyClient>>>,
    https_proxy_pool: Arc<Mutex<Vec<TunnelProxyClient>>>,
}

impl ProxyPoolUpdator {
    pub fn new(
        http_proxy_pool: Arc<Mutex<Vec<HttpProxyClient>>>,
        https_proxy_pool: Arc<Mutex<Vec<TunnelProxyClient>>>,
    ) -> Self {
        Self {
            client_map: HashMap::new(),
            http_proxy_pool,
            https_proxy_pool,
        }
    }

    pub async fn update(&mut self) {
        loop {
            if let Err(err) = self.try_update().await {
                log::warn!("Failed to update proxy pool: {}", err.msg);
            }
            sleep(tokio::time::Duration::from_secs(GLOBAL_CONFIG.proxy_pool.update_interval)).await;
        }
    }

    pub async fn try_update(&mut self) -> Result<(), SimpleError>
    {
        let proxy_list: Vec<ProxyInfo> = reqwest::get(&GLOBAL_CONFIG.proxy_pool.fetch_addr)
            .await?
            .json()
            .await?;
            
        log::info!("Get {} proxy servers.", proxy_list.len());

        let mut client_list = Vec::<HttpProxyClient>::new();

        for proxy in &proxy_list {
            if let Some(client) = self.client_map.get(&proxy.proxy) {
                client_list.push(client.clone());
            } else {
                match HttpProxyClient::with_http_proxy(&proxy.proxy) {
                    Ok(client) => client_list.push(client),
                    Err(err) => log::error!("Failed to create proxy client: {}", err.msg),
                }
            }
        }
        self.client_map.clear();
        for (i, proxy) in proxy_list.into_iter().enumerate() {
            self.client_map.insert(proxy.proxy, client_list[i].clone());
        }

        let mut verified_http_client = Vec::<HttpProxyClient>::new();

        let result = futures::future::join_all(client_list.iter().map(|client| Self::verify(client))).await;

        for (i, result) in result.into_iter().enumerate() {
            if result {
                verified_http_client.push(client_list[i].clone());
            }
        }

        let mut verified_tunnel_client: Vec<TunnelProxyClient> = 
            futures::future::join_all(
                verified_http_client
                .iter()
                .map(|client| TunnelProxyClient::new(&client.proxy_addr).verify()))
            .await
            .into_iter()
            .filter_map(|result| match result {
                Ok(client) => Some(client),
                Err(err) => {
                    log::warn!("Tunnel verification failed: {}", err.msg);
                    None
                },
            })
            .collect();
        
        log::info!("{} http proxy servers available.", verified_http_client.len());
        {
            let mut guard = self.http_proxy_pool.lock().await;
            std::mem::swap(&mut *guard, &mut verified_http_client);
        }

        log::info!("{} proxy servers available for tunnel proxy.", verified_tunnel_client.len());
        {
            let mut guard = self.https_proxy_pool.lock().await;
            std::mem::swap(&mut *guard, &mut verified_tunnel_client);
        }

        Ok(())
    }

    async fn verify(client: &HttpProxyClient) -> bool {
        match client.verify().await {
            Err(err)=> {
                log::warn!("Failed to verify {}: {}", client.proxy_addr, err.msg);
                false
            },
            Ok(result) => {
                result
            }
        }
    }
}

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

    async fn verify(&self) -> Result<bool, SimpleError> {
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

#[derive(Clone)]
pub struct TunnelProxyClient {
    pub proxy_addr: String,
}

impl TunnelProxyClient {
    fn new(addr: &str) -> Self {
        Self {
            proxy_addr: addr.to_owned(),
        }
    }
    pub async fn establish(&self, addr: &str) -> Result<TcpStream, SimpleError> {
        match timeout(
            tokio::time::Duration::from_secs(1), 
            self.try_establish(addr)
            ).await 
        {
            Ok(result) => result,
            Err(_) => Err("Proxy tunnel establish timeout.")?,
        }
    }
    pub async fn try_establish(&self, addr: &str) -> Result<TcpStream, SimpleError> {
        let mut tcp = TcpStream::connect(&self.proxy_addr).await?;
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut request = httparse::Request::new(&mut headers);
        request.method = Some("CONNECT");
        request.path = Some(addr);
        request.version = Some(1);
        let message = request.write_request()?;
        tcp.write_all(message.as_bytes()).await?;

        let mut buffer: [u8; 512] = [0; 512];
        headers = [httparse::EMPTY_HEADER; 16];
        let mut response = httparse::Response::new(&mut headers);
        crate::http::parse_from_stream(&mut response, &mut tcp, &mut buffer).await?;

        match response.code {
            Some(200) => Ok(tcp),
            Some(code) => Err(format!("Server refused to open tunnel: {}", code))?,
            None => Err("Invalid server response.")?,
        }
    }

    pub async fn verify(self) -> Result<Self, SimpleError> {
        let stream = self.establish(&GLOBAL_CONFIG.proxy_pool.https_validate).await.log_warn()?;
        log::info!("Proxy {} passed tunnel test.", self.proxy_addr);

        let ssl = ssl::Ssl::new(&SSL_CONTEXT)?;
        let mut ssl_stream = async_ssl::SslStream::new(ssl, stream).log_warn()?;
        match timeout(tokio::time::Duration::from_secs(1), ssl_stream.connect()).await {
            Ok(Ok(_)) => (),
            Ok(err) => err.log_warn()?,
            Err(_) => Err("SSL Handshake timeout.").log_warn()?,
        }
        log::info!("Proxy {} ssl handshake successfully.", self.proxy_addr);

        match ssl_stream.sync_ssl().peer_certificate() {
            Some(cert) => {
                log::info!("Get cert though {} - {:?}", self.proxy_addr, cert);
                Ok(self)
            },
            None => Err(SimpleError::new("None certificate")),
        }
    }
}
