
use rand::{RngCore, SeedableRng};
use serde::{Deserialize};
use tokio::{ sync::Mutex, task::{self, JoinHandle}, time::{sleep}};
use std::{collections::{HashMap}, sync::Arc};

use crate::{error::*};
use crate::config::{GLOBAL_CONFIG};

use super::{http_proxy::HttpProxyClient, socks5_proxy::{Socks5ProxyInfo, Socks5ProxyUpdater}};
use super::tunnel_proxy::TunnelProxyClient;
use super::socks5_proxy::Socks5Proxy;

#[derive(Clone, Deserialize)]
struct ProxyInfo {
    proxy: String,
}

#[derive(Clone)]
pub struct ProxyPool {
    http_client_pool: Arc<Mutex<Vec<HttpProxyClient>>>,
    tunnel_client_pool: Arc<Mutex<Vec<TunnelProxyClient>>>,
    socks5_proxy_pool: Arc<Mutex<Vec<Socks5ProxyInfo>>>,
    rng: Arc<Mutex<rand::rngs::SmallRng>>,
}

impl ProxyPool {
    pub fn new() -> Self {
        Self {
            http_client_pool: Arc::new(Mutex::new(Vec::new())),
            tunnel_client_pool: Arc::new(Mutex::new(Vec::new())),
            socks5_proxy_pool: Arc::new(Mutex::new(Vec::new())),
            rng: Arc::new(Mutex::new(rand::rngs::SmallRng::from_entropy())),
        }
    }
    pub async fn start(&self) -> JoinHandle<()> {
        let mut updater = ProxyPoolUpdator::new(self.http_client_pool.clone(), self.tunnel_client_pool.clone());
        // let client_pool = self.http_client_pool.clone();
        if let Err(err) = updater.try_update().await {
            log::error!("Failed to initially update proxy pool: {}", err.msg);
        }
        if GLOBAL_CONFIG.proxy_pool.socks5.enabled {
            let socks5_updater = Socks5ProxyUpdater {
                pool: self.socks5_proxy_pool.clone(),
            };
            socks5_updater.start().await;
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
            // log::warn!("Proxy pool is empty, retry in {}s", GLOBAL_CONFIG.proxy_pool.update_interval);
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
            // log::warn!("Proxy pool is empty, retry in {}s", GLOBAL_CONFIG.proxy_pool.update_interval);
            sleep(tokio::time::Duration::from_secs(GLOBAL_CONFIG.proxy_pool.update_interval)).await;
        }
    }
    pub async fn get_socks5_proxy(&self) -> Socks5Proxy {
        let proxy = loop {
            let t = self.rng.lock().await.next_u32();
            {
                let guard = self.socks5_proxy_pool.lock().await;
                if guard.len() > 0 {
                    let idx = ((t as u64) * guard.len() as u64 / u32::MAX as u64) % (guard.len() as u64);
                    break guard[idx as usize].addr.clone();
                }
            }
            // log::warn!("Proxy pool is empty, retry in {}s", GLOBAL_CONFIG.proxy_pool.update_interval);
            sleep(tokio::time::Duration::from_secs(3)).await;
        };
        Socks5Proxy {
            addr: proxy
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
            sleep(tokio::time::Duration::from_secs(GLOBAL_CONFIG.proxy_pool.update_interval)).await;
            if let Err(err) = self.try_update().await {
                log::warn!("Failed to update proxy pool: {}", err.msg);
            }
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
                    log::debug!("Tunnel verification failed: {}", err.msg);
                    None
                },
            })
            .collect();
        
        log::info!("{} http proxy servers available.", verified_http_client.len());
        if verified_http_client.len() == 0 {
            log::warn!("Http proxy pool empty.");
        }
        {
            let mut guard = self.http_proxy_pool.lock().await;
            std::mem::swap(&mut *guard, &mut verified_http_client);
        }

        log::info!("{} https proxy servers available.", verified_tunnel_client.len());
        if verified_tunnel_client.len() == 0 {
            log::warn!("Https proxy pool empty.");
        }
        {
            let mut guard = self.https_proxy_pool.lock().await;
            std::mem::swap(&mut *guard, &mut verified_tunnel_client);
        }

        Ok(())
    }

    async fn verify(client: &HttpProxyClient) -> bool {
        match client.verify().await {
            Err(err)=> {
                log::debug!("Failed to verify {}: {}", client.proxy_addr, err.msg);
                false
            },
            Ok(result) => {
                result
            }
        }
    }
}

