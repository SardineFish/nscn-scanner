use rand::{RngCore, SeedableRng};
use serde::{Deserialize};
use tokio::{sync::Mutex, task::{self, JoinHandle}, time::sleep};
use std::{ collections::HashMap, mem::{self}, sync::Arc};

use crate::error::*;
use crate::config::GLOBAL_CONFIG;

#[derive(Clone, Deserialize)]
struct ProxyInfo {
    proxy: String,
}

#[derive(Clone)]
pub struct ProxyPool {
    addr: String,
    client_pool: Arc<Mutex<Vec<reqwest::Client>>>,
    rng: Arc<Mutex<rand::rngs::SmallRng>>,
}

impl ProxyPool {
    pub fn new(addr: &str) -> Self {
        Self {
            addr: addr.to_owned(),
            client_pool: Arc::new(Mutex::new(Vec::new())),
            rng: Arc::new(Mutex::new(rand::rngs::SmallRng::from_entropy())),
        }
    }
    pub async fn start(&self) -> JoinHandle<()> {
        let mut updater = ProxyPoolUpdator::new();
        let client_pool = self.client_pool.clone();
        if let Err(err) = Self::update_pool(&mut updater, &client_pool).await {
            log::error!("Failed to initially update proxy pool: {}", err.msg);
        }
        task::spawn(async move {
            loop {
                if let Err(err) = Self::update_pool(&mut updater, &client_pool).await {
                    log::warn!("Failed to update proxy pool: {}", err.msg);
                }
                sleep(tokio::time::Duration::from_secs(GLOBAL_CONFIG.proxy_pool_retry)).await;
            }
        })
    }
    async fn update_pool(updater: &mut ProxyPoolUpdator, client_pool: &Arc<Mutex<Vec<reqwest::Client>>>) -> Result<(), ErrorMsg> {
        let mut pool = updater.update().await?;
        let mut guard = client_pool.lock().await;
        mem::swap(&mut *guard, &mut pool);
        log::info!("Get {} proxy servers.", guard.len());
        Ok(())
    }
    pub async fn get_client(&self) -> reqwest::Client {
        loop {
            let t = self.rng.lock().await.next_u32();
            {
                let guard = self.client_pool.lock().await;
                if guard.len() > 0 {
                    let idx = ((t as u64) * guard.len() as u64 / u32::MAX as u64) % (guard.len() as u64);
                    return guard[idx as usize].clone();
                }
            }
            log::warn!("Proxy pool is empty, retry in {}s", GLOBAL_CONFIG.proxy_pool_retry);
            sleep(tokio::time::Duration::from_secs(GLOBAL_CONFIG.proxy_pool_retry)).await;
        }
    }
}

struct ProxyPoolUpdator {
    client_map: HashMap<String, reqwest::Client>,
}

impl ProxyPoolUpdator {
    pub fn new() -> Self {
        Self {
            client_map: HashMap::new(),
        }
    }

    pub async fn update(&mut self) -> Result<Vec<reqwest::Client>, ErrorMsg>
    {
        let proxy_list: Vec<ProxyInfo> = reqwest::get(&GLOBAL_CONFIG.proxy_pool)
            .await?
            .json()
            .await?;
        let mut client_list = Vec::<reqwest::Client>::new();

        for proxy in &proxy_list {
            if let Some(client) = self.client_map.get(&proxy.proxy) {
                client_list.push(client.clone());
            } else {
                let proxy_addr = format!("http://{}", proxy.proxy);
                let client = reqwest::Client::builder()
                    .proxy(reqwest::Proxy::http(&proxy_addr)?)
                    .timeout(std::time::Duration::from_secs(GLOBAL_CONFIG.request_timeout))
                    .build()?;
                client_list.push(client);
            }
        }
        self.client_map.clear();
        for (i, proxy) in proxy_list.into_iter().enumerate() {
            self.client_map.insert(proxy.proxy, client_list[i].clone());
        }

        Ok(client_list)
    }
}