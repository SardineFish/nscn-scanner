use rand::{RngCore, SeedableRng};
use serde::{Deserialize};
use tokio::{sync::Mutex, task::{self, JoinHandle}, time::sleep};
use std::{borrow::BorrowMut, mem::{self, swap}, sync::Arc, time::Duration};

use crate::error::*;
use crate::config::GLOBAL_CONFIG;

#[derive(Clone, Deserialize)]
struct ProxyInfo {
    proxy: String,
}

#[derive(Clone)]
pub struct ProxyPool {
    addr: String,
    pool: Arc<Mutex<Vec<ProxyInfo>>>,
    rng: Arc<Mutex<rand::rngs::SmallRng>>,
}

impl ProxyPool {
    pub fn new(addr: &str) -> Self {
        Self {
            addr: addr.to_owned(),
            pool: Arc::new(Mutex::new(Vec::new())),
            rng: Arc::new(Mutex::new(rand::rngs::SmallRng::from_entropy())),
        }
    }
    pub async fn start(&self) -> JoinHandle<()> {
        let pool = self.pool.clone();
        if let Err(err) = Self::update_pool(&pool).await {
            log::error!("Failed to initially update proxy pool: {}", err.msg);
        }
        task::spawn(async move {
            loop {
                if let Err(err) = Self::update_pool(&pool).await {
                    log::warn!("Failed to update proxy pool: {}", err.msg);
                }
                sleep(tokio::time::Duration::from_secs(GLOBAL_CONFIG.proxy_pool_retry)).await;
            }
        })
    }
    async fn update_pool(pool: &Arc<Mutex<Vec<ProxyInfo>>>) -> Result<(), ErrorMsg> {
        let mut proxy_list: Vec<ProxyInfo> = reqwest::get(&GLOBAL_CONFIG.proxy_pool).await?
            .json().await?;
        let mut guard = pool.lock().await;
        // guard.clear();
        // guard.clone_from_slice(&proxy_list[..]);
        // guard.extend_from_slice(&proxy_list[..]);
        mem::swap(&mut *guard, &mut proxy_list);
        log::info!("Get {} proxy servers.", guard.len());
        Ok(())
    }
    pub async fn get(&self) -> String {
        loop {
            let t = self.rng.lock().await.next_u32();
            {
                let guard = self.pool.lock().await;
                if guard.len() > 0 {
                    let idx = ((t as u64) * guard.len() as u64 / u32::MAX as u64) % (guard.len() as u64);
                    return guard[idx as usize].proxy.clone();
                }
            }
            log::warn!("Proxy pool is empty, retry in {}s", GLOBAL_CONFIG.proxy_pool_retry);
            sleep(tokio::time::Duration::from_secs(GLOBAL_CONFIG.proxy_pool_retry)).await;
        }
    }
}