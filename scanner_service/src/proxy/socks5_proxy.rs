use std::{sync::Arc, time};
use futures::{future::join_all};
use serde::{Deserialize};

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use tokio::{net::TcpStream, sync::{Mutex}, task, time::{sleep}};
use tokio_socks::tcp::Socks5Stream;
use crate::{error::*, net_scanner::scanner::Connector};
use crate::config::GLOBAL_CONFIG;

use super::ProxyPool;

pub(super) struct Socks5ProxyInfo {
    pub addr: String,
    pub failure_count: usize,
    pub fetch_time: DateTime<Utc>,
    pub deadline: DateTime<Utc>,
}

pub struct Socks5Proxy {
    pub addr: String,
}
impl Socks5Proxy {
}
#[async_trait::async_trait]
impl Connector<Socks5Stream<TcpStream>> for Socks5Proxy {
    async fn connect(self, addr: &str, port: u16) -> Result<Socks5Stream<TcpStream>, SimpleError> {
        let stream = TcpStream::connect(self.addr).await.map_err(|err| {
            // log::warn!("Failed to connect TCP in {}s: {}", (std::time::Instant::now() - start).as_secs_f64(), err);
            err
        })?;
        Ok(Socks5Stream::connect_with_socket(stream, (addr, port)).await.map_err(|err| {
            // log::warn!("Failed to connect TCP in {}s: {}", (std::time::Instant::now() - start).as_secs_f64(), err);
            err
        })?)
    }
}

#[derive(Deserialize)]
struct ProxyServerData {
    ip: String,
    port: u16,
    expire_time: String,
}
#[derive(Deserialize)]
struct FetchResponse {
    code: i32,
    success: bool,
    msg: String,
    data: Vec<ProxyServerData>,
}

#[derive(Clone)]
pub struct Socks5ProxyUpdater {
    pub(super) pool: Arc<Mutex<Vec<Socks5ProxyInfo>>>,
}
impl Socks5ProxyUpdater {
    pub async fn start(self) {
        if let Some(fetch_url) = &GLOBAL_CONFIG.proxy.socks5.first_fetch {
            self.fetch_new_proxy(fetch_url).await;
        } else {
            for _ in 0..GLOBAL_CONFIG.proxy.socks5.pool_size {
                self.fetch_new_proxy(&GLOBAL_CONFIG.proxy.socks5.fetch).await;
            }
        }
    }
    pub fn start_monitor(proxy_pool: &ProxyPool) {
        let proxy_pool = proxy_pool.clone();
        task::spawn(async move {
            loop {
                sleep(std::time::Duration::from_secs(3)).await;
                let proxy = proxy_pool.get_socks5_proxy().await;
                if let Some(url) = &GLOBAL_CONFIG.proxy.socks5.validate {
                    if let Err(err) = Self::validate_proxy(&proxy, url).await {
                        log::warn!("Proxy {} validate failed: {}", proxy.addr, err.msg);
                    }
                }
            }
        });
    }
    async fn validate_proxy(_proxy: &Socks5Proxy, _validate_url: &str) -> Result<(), SimpleError> {
        // let mut stream = proxy.connect(validate_url, 3).await?;
        // stream.write_all(b"\r\n\r\n").await?;
        // let mut buf = String::new();
        // stream.read_to_string(&mut buf).await?;
        Ok(())
    }
    fn manage_expire(self, addr: String, deadline: DateTime<Utc>) {
        task::spawn(async move {
            let duration = deadline - Utc::now();
            log::info!("{} will expire at {}", addr, deadline);
            sleep(std::time::Duration::from_millis(duration.num_milliseconds() as u64)).await;
            log::info!("{} expired", addr);

            self.fetch_new_proxy(&GLOBAL_CONFIG.proxy.socks5.fetch).await;

            let mut guard = self.pool.lock().await;
            guard.iter().position(|proxy| proxy.addr == addr)
                .map(|idx| guard.remove(idx))
                .map(|proxy| log::info!("Proxy {} expired", proxy.addr));
            
            // if guard.len() < GLOBAL_CONFIG.proxy_pool.socks5.pool_size {
            //     self.fetch_new_proxy().await;
            // }
        });
    }
    async fn fetch_new_proxy(&self, addr: &str) {
        loop {
            match self.fecth_proxy(addr).await {
                Ok(proxy_list) => for proxy in proxy_list {
                    log::info!("Fetched socks5 proxy {}", proxy.addr);
                    self.clone().manage_expire(proxy.addr.clone(), proxy.deadline);
                    let mut guard = self.pool.lock().await;
                    guard.push(proxy);
                },
                err => {
                    err.log_error_consume("socks5-fetch");
                    sleep(time::Duration::from_secs(1)).await;
                    continue;
                },
            }
            break;
        }
    }
    async fn fecth_proxy(&self, addr: &str) -> Result<Vec<Socks5ProxyInfo>, SimpleError> {
        let data = reqwest::get(addr)
            .await?
            .json::<FetchResponse>()
            .await?;
        
        if !data.success {
            Err(data.msg)?
        }

        if data.data.len() < 1 {
            Err("Empty proxy")?
        }


        let proxy_list: Vec<Socks5ProxyInfo> = join_all(data.data.into_iter()
            .map(|data| async move {
                let time = NaiveDateTime::parse_from_str(&data.expire_time, "%Y-%m-%d %H:%M:%S")?;
                let deadline = chrono_tz::Asia::Shanghai
                    .from_local_datetime(&time)
                    .single()
                    .ok_or("Time converting failed")?
                    .with_timezone(&Utc);

                // let proxy_addr = format!("{}:{}", data.ip, data.port);

                Result::<Socks5ProxyInfo, SimpleError>::Ok(Socks5ProxyInfo {
                    addr: format!("{}:{}", data.ip, data.port),
                    failure_count: 0,
                    fetch_time: Utc::now(),
                    deadline,
                })
            })).await
            .into_iter()
            .filter_map(|proxy| match proxy {
                Ok(proxy) => Some(proxy),
                Err(err) => {
                    log::error!("Failed to create proxy info {}", err.msg);
                    None
                },
            })
            .collect();

        Ok(proxy_list)
    }
}

#[cfg(test)]
#[allow(warnings)]
mod test {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};
    use crate::config::GLOBAL_CONFIG;

    #[tokio::test]
    async fn test_socks5() {
        let addr = GLOBAL_CONFIG.test.as_ref().and_then(|m|m.get("test-socks5")).unwrap();
        let test_ssh = GLOBAL_CONFIG.test.as_ref().and_then(|m|m.get("test-ssh")).unwrap();
        let socket = timeout(Duration::from_secs(3), TcpStream::connect(addr)).await.unwrap().unwrap();
        let mut stream = tokio_socks::tcp::Socks5Stream::connect_with_socket(socket, (test_ssh.as_str(), 22)).await.unwrap();
        // stream.read_i32().await.unwrap();
        // stream.write_i32(1).await.unwrap();
        stream.write(b"fuck").await.unwrap();
    }
}