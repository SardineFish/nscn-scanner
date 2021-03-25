use chrono::Utc;
use rand::{RngCore, SeedableRng};
use reqwest::{Proxy, StatusCode};
use serde::{Deserialize};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::Mutex, task::{self, JoinHandle}, time::{sleep, timeout}};
use tokio_socks::tcp::Socks5Stream;
use std::{collections::{HashMap, HashSet}, sync::Arc};
use openssl::{ssl};
use crate::ssl_context::SSL_CONTEXT;
use crate::async_ssl;

use crate::{error::*, http::WriteRequest};
use crate::config::{GLOBAL_CONFIG, ProxyVerify};

pub struct Socks5Proxy {
    pub addr: String,
}
impl Socks5Proxy {
    pub async fn connect(&self, target: &str) -> Socks5Stream<TcpStream> {
        let socket = TcpStream::connect(self.addr.as_str()).await;
        let stream = match tokio_socks::tcp::Socks5Stream::connect(self.addr.as_str(), target).await {
            Ok(stream) => stream,
            Err(err) => panic!(),
        };
        stream
    }
}

#[cfg(test)]
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