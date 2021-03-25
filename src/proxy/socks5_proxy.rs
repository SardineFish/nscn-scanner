use std::{pin::Pin, task::{Context, Poll}};

use chrono::{DateTime, Utc};
use tokio::{io::{self, AsyncRead, AsyncWrite, ReadBuf}, net::TcpStream, time::timeout};
use tokio_socks::tcp::Socks5Stream;
use tokio::time::Duration;
use crate::error::*;
use crate::config::GLOBAL_CONFIG;

pub(super) struct Socks5ProxyInfo {
    pub addr: String,
    pub failure_count: usize,
    pub fetch_time: DateTime<Utc>,
    pub deadline: DateTime<Utc>,
}

pub struct Socks5Proxy {
    pub addr: String,
    stream: Socks5Stream<TcpStream>,
}
impl Socks5Proxy {
    pub async fn connect(proxy: &str, target: &str) -> Result<Self, SimpleError> {
        let socket = timeout(Duration::from_secs(GLOBAL_CONFIG.proxy_pool.socks5_timeout), TcpStream::connect(proxy))
            .await
            .map_err(|_|"Socks5 connect timeout")??;

        let stream = Socks5Stream::connect_with_socket(socket, target).await?;
        Ok(Socks5Proxy {
            addr: proxy.to_owned(),
            stream,
        })
    }
}
impl AsyncRead for Socks5Proxy {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for Socks5Proxy {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
    fn poll_write_vectored(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[std::io::IoSlice<'_>]) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
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