
use tokio::{io::AsyncWriteExt, net::TcpStream, time::{timeout}};
use openssl::{ssl};
use crate::ssl_context::SSL_CONTEXT;
use crate::async_ssl;

use crate::{error::*, http::WriteRequest};
use crate::config::{GLOBAL_CONFIG};

#[derive(Clone)]
pub struct TunnelProxyClient {
    pub proxy_addr: String,
}

impl TunnelProxyClient {
    pub(super) fn new(addr: &str) -> Self {
        Self {
            proxy_addr: addr.to_owned(),
        }
    }
    pub async fn establish(&self, addr: &str) -> Result<TcpStream, SimpleError> {
        match timeout(
            tokio::time::Duration::from_secs(GLOBAL_CONFIG.scanner.https.timeout), 
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
        let stream = self.establish(&GLOBAL_CONFIG.proxy_pool.https_validate).await.log_warn("https_proxy_verify")?;
        log::info!("Proxy {} passed tunnel test.", self.proxy_addr);

        let ssl = ssl::Ssl::new(&SSL_CONTEXT)?;
        let mut ssl_stream = async_ssl::SslStream::new(ssl, stream).log_warn("https_proxy_verify")?;
        match timeout(tokio::time::Duration::from_secs(GLOBAL_CONFIG.scanner.https.timeout), ssl_stream.connect()).await {
            Ok(Ok(_)) => (),
            Ok(err) => err.log_warn("https_proxy_verify")?,
            Err(_) => Err("SSL Handshake timeout.").log_warn("https_proxy_verify")?,
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