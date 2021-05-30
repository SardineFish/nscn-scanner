use std::time::{Duration};

use serde::{Serialize, Deserialize};
use openssl::ssl::Ssl;
use tokio::{io::{AsyncRead, AsyncWrite}, time::{timeout}};
use mongodb::{bson};

use crate::{config::GLOBAL_CONFIG,};
use crate::error::*;
use crate::ssl::ssl_context::SSL_CONTEXT;
use crate::ssl::async_ssl;
use super::{result_handler::ScanResult, scanner::ScanTask};

pub struct HttpsScanTask;
impl HttpsScanTask {
    async fn scan<S: AsyncRead + AsyncWrite + Unpin>(&self, stream: S) -> Result<HttpsResponse, SimpleError> {
        // log::info!("Scan HTTPS {} through {}", self.addr, client.proxy_addr);
        timeout(Duration::from_secs(GLOBAL_CONFIG.scanner.https.timeout), async move {
            let stream = self.connect_ssl(stream).await?;

            match stream.sync_ssl().peer_certificate() {
                None => Err("No certificate")?,
                Some(cert) => {
                    let pem = cert.to_pem()?;
                    Ok(HttpsResponse {
                        cert: std::str::from_utf8(&pem[..])?.to_owned(),
                    })
                }
            }
        }).await.map_err(|_|"Timeout")?
    }
    async fn connect_ssl<S: AsyncRead + AsyncWrite + Unpin>(&self, stream: S) -> Result<async_ssl::SslStream<S>, SimpleError> {
        // log::info!("ESTABLISHED");
        let ssl = Ssl::new(&SSL_CONTEXT)?;
        let mut stream = async_ssl::SslStream::new(ssl, stream)?;
        match timeout(tokio::time::Duration::from_secs(GLOBAL_CONFIG.scanner.https.timeout), stream.connect()).await{
            Ok(Ok(())) => Ok(stream),
            Ok(Err(err)) => Err(err)?,
            Err(_) => Err("SSL Handshake timeout.")?,
        }
    }
}

#[async_trait::async_trait]
impl ScanTask<HttpsResponse> for HttpsScanTask {
    fn scanner_name() -> &'static str {
        "https"
    }
    async fn scan<S: Send + Sync + AsyncRead + AsyncWrite + Unpin + 'static>(self, stream: &mut S) -> Result<HttpsResponse, SimpleError> {
        self.scan(stream).await
    }
}

#[derive(Serialize, Deserialize)]
struct HttpsScanRecord {
    address: String,
    proxy: String,
    time: bson::DateTime,
    result: ScanResult<HttpsResponse>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HttpsResponse {
    pub cert: String,
}
