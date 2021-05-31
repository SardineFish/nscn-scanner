
use serde::{Serialize, Deserialize};
use openssl::ssl::Ssl;
use tokio::{io::{AsyncRead, AsyncWrite}};
use mongodb::{bson};

use crate::error::*;
use crate::ssl::ssl_context::SSL_CONTEXT;
use crate::ssl::async_ssl;
use super::{result_handler::ScanResult, scanner::ScanTask};

pub struct HttpsScanTask;
impl HttpsScanTask {
    async fn scan<S: AsyncRead + AsyncWrite + Unpin>(stream: S) -> Result<HttpsResponse, SimpleError> {
        let stream = Self::connect_tls(stream).await?;
        match stream.sync_ssl().peer_certificate() {
            None => Err("No certificate")?,
            Some(cert) => {
                let pem = cert.to_pem()?;
                Ok(HttpsResponse {
                    cert: std::str::from_utf8(&pem[..])?.to_owned(),
                })
            }
        }
    }
    async fn connect_tls<S: AsyncRead + AsyncWrite + Unpin>(stream: S) -> Result<async_ssl::SslStream<S>, SimpleError> {
        // log::info!("ESTABLISHED");
        let ssl = Ssl::new(&SSL_CONTEXT)?;
        let mut stream = async_ssl::SslStream::new(ssl, stream)?;
        stream.connect().await?;
        Ok(stream)
    }
}

#[async_trait::async_trait]
impl ScanTask<HttpsResponse> for HttpsScanTask {
    fn scanner_name() -> &'static str {
        "https"
    }
    async fn scan<S: Send + Sync + AsyncRead + AsyncWrite + Unpin + 'static>(self, stream: &mut S) -> Result<HttpsResponse, SimpleError> {
        Self::scan(stream).await
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
