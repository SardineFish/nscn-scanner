use std::sync::Arc;

use shadowsocks::{self, ProxyClientStream, ServerConfig, context::Context};

use crate::{SSProxyConfig, error::SimpleError, net_scanner::scanner::Connector};

pub type SSProxyStream = ProxyClientStream<shadowsocks::net::TcpStream>;

#[derive(Clone)]
pub struct SSProxy {
    pub(super) ctx: Arc<Context>,
    pub cfg: &'static ServerConfig,
}

#[async_trait::async_trait]
impl Connector<SSProxyStream> for SSProxy {
    async fn connect(self, addr: &str, port: u16) -> Result<SSProxyStream, SimpleError> {
        let stream = ProxyClientStream::connect(self.ctx, &self.cfg, (addr.to_owned(), port)).await?;
        Ok(stream)
    }
}