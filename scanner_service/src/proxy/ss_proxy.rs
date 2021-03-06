use std::sync::Arc;

use shadowsocks::{self, ProxyClientStream, ServerConfig, context::Context};

use crate::{error::SimpleError, net_scanner::scanner::Connector};
use crate::error::LogError;

pub type SSProxyStream = ProxyClientStream<shadowsocks::net::TcpStream>;

#[derive(Clone)]
pub struct SSProxy {
    pub(super) ctx: Arc<Context>,
    pub cfg: &'static ServerConfig,
}

#[async_trait::async_trait]
impl Connector<SSProxyStream> for SSProxy {
    async fn connect(self, addr: &str, port: u16) -> Result<SSProxyStream, SimpleError> {
        let stream = ProxyClientStream::connect(self.ctx, &self.cfg, (addr.to_owned(), port))
            .await
            .log_warn("ss-connect")?;
        Ok(stream)
    }
}

#[cfg(test)]
mod test {
    use crate::config::*;
    use crate::proxy::ss_proxy::SSProxy;
    use crate::net_scanner::scanner::Connector;
    use crate::net_scanner::http_scanner::HttpScanTask;
    use crate::net_scanner::scanner::ScanTask;

    #[tokio::test]
    async fn test_ss_proxy() {
        if let Some(cfg_list) = &GLOBAL_CONFIG.proxy.shadowsocks {
            for cfg in cfg_list {
                let proxy = SSProxy {
                    cfg,
                    ctx: shadowsocks::context::Context::new_shared(shadowsocks::config::ServerType::Local),
                };

                let mut stream = tokio::time::timeout(std::time::Duration::from_secs(5), proxy.connect("myip.top", 80))
                    .await
                    .expect(&format!("{} Timeout", cfg.addr().to_string()))
                    .unwrap();
                let result = HttpScanTask("myip.top".to_owned(), 80).scan(&mut stream).await.unwrap();
                println!("{:?}", result);
                assert_eq!(result.status, 200);
            }
        }
    }
    
}