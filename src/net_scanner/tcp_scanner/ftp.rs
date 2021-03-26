use tokio::{io::{AsyncRead, AsyncWrite, AsyncWriteExt}, sync::mpsc::Sender};
use serde::{Serialize};

use crate::{error::*, net_scanner::scanner::{ScanResult, ScannerResources, Scheduler, TaskPool}};
use crate::config::GLOBAL_CONFIG;

use super::async_reader::AsyncBufReader;

pub struct FTPScanTask {
    pub host: String,
    pub port: u16,
    pub resources: ScannerResources,
}
impl FTPScanTask {
    pub async fn start(self) {
        let proxy_addr;
        let result = if GLOBAL_CONFIG.scanner.ftp.use_proxy {
            let mut proxy = self.resources.proxy_pool.get_socks5_proxy(&format!("{}:{}", &self.host, self.port)).await;
            
            proxy_addr = proxy.addr.clone();
            Self::scan(&mut proxy).await
        } else {
            panic!("Not implement");
        };

        let result = ScanResult::<FTPScanResult>::from(result);
        self.resources.result_handler.save(&format!("tcp.{}.ftp", self.port), &self.host, &proxy_addr, result).await;
    }
    async fn scan<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<FTPScanResult, SimpleError> {
        let mut stream = FTPStream(stream);
        let result = match stream.read_response().await? {
            (230, text) => FTPScanResult {
                handshake_code: 230,
                handshake_text: text,
                access: FTPAccess::NoLogin,
            },
            (220, text) => FTPScanResult {
                handshake_code: 220,
                handshake_text: text,
                access: Self::try_login_anonymouse(&mut stream).await?,
            },
            (code, text) => FTPScanResult {
                handshake_code: code,
                handshake_text: text,
                access: FTPAccess::Failed,
            },
        };
        stream.0.shutdown().await.log_warn_consume("ftp-scanner");
        Ok(result)
    }

    async fn try_login_anonymouse<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut FTPStream<'_, S>) -> Result<FTPAccess, SimpleError> {
        match stream.send_cmd("USER anonymous").await? {
            (230, _) => return Ok(FTPAccess::Anonymous),
            (331, _) => (),
            _ => return Ok(FTPAccess::Login),
        }
        match stream.send_cmd("PASS guest").await? {
            (230, _) => return Ok(FTPAccess::Anonymous),
            _ => (),
        }
        match stream.send_cmd("USER anonymous").await? {
            (230, _) => return Ok(FTPAccess::Anonymous),
            (331, _) => (),
            _ => return Ok(FTPAccess::Login),
        }
        match stream.send_cmd("PASS nouser@example.com").await? {
            (230, _) => return Ok(FTPAccess::AnonymousEmail),
            _ => (),
        }
        Ok(FTPAccess::Login)
    }

}

struct FTPStream<'s, S>(pub &'s mut S);

impl<'s, S: AsyncRead + Unpin> FTPStream<'s, S> {
    
    async fn read_response(&mut self) -> Result<(i16, String), SimpleError> {
        let mut reader = AsyncBufReader::new(&mut self.0);

        let line = reader.read_line_crlf().await?;
        if line.len() < 6 {
            Err("Invalid response line")?
        }
        let code: i16 = std::str::from_utf8(&line[..3])?.parse()?;
        let msg = match line[3] {
            b' ' => std::str::from_utf8(&line[4..line.len() - 2])?.to_owned(),
            b'-' => std::str::from_utf8(&line[4..])?.to_owned() + &Self::read_to_end(code, &mut reader).await?,
            _ => Err("Invalid response line")?,
        };

        Ok((code, msg))
    }
    async fn read_to_end(code: i16, reader: &mut AsyncBufReader<'_, &mut S>) -> Result<String, SimpleError> {
        let last_line = false;
        let mut string_buf = String::with_capacity(256);
        while !last_line {
            let line = reader.read_line_crlf().await?;
            match std::str::from_utf8(&line[..3])?.parse::<i16>() {
                Ok(read_code) if read_code == code => {
                    string_buf.push_str(std::str::from_utf8(&line[4..line.len() - 2])?);
                    break;
                },
                _ => string_buf.push_str(std::str::from_utf8(&line[..])?)
            }
        }

        Ok(string_buf)
    }
}

impl<'s, S: AsyncRead + AsyncWrite + Unpin> FTPStream<'s, S> {
    async fn send_cmd(&mut self, cmd: &str) -> Result<(i16, String), SimpleError> {
        self.0.write_all(cmd.as_bytes()).await?;
        self.0.write_all(b"\r\n").await?;
        self.read_response().await
    }
}

#[derive(Serialize)]
pub struct FTPScanResult {
    pub handshake_code: i16,
    pub handshake_text: String,
    pub access: FTPAccess,
}

#[derive(Serialize, PartialEq, Debug)]
pub enum FTPAccess {
    Failed,
    Login,
    NoLogin,
    Anonymous,
    AnonymousEmail,
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::config::GLOBAL_CONFIG;

    #[tokio::test]
    async fn test_ftp_response_parser() {
        let single_line = b"\x32\x32\x30\x20\x57\x65\x6c\x63\x6f\x6d\x65\x20\x74\x6f\x20\x47\
\x41\x49\x4e\x45\x54\x20\x46\x54\x50\x20\x73\x65\x72\x76\x69\x63\
\x65\x2e\x0d\x0a";
        let (code, msg) = FTPStream(&mut &single_line[..]).read_response().await.unwrap();
        assert_eq!(220, code);
        assert_eq!("Welcome to GAINET FTP service.", msg);

        let multi_line = b"123-First line\r\n\
Second line\r\n\
234 A line beginning with numbers\r\n\
123 The last line\r\n";
        let expected_msg = "First line\r\n\
Second line\r\n\
234 A line beginning with numbers\r\n\
The last line";
        let (code, msg) = FTPStream(&mut &multi_line[..]).read_response().await.unwrap();
        assert_eq!(123, code);
        assert_eq!(expected_msg, msg);
    }

    #[tokio::test]
    async fn test_ftp_scanner() {
        let hostname = GLOBAL_CONFIG.test.as_ref().and_then(|m|m.get("test-ftp")).unwrap();

        let mut stream = tokio::net::TcpStream::connect((hostname.as_str(), 21)).await.unwrap();
        let result = FTPScanTask::scan(&mut stream).await.unwrap();
        assert_eq!(FTPAccess::Login, result.access);
    }
}