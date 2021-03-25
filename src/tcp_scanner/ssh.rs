use tokio::io::{ AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use serde::{Serialize};

use crate::error::{LogError, SimpleError};
use crate::config::GLOBAL_CONFIG;
use super::async_reader::AsyncBufReader;

struct SSHScanTask {
    host: String,
    port: u16,
}

const SSH_PROTOCOL_VERSION: &[u8] = b"SSH-2.0-OpenSSH_for_Windows_7.7\r\n";

impl SSHScanTask {
    async fn scan(&self) -> Result<SSHScannResult, SimpleError> {
        let mut stream = tokio::net::TcpStream::connect((self.host.as_str(), self.port)).await?;
        stream.write_all(SSH_PROTOCOL_VERSION).await?;

        let result = SSHScannResult {
            protocol: ProtocolVersionMessage::read(&mut stream).await?,
            algorithm: AlgorithmExchange::read(&mut stream).await?,
        };
        stream.shutdown().await.log_warn_consume("ssh-scan");
        Ok(result)
    }
}

#[derive(Debug, Serialize)]
pub struct SSHScannResult {
    protocol: ProtocolVersionMessage,
    algorithm: AlgorithmExchange,
}

#[derive(Debug, Serialize)]
struct ProtocolVersionMessage {
    version: String,
    software: String,
    comments: String,
}
impl ProtocolVersionMessage {
    pub async fn read<R: AsyncRead + Unpin>(stream: &mut R) -> Result<Self, SimpleError> {
        let mut reader = AsyncBufReader::new(stream);
        let ignore_line = true;
        while ignore_line
        {
            let line = reader.read_line_crlf().await?;
            if line.len() == 0 {
                return Err("End of socket")?;
            } else if line.starts_with(b"SSH") {
                return Self::parse(line);
            }
        }
        
        Err("")?
    }
    pub async fn write<W: AsyncWrite + Unpin>(&self, stream: &mut W) -> Result<(), SimpleError> {
        stream.write_all(b"SSH-").await?;
        stream.write_all(self.version.as_bytes()).await?;
        stream.write_all(b"-").await?;
        stream.write_all(self.software.as_bytes()).await?;
        if self.comments.len() > 0 {
            stream.write_all(b" ").await?;
            stream.write_all(self.comments.as_bytes()).await?;
        }
        stream.write_all(b"\r\n").await?;
        Ok(())
    }
    pub fn parse(line: &[u8]) -> Result<Self, SimpleError> {
        if line.len() < 2 {
            Err("Invalid protocol version")?
        }
        let line = &line[..line.len() - 2];
        let mut split = std::str::from_utf8(line)?.split(' ');
        let protocol_and_software = split.next().ok_or(SimpleError::new("Invalid protocol version"))?;
        let comments = split.next().unwrap_or("");

        let mut split = protocol_and_software.split('-');
        let _ssh = split.next().ok_or(SimpleError::new("Invalid protocol version"))?;
        let protocol_version = split.next().ok_or(SimpleError::new("Invalid protocol version"))?;
        let software_version = split.next().ok_or(SimpleError::new("Invalid protocol version"))?;
        Ok(Self {
            version: protocol_version.to_owned(),
            software: software_version.to_owned(),
            comments: comments.to_owned(),
        })
    }
}

#[derive(Debug, Serialize, PartialEq)]
struct AlgorithmExchange {
    kex: Vec<String>,
    host_key: Vec<String>,
    encryption_client_to_server: Vec<String>,
    encryption_server_to_client: Vec<String>,
    mac_client_to_server: Vec<String>,
    mac_server_to_client: Vec<String>,
    compression_client_to_server: Vec<String>,
    compression_server_to_client: Vec<String>,
    languages_client_to_server: Vec<String>,
    languages_server_to_client: Vec<String>,
}

impl AlgorithmExchange {
    pub async fn read<R: AsyncRead + Unpin>(stream: &mut R) -> Result<AlgorithmExchange, SimpleError> {
        let packet = Self::read_packet(stream).await?;

        Self::parse_packet(&packet[..]).await
    }
    async fn parse_packet(mut packet: &[u8]) -> Result<Self, SimpleError> {
        let msg_type = packet.read_u8().await?;
        if msg_type != 20 {
            Err("Invalid message type")?
        }
        let _cookie = packet.read_u128().await?;
        Ok(Self {
            kex: Self::parse_name_list(&mut packet).await?,
            host_key: Self::parse_name_list(&mut packet).await?,
            encryption_client_to_server: Self::parse_name_list(&mut packet).await?,
            encryption_server_to_client: Self::parse_name_list(&mut packet).await?,
            mac_client_to_server: Self::parse_name_list(&mut packet).await?,
            mac_server_to_client: Self::parse_name_list(&mut packet).await?,
            compression_client_to_server: Self::parse_name_list(&mut packet).await?,
            compression_server_to_client: Self::parse_name_list(&mut packet).await?,
            languages_client_to_server: Self::parse_name_list(&mut packet).await?,
            languages_server_to_client: Self::parse_name_list(&mut packet).await?,
        })
    }
    async fn parse_name_list(packet: &mut &[u8]) -> Result<Vec<String>, SimpleError> {
        let byte_size = packet.read_u32().await? as usize;
        let (content, rest) = packet.split_at(byte_size);
        *packet = rest;
        let name_list = std::str::from_utf8(content)?;
        
        Ok(name_list.split(',').map(|name| name.to_owned()).collect())

    }
    // Ref: https://tools.ietf.org/html/rfc4253#section-6.1
    async fn read_packet<R: AsyncRead + Unpin>(stream: &mut R) -> Result<Vec<u8>, SimpleError> {
        let packet_length = stream.read_u32().await? as usize;
        let padding_length = stream.read_u8().await? as usize;
        let payload_length = packet_length - padding_length - 1;
        let mut buf: Vec<u8> = vec![0; packet_length - 1];
        stream.read_exact(&mut buf).await?;
        buf.resize(payload_length, 0);

        Ok(buf)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[tokio::test]
    async fn test_protocol_version_with_comment() {
        let buf = b"SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\r\n";
        let protocol = ProtocolVersionMessage::read(&mut &buf[..]).await.unwrap();
        assert_eq!("2.0", protocol.version);
        assert_eq!("OpenSSH_7.9p1", protocol.software);
        assert_eq!("Debian-10+deb10u2", protocol.comments);
    }

    #[tokio::test]
    async fn test_protocol_version_without_comment() {
        let buf = b"SSH-2.0-billsSSH_3.6.3q3\r\n";
        let protocol = ProtocolVersionMessage::read(&mut &buf[..]).await.unwrap();
        assert_eq!("2.0", protocol.version);
        assert_eq!("billsSSH_3.6.3q3", protocol.software);
        assert_eq!("", protocol.comments);
    }

    #[tokio::test]
    async fn test_algorithm_parse() {
        let kex_init = AlgorithmExchange::read(&mut &SSH_KEXINIT_DATA[..]).await.unwrap();
        println!("{:?}", kex_init);
    }

    #[tokio::test]
    async fn test_ssh_scanner() {
        let kex_init = AlgorithmExchange::read(&mut &SSH_KEXINIT_DATA[..]).await.unwrap();
        let addr = GLOBAL_CONFIG.test.as_ref().and_then(|m|m.get("test-ssh")).unwrap();
        let task = SSHScanTask {
            host: addr.to_owned(),
            port: 22,
        };
        let result = task.scan().await.unwrap();
        println!("{:?}", result);
        assert_eq!(kex_init, result.algorithm);
    }

    const SSH_KEXINIT_DATA: &[u8; 1080] = b"\x00\x00\x04\x34\x06\x14\x5d\x44\xad\xae\x71\xd1\x9f\x37\xca\x0e\
\xd4\x51\xa3\x3e\x40\xcd\x00\x00\x01\x02\x63\x75\x72\x76\x65\x32\
\x35\x35\x31\x39\x2d\x73\x68\x61\x32\x35\x36\x2c\x63\x75\x72\x76\
\x65\x32\x35\x35\x31\x39\x2d\x73\x68\x61\x32\x35\x36\x40\x6c\x69\
\x62\x73\x73\x68\x2e\x6f\x72\x67\x2c\x65\x63\x64\x68\x2d\x73\x68\
\x61\x32\x2d\x6e\x69\x73\x74\x70\x32\x35\x36\x2c\x65\x63\x64\x68\
\x2d\x73\x68\x61\x32\x2d\x6e\x69\x73\x74\x70\x33\x38\x34\x2c\x65\
\x63\x64\x68\x2d\x73\x68\x61\x32\x2d\x6e\x69\x73\x74\x70\x35\x32\
\x31\x2c\x64\x69\x66\x66\x69\x65\x2d\x68\x65\x6c\x6c\x6d\x61\x6e\
\x2d\x67\x72\x6f\x75\x70\x2d\x65\x78\x63\x68\x61\x6e\x67\x65\x2d\
\x73\x68\x61\x32\x35\x36\x2c\x64\x69\x66\x66\x69\x65\x2d\x68\x65\
\x6c\x6c\x6d\x61\x6e\x2d\x67\x72\x6f\x75\x70\x31\x36\x2d\x73\x68\
\x61\x35\x31\x32\x2c\x64\x69\x66\x66\x69\x65\x2d\x68\x65\x6c\x6c\
\x6d\x61\x6e\x2d\x67\x72\x6f\x75\x70\x31\x38\x2d\x73\x68\x61\x35\
\x31\x32\x2c\x64\x69\x66\x66\x69\x65\x2d\x68\x65\x6c\x6c\x6d\x61\
\x6e\x2d\x67\x72\x6f\x75\x70\x31\x34\x2d\x73\x68\x61\x32\x35\x36\
\x2c\x64\x69\x66\x66\x69\x65\x2d\x68\x65\x6c\x6c\x6d\x61\x6e\x2d\
\x67\x72\x6f\x75\x70\x31\x34\x2d\x73\x68\x61\x31\x00\x00\x00\x41\
\x72\x73\x61\x2d\x73\x68\x61\x32\x2d\x35\x31\x32\x2c\x72\x73\x61\
\x2d\x73\x68\x61\x32\x2d\x32\x35\x36\x2c\x73\x73\x68\x2d\x72\x73\
\x61\x2c\x65\x63\x64\x73\x61\x2d\x73\x68\x61\x32\x2d\x6e\x69\x73\
\x74\x70\x32\x35\x36\x2c\x73\x73\x68\x2d\x65\x64\x32\x35\x35\x31\
\x39\x00\x00\x00\x6c\x63\x68\x61\x63\x68\x61\x32\x30\x2d\x70\x6f\
\x6c\x79\x31\x33\x30\x35\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\
\x6f\x6d\x2c\x61\x65\x73\x31\x32\x38\x2d\x63\x74\x72\x2c\x61\x65\
\x73\x31\x39\x32\x2d\x63\x74\x72\x2c\x61\x65\x73\x32\x35\x36\x2d\
\x63\x74\x72\x2c\x61\x65\x73\x31\x32\x38\x2d\x67\x63\x6d\x40\x6f\
\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x61\x65\x73\x32\x35\
\x36\x2d\x67\x63\x6d\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\
\x6d\x00\x00\x00\x6c\x63\x68\x61\x63\x68\x61\x32\x30\x2d\x70\x6f\
\x6c\x79\x31\x33\x30\x35\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\
\x6f\x6d\x2c\x61\x65\x73\x31\x32\x38\x2d\x63\x74\x72\x2c\x61\x65\
\x73\x31\x39\x32\x2d\x63\x74\x72\x2c\x61\x65\x73\x32\x35\x36\x2d\
\x63\x74\x72\x2c\x61\x65\x73\x31\x32\x38\x2d\x67\x63\x6d\x40\x6f\
\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x61\x65\x73\x32\x35\
\x36\x2d\x67\x63\x6d\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\
\x6d\x00\x00\x00\xd5\x75\x6d\x61\x63\x2d\x36\x34\x2d\x65\x74\x6d\
\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x75\x6d\x61\
\x63\x2d\x31\x32\x38\x2d\x65\x74\x6d\x40\x6f\x70\x65\x6e\x73\x73\
\x68\x2e\x63\x6f\x6d\x2c\x68\x6d\x61\x63\x2d\x73\x68\x61\x32\x2d\
\x32\x35\x36\x2d\x65\x74\x6d\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\
\x63\x6f\x6d\x2c\x68\x6d\x61\x63\x2d\x73\x68\x61\x32\x2d\x35\x31\
\x32\x2d\x65\x74\x6d\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\
\x6d\x2c\x68\x6d\x61\x63\x2d\x73\x68\x61\x31\x2d\x65\x74\x6d\x40\
\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x75\x6d\x61\x63\
\x2d\x36\x34\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\
\x75\x6d\x61\x63\x2d\x31\x32\x38\x40\x6f\x70\x65\x6e\x73\x73\x68\
\x2e\x63\x6f\x6d\x2c\x68\x6d\x61\x63\x2d\x73\x68\x61\x32\x2d\x32\
\x35\x36\x2c\x68\x6d\x61\x63\x2d\x73\x68\x61\x32\x2d\x35\x31\x32\
\x2c\x68\x6d\x61\x63\x2d\x73\x68\x61\x31\x00\x00\x00\xd5\x75\x6d\
\x61\x63\x2d\x36\x34\x2d\x65\x74\x6d\x40\x6f\x70\x65\x6e\x73\x73\
\x68\x2e\x63\x6f\x6d\x2c\x75\x6d\x61\x63\x2d\x31\x32\x38\x2d\x65\
\x74\x6d\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x68\
\x6d\x61\x63\x2d\x73\x68\x61\x32\x2d\x32\x35\x36\x2d\x65\x74\x6d\
\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x68\x6d\x61\
\x63\x2d\x73\x68\x61\x32\x2d\x35\x31\x32\x2d\x65\x74\x6d\x40\x6f\
\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x68\x6d\x61\x63\x2d\
\x73\x68\x61\x31\x2d\x65\x74\x6d\x40\x6f\x70\x65\x6e\x73\x73\x68\
\x2e\x63\x6f\x6d\x2c\x75\x6d\x61\x63\x2d\x36\x34\x40\x6f\x70\x65\
\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x75\x6d\x61\x63\x2d\x31\x32\
\x38\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x68\x6d\
\x61\x63\x2d\x73\x68\x61\x32\x2d\x32\x35\x36\x2c\x68\x6d\x61\x63\
\x2d\x73\x68\x61\x32\x2d\x35\x31\x32\x2c\x68\x6d\x61\x63\x2d\x73\
\x68\x61\x31\x00\x00\x00\x15\x6e\x6f\x6e\x65\x2c\x7a\x6c\x69\x62\
\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x00\x00\x00\x15\
\x6e\x6f\x6e\x65\x2c\x7a\x6c\x69\x62\x40\x6f\x70\x65\x6e\x73\x73\
\x68\x2e\x63\x6f\x6d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00";
}