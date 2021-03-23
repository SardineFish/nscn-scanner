use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, Result as IOResult};

use crate::error::SimpleError;

use super::async_reader::AsyncBufReader;


struct SSHScannResult {
    protocol: ProtocolVersionMessage,
    algorithm: AlgorithmExchange,
}
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
}