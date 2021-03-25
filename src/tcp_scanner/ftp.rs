use tokio::io::AsyncRead;

use crate::error::*;

use super::async_reader::AsyncBufReader;

pub struct FTPScanTask {
    host: String,
    port: i16,
}
impl FTPScanTask {
    pub async fn read_response<R: AsyncRead + Unpin>(stream: &mut R) -> Result<(i16, String), SimpleError> {
        let mut reader = AsyncBufReader::new(stream);

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
    async fn read_to_end<R: AsyncRead + Unpin>(code: i16, reader: &mut AsyncBufReader<'_, R>) -> Result<String, SimpleError> {
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

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_ftp_response_parser() {
        let single_line = b"\x32\x32\x30\x20\x57\x65\x6c\x63\x6f\x6d\x65\x20\x74\x6f\x20\x47\
\x41\x49\x4e\x45\x54\x20\x46\x54\x50\x20\x73\x65\x72\x76\x69\x63\
\x65\x2e\x0d\x0a";
        let (code, msg) = FTPScanTask::read_response(&mut &single_line[..]).await.unwrap();
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
        let (code, msg) = FTPScanTask::read_response(&mut &multi_line[..]).await.unwrap();
        assert_eq!(123, code);
        assert_eq!(expected_msg, msg);
    }
}