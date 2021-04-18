use tokio::io::AsyncReadExt;
use std::{fmt::Write as FmtWrite, str::from_utf8};
use crate::error::*;

pub trait WriteRequest {
    fn write_request(&self) -> Result<String, SimpleError>;
}

impl<'s> WriteRequest for httparse::Request<'s, 's> {
    fn write_request(&self) -> Result<String, SimpleError> {
        let mut output = String::new();
        let method = self.method.ok_or("Invalid method")?;
        let path = self.path.ok_or("Invalid path")?;
        let version = self.version.ok_or("Invalid version")?;

        write!(&mut output, "{} {} HTTP/1.{}\r\n", method, path, version)?;
        for header in self.headers.iter() {
            write!(&mut output, "{}: {}\r\n", header.name, from_utf8(header.value)?)?;
        }
        write!(&mut output, "\r\n")?;

        Ok(output)
    }
}

pub async fn parse_from_stream<'s>(response: &mut httparse::Response<'s, 's>, stream: &mut tokio::net::TcpStream, buf: &'s mut[u8]) 
    -> Result<(), SimpleError> 
{
    let mut len = 0;
    loop {
        let recv_len: usize = stream.read(&mut buf[len..]).await?;
        if recv_len == 0 {
            if len == buf.len() {
                return Err("Buffer overflow.")?;
            } else {
                return Err("Connection closed.")?;
            }
        }
        len += recv_len;
        if len >= 4 {
            if &buf[len-4..len] == b"\r\n\r\n" {
                break;
            }
        }
    }
    response.parse(buf)?;
    Ok(())
}