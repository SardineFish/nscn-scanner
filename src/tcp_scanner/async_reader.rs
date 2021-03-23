use std::{cmp::{ min}, pin::Pin, task::{Context, Poll}};

use tokio::io::{self, AsyncRead, AsyncReadExt, ReadBuf};
use bytes::BytesMut;

use crate::error::*;

pub struct AsyncBufReader<'r, R> {
    stream: &'r mut R,
    buf: BytesMut,
    buf_offset: usize,
}

impl<'r, R: AsyncRead + Unpin> AsyncBufReader<'r, R> {
    pub fn new(stream: &'r mut R) -> Self {
        Self { 
            stream,
            buf: BytesMut::with_capacity(1024),
            buf_offset: 0,
        }
    }
    pub async fn read_line_crlf(&mut self) -> Result<&[u8], SimpleError> {
        let mut scan_start = self.buf_offset;
        println!("start at {}", scan_start);
        loop {
            let limit = match self.buf.len() {
                0 => 0,
                _ => self.buf.len() - 1,
            };
            for i in scan_start..limit {
                if self.buf[i] == b'\r' && self.buf[i + 1] == b'\n' {
                    let start = self.buf_offset;
                    self.buf_offset = i + 2;
                    return Ok(&self.buf[start..self.buf_offset]);
                }
                scan_start = i;
            }
            let size = self.stream.read_buf(&mut self.buf).await?;
            println!("read {}", size);
            if size == 0 {
                return Ok(&self.buf[0..0])
            }
        }
    }
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.buf_offset
    }
}

impl<'r, R: AsyncRead + Unpin> AsyncRead for AsyncBufReader<'r, R> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let buf_len = self.buf.len() - self.buf_offset;
        if buf_len > 0 {
            let read_len = min(buf_len, buf.remaining());
            buf.put_slice(&self.buf[self.buf_offset..self.buf_offset + read_len]);
            self.buf_offset += read_len;
            if self.buf.len() - self.buf_offset <= 0 {
                self.buf_offset = 0;
                self.buf.clear();
            }
            Poll::Ready(Ok(()))
        } else {
            let pin = Pin::new(&mut self.stream);
            pin.poll_read(cx, buf)
        }

    }
}

#[cfg(test)]
mod test {
    use super::AsyncBufReader;

    #[tokio::test]
    async fn test_async_reader()
    {
        let mut file = tokio::fs::File::open("./data/test.txt").await.unwrap();
        let mut reader = AsyncBufReader::new(&mut file);
        let line = reader.read_line_crlf().await.unwrap();
        assert_eq!(b"ABCD\r\n", line);
        let line = reader.read_line_crlf().await.unwrap();
        assert_eq!(b"EFGHI\r\n", line);
        let line = reader.read_line_crlf().await.unwrap();
        assert_eq!(b"\r\n", line);
        let line = reader.read_line_crlf().await.unwrap();
        assert_eq!(0, line.len());
    }


}