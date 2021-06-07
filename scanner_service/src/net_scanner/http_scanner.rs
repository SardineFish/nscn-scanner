use std::{collections::HashMap, pin::Pin, sync::atomic::AtomicPtr, task::{Context, Poll}};

use http_types::{Url, headers::HeaderValues};
use reqwest::{ header::HeaderMap};
use serde::{Serialize, Deserialize};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use crate::{error::SimpleError};

use super::{scanner::ScanTask};

#[derive(Serialize, Deserialize, Debug)]
pub struct HttpResponseData {
    pub status: i32,
    pub headers: HashMap<String, String>,
    pub body: String,
}

trait SerializeHeaders {
    fn serialize(&self) -> HashMap<String, Vec<String>>;
}

impl SerializeHeaders for HeaderMap {
    fn serialize(&self) -> HashMap<String, Vec<String>> {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for key in self.keys() {
            let values = self.get_all(key).iter()
                .filter_map(|value| value.to_str().ok().map(str::to_owned))
                .collect();
            map.insert(key.to_string(), values);
        }
        map
    }
}

fn stringify_header_values(values: HeaderValues) -> String {
    values.into_iter()
        .map(|v|v.as_str())
        .collect::<Vec::<_>>()
        .join(",")
}

pub struct HttpScanTask(pub String, pub u16);

#[async_trait::async_trait]
impl ScanTask<HttpResponseData> for HttpScanTask {
    async fn scan<S: Send + Sync + AsyncRead + AsyncWrite + Unpin + 'static>(self, stream: &mut S) -> Result<HttpResponseData, SimpleError> {
        let url = Url::parse(&format!("http://{}:{}/", self.0, self.1))?;
        let request = http_types::Request::new(http_types::Method::Get, url);
        let mut response = async_h1::connect(UnsafeStreamWrapper::from(stream), request).await?;

        log::info!("{}/HTTP was opened at {}", self.1, self.0);
        
        Ok(HttpResponseData{
            status: u16::from(response.status()) as i32,
            body: response.take_body().into_string().await?,
            headers: response.into_iter()
                .map(|(name, values)| (name.to_string(), stringify_header_values(values)))
                .collect()
        })
    }

    fn scanner_name() -> &'static str {
        "http"
    }
}

struct UnsafeStreamWrapper<S>(AtomicPtr<S>);

impl<S> From<&mut S> for UnsafeStreamWrapper<S> {
    fn from(stream: &mut S) -> Self {
        Self(AtomicPtr::new(stream))
    }
}

impl<S> futures::AsyncRead for UnsafeStreamWrapper<S> where S : AsyncRead + Unpin + 'static {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, io::Error>> {
        let stream = Pin::new(unsafe{self.0.get_mut().as_mut()}.expect("Invalid stream reference") as &'static mut S);
        let mut buf = ReadBuf::new(buf);
        match stream.poll_read(cx, &mut buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.filled().len())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> futures::AsyncWrite for UnsafeStreamWrapper<S> where S: AsyncWrite + Unpin + 'static {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        let stream = Pin::new(unsafe{self.0.get_mut().as_mut()}.expect("Invalid stream reference") as &'static mut S);
        stream.poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let stream = Pin::new(unsafe{self.0.get_mut().as_mut()}.expect("Invalid stream reference") as &'static mut S);
        stream.poll_flush(cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let stream = Pin::new(unsafe{self.0.get_mut().as_mut()}.expect("Invalid stream reference") as &'static mut S);
        stream.poll_shutdown(cx)
    }
}