use std::{collections::HashMap, pin::Pin, sync::atomic::AtomicPtr, task::{Context, Poll}};

use http_types::Url;
use reqwest::{ Response, header::HeaderMap};
use serde::{Serialize, Deserialize};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use crate::{ScanTaskInfo, error::SimpleError, net_scanner::scheduler::{ScannerResources}, proxy::{http_proxy::HttpProxyClient}};
use crate::config::GLOBAL_CONFIG;

use super::{result_handler::ScanResult, scanner::ScanTask};

#[derive(Serialize, Deserialize, Debug)]
pub struct HttpResponseData {
    pub status: i32,
    pub headers: HashMap<String, String>,
    pub body: String,
}

impl HttpResponseData {
    // async fn from_response(response: Response) -> Self {
    //     Self {
    //         headers: response.headers().serialize(),
    //         status: response.status().as_u16() as i32,
    //         body: response.text().await.unwrap_or("Failed to parse body".to_owned()),
    //     }
    // }
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

pub struct HttpScanTask(pub String, pub u16);

// impl<'r> HttpScanTask<'r> {
//     // pub async fn dispatch(addr: &str, resources: &ScannerResources, task_pool: &mut TaskPool) {
//     //     let task = HttpScanTask {
//     //         address: addr.to_owned(),
//     //         resources: resources.clone(),
//     //     };
//     //     task_pool.spawn("http", task.run()).await;
//     // }
//     pub async fn run(addr: String, resources: &'r mut ScannerResources) {
//         let mut client = match GLOBAL_CONFIG.scanner.http.socks5 {
//             Some(true) => resources.proxy_pool.get_socks5_client().await,
//             _ => resources.proxy_pool.get_http_client().await,
//         };
//         let task = Self {
//             address: addr,
//             resources: resources
//         };
//         let result = task.scan(&mut client).await;
//         let task_result = ScanTaskInfo::with_proxy(client.proxy_addr, result);
//         task.resources.result_handler.save_scan_results("http", &task.address, &task_result).await;


//         // if  let (ScanResult::Ok(_), true) = (&task_result.result, GLOBAL_CONFIG.analyser.analyse_on_scan) {
//         //     let mut services = HashMap::<String, ServiceAnalyseResult>::new();
//         //     self.resources.analyser.web_analyser.analyse(&task_result.result, &mut services)
//         //         .await
//         //         .log_error_consume("web-analyse");

//         //     self.resources.vuln_searcher.search_all(&mut services).await;
            
//         //     self.resources.result_handler.save_analyse_results(&self.address, "web", services)
//         //         .await
//         //         .log_error_consume("web-result-saving");
//         // }
//     }
//     async fn scan(&self, client: &mut HttpProxyClient) -> ScanResult<HttpResponseData> {
//         // let proxy_addr = self.proxy_pool.get().await;
//         // let proxy = reqwest::Proxy::http(format!("http://{}", proxy_addr))?;
//         // log::debug!("Use http proxy {}", proxy_addr);
        
//         // log::info!("Http scan {} through {}", self.address, proxy_addr);


//         let result = client.client.get(format!("http://{}", self.address))
//             .send()
//             .await;
        
//         match result {
//             Ok(response) => {
//                 log::info!("GET {} - {}", self.address, response.status());
//                 ScanResult::Ok(HttpResponseData::from_response(response).await)
//             },
//             Err(err) => ScanResult::Err(err.to_string())
//         }
//     }
// }

#[async_trait::async_trait]
impl ScanTask<HttpResponseData> for HttpScanTask {
    async fn scan<S: Send + Sync + AsyncRead + AsyncWrite + Unpin + 'static>(self, stream: &mut S) -> Result<HttpResponseData, SimpleError> {
        let url = Url::parse(&format!("http://{}:{}/", self.0, self.1))?;
        let request = http_types::Request::new(http_types::Method::Get, url);
        let mut response = async_h1::connect(UnsafeStreamWrapper::from(stream), request).await?;

        Ok(HttpResponseData{
            status: u16::from(response.status()) as i32,
            body: response.take_body().into_string().await?,
            headers: response.into_iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
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