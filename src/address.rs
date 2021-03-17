use std::{ops::Range, str::FromStr};

use reqwest::Proxy;

use crate::error::*;
use crate::config::GLOBAL_CONFIG;

pub fn parse_ipv4_cidr(addr: &str) -> Result<Range<u32>, SimpleError> {
    let slices: Vec<&str> = addr.split("/").collect();
    if slices.len() < 2 {
        log::warn!("Invalid CIDR address");
        Err("Invalid CIDR address.")?
    } else {
        let base_ip: u32 = std::net::Ipv4Addr::from_str(slices[0]).unwrap()
            .into();

        let cidr: i32 = slices[1].parse().unwrap();
        let offset = 32 - cidr;
        Ok(base_ip..base_ip + (1 << offset))
    }
}

pub async fn fetch_address_list(url: &str) -> Result<Vec<Range<u32>>, SimpleError> {
    log::info!("{}", url);
    let mut builder = reqwest::Client::builder();
    if let Some(proxy_addr) = &GLOBAL_CONFIG.proxy {
        builder = builder.proxy(Proxy::http(proxy_addr)?)
            .proxy(Proxy::https(proxy_addr)?);
    }

    let client = builder.build()?;
    let body = client.get(url).send().await?.text().await?;
    Ok(body.split_whitespace()
        .filter_map(|addr|parse_ipv4_cidr(addr).ok())
        .collect())
}