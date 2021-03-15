use std::{ops::Range, str::FromStr};

use reqwest::Proxy;

use crate::error::*;
use crate::config::GLOBAL_CONFIG;

pub fn parse_ipv4_cidr(addr: &str) -> Result<Range<u32>, ErrorMsg> {
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

pub async fn fetch_address_list(url: &str) -> Result<Vec<Range<u32>>, ErrorMsg> {
    log::info!("{}", url);
    let client = reqwest::Client::builder()
        .proxy(Proxy::http(&GLOBAL_CONFIG.proxy)?)
        .proxy(Proxy::https(&GLOBAL_CONFIG.proxy)?)
        .build()?;
    let body = client.get(url).send().await?.text().await?;
    Ok(body.split_whitespace()
        .filter_map(|addr|parse_ipv4_cidr(addr).ok())
        .collect())
}