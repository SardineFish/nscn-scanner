use std::{ops::Range, str::FromStr, time::Duration};

use reqwest::Proxy;

use crate::error::*;
use crate::config::GLOBAL_CONFIG;

pub fn parse_ipv4_cidr(cidr: &str) -> Result<Range<u32>, SimpleError> {
    let slices: Vec<&str> = cidr.split("/").collect();
    if slices.len() < 2 {
        log::warn!("Invalid CIDR address");
        Err("Invalid CIDR address.")?
    } else {
        let base_ip: u32 = std::net::Ipv4Addr::from_str(slices[0])?
            .into();

        let cidr: i32 = slices[1].parse().unwrap();
        match cidr {
            0 => Ok(0..u32::max_value()),
            cidr => Ok(base_ip..base_ip + (1 << (32 - cidr)))
        }
    }
}

pub async fn fetch_address_list(url: &str) -> Result<Vec<String>, SimpleError> {
    log::info!("{}", url);
    let mut builder = reqwest::Client::builder();
    if let Some(proxy_addr) = &GLOBAL_CONFIG.scanner.task.proxy {
        builder = builder.proxy(Proxy::http(proxy_addr)?)
            .proxy(Proxy::https(proxy_addr)?);
    }
    builder = builder.timeout(Duration::from_secs(3));

    let client = builder.build()?;
    let body = client.get(url).send().await?.text().await?;
    Ok(body.split_whitespace()
        .map(|addr| addr.to_owned())
        .collect())
}