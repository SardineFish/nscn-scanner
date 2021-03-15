use std::{ops::Range, str::FromStr};

use crate::error::*;

pub fn parse_ipv4_cidr(addr: &str) -> Result<Range<u32>, ErrorMsg> {
    let slices: Vec<&str> = addr.split("/").collect();
    if slices.len() < 2 {
        Err("Invalid CIDR address.")?
    } else {
        let base_ip: u32 = std::net::Ipv4Addr::from_str(slices[0])?
            .into();

        let cidr: i32 = slices[1].parse()?;
        let offset = 32 - cidr;
        Ok(base_ip..base_ip + (1 << offset))
    }
}

