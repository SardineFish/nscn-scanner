use serde::{Deserialize};
use tokio::fs::read_to_string;
use crate::error::*;

#[derive(Deserialize)]
pub struct Config {
    pub proxy_pool: String,
    pub mongodb: String,
    pub redis: String,
    pub addr_src: Vec<String>,
}

impl Config {
    pub async fn from_file(path: &str) -> Result<Self, ErrorMsg> {
        let data = read_to_string(path).await?;
        Ok(serde_json::from_str(&data)?)
    }
}