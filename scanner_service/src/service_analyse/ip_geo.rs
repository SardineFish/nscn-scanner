use std::{collections::HashMap, sync::Arc};

use ip2region::{IpInfo};
use serde::{Serialize, Deserialize};

use crate::error::SimpleError;

#[derive(Clone)]
pub struct IP2Geo {
    geo_data: Arc<HashMap<String, GeoData>>,
}

impl IP2Geo {
    pub fn from_json(city_data_json: &str) -> Result<Self, SimpleError> {
        let json_data = std::fs::read_to_string(city_data_json)?;
        Ok(Self {
            geo_data: Arc::new(serde_json::from_str(&json_data)?),
        })
    }
    pub fn search_ip(&self, ip: &str) -> Option<IPGeoData> {
        let info = ip2region::memory_search(ip).ok()?;
        let mut geo = IPGeoData::from(info);
        if let Some(city) = self.geo_data.get(&geo.city) {
            geo.coord = Some(city.center.clone());
        } else {
            // log::warn!("Unknown IP Geo {}:{}>{}>{}>{}", geo.citycode, geo.country, geo.region, geo.province, geo.city);
        }
        Some(geo)
    }
}

#[derive(Deserialize)]
struct GeoData {
    citycode: i32,
    adcode: i32,
    center: [f64; 2],
    name: String,
}

#[derive(Serialize, Deserialize)]
pub struct IPGeoData {
    pub citycode: i32,
    pub coord: Option<[f64; 2]>,
    pub country: String,
    pub province: String,
    pub isp: String,
    pub region: String,
    pub city: String,
}
impl<'s> From<IpInfo<'s>> for IPGeoData {
    fn from(info: IpInfo<'s>) -> Self {
        Self {
            citycode: info.city_id as i32,
            city: info.city.to_owned(),
            coord: Some([0.0, 0.0]),
            country: info.country.to_owned(),
            isp: info.ISP.to_owned(),
            province: info.province.to_owned(),
            region: info.region.to_owned(),
        }
    }
}