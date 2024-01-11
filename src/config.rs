use std::net::Ipv4Addr;
use std::path::Path;

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub local_addr: Ipv4Addr,
    pub routers: Vec<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub broadcast: Ipv4Addr,
    pub subnet: Ipv4Addr,
}

impl Config {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let string = std::fs::read_to_string(path)?;
        let config = toml::from_str(&string)?;
        Ok(config)
    }
}
