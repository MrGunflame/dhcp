use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, SystemTime};

use bytes::Buf;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{Lease, MacAddr, ServerError};

#[derive(Debug)]
pub struct Database {
    leases: HashMap<MacAddr, Lease>,
    file: File,
}

impl Database {
    pub async fn new(path: impl AsRef<Path>) -> Result<Self, ServerError> {
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).read(true);

        let mut file = opts.open(path).await?;

        let mut buf = Vec::new();
        file.read_to_end(&mut buf).await?;
        let mut buf = &buf[..];

        let mut entries = HashMap::new();
        while !buf.is_empty() {
            let lease = Lease::decode(&mut buf)?;
            entries.insert(lease.mac, lease);
        }

        Ok(Self {
            file,
            leases: entries,
        })
    }

    pub async fn insert(&mut self, lease: Lease) -> io::Result<()> {
        self.leases.insert(lease.mac, lease);
        self.flush_data().await
    }

    pub async fn remove(&mut self, mac: MacAddr) -> io::Result<()> {
        if self.leases.remove(&mac).is_some() {
            self.flush_data().await
        } else {
            Ok(())
        }
    }

    pub fn leases(&self) -> impl Iterator<Item = Lease> + '_ {
        self.leases.values().copied()
    }

    async fn flush_data(&mut self) -> io::Result<()> {
        let mut buf = Vec::new();
        for lease in self.leases.values() {
            lease.encode(&mut buf);
        }

        self.file.set_len(0).await?;
        self.file.write_all(&buf).await?;
        Ok(())
    }
}

impl Lease {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(self.mac.octets());
        buf.extend(self.ip.octets());
        buf.extend(
            self.valid_until
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_le_bytes(),
        );
    }

    pub fn decode(buf: &mut &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < 6 + 4 + 8 {
            return Err(DecodeError);
        }

        let mut mac = [0; 6];
        let mut ip = [0; 4];
        let mut valid_until = [0; 8];

        buf.copy_to_slice(&mut mac);
        buf.copy_to_slice(&mut ip);
        buf.copy_to_slice(&mut valid_until);

        Ok(Self {
            mac: MacAddr::from_octets(mac),
            ip: Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
            valid_until: SystemTime::UNIX_EPOCH
                + Duration::from_secs(u64::from_le_bytes(valid_until)),
        })
    }
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("decode error")]
pub struct DecodeError;
