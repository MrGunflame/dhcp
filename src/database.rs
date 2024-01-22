use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, SystemTime};

use bytes::Buf;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{Lease, MacAddr};

#[derive(Debug)]
pub struct Database {
    file: File,
}

impl Database {
    pub async fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).read(true);

        let file = opts.open(path).await?;

        Ok(Self { file })
    }

    pub async fn insert(&mut self, lease: Lease) -> io::Result<()> {
        let mut buf = Vec::new();
        buf.extend(lease.mac.octets());
        buf.extend(lease.ip.octets());
        buf.extend(
            lease
                .valid_until
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_le_bytes(),
        );
        self.file.write_all(&buf).await
    }

    pub async fn iter(&mut self) -> io::Result<Vec<Lease>> {
        let mut buf = Vec::new();
        self.file.read_to_end(&mut buf).await?;
        let mut buf = &buf[..];

        let mut entries = Vec::new();
        while !buf.is_empty() {
            if buf.remaining() < 6 + 4 {
                todo!();
            };

            let mut mac = [0; 6];
            let mut ip = [0; 4];
            let mut valid_until = [0; 8];

            buf.copy_to_slice(&mut mac);
            buf.copy_to_slice(&mut ip);
            buf.copy_to_slice(&mut valid_until);

            entries.push(Lease {
                mac: MacAddr::from_octets(mac),
                ip: Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
                valid_until: SystemTime::UNIX_EPOCH
                    + Duration::from_secs(u64::from_le_bytes(valid_until)),
            });
        }

        Ok(entries)
    }

    pub async fn remove(&mut self, mac: MacAddr) -> io::Result<()> {
        let mut entries = self.iter().await?;
        self.file.set_len(0).await?;

        entries.retain(|lease| lease.mac != mac);

        for lease in entries {
            self.insert(lease).await?;
        }

        Ok(())
    }
}
