use std::io;
use std::net::Ipv4Addr;
use std::path::Path;

use bytes::Buf;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::MacAddr;

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

    pub async fn insert(&mut self, mac: MacAddr, ip: Ipv4Addr) -> io::Result<()> {
        let mut buf = Vec::new();
        buf.extend(mac.octets());
        buf.extend(ip.octets());
        self.file.write_all(&buf).await
    }

    pub async fn iter(&mut self) -> io::Result<Vec<(MacAddr, Ipv4Addr)>> {
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

            buf.copy_to_slice(&mut mac);
            buf.copy_to_slice(&mut ip);

            entries.push((
                MacAddr::from_octets(mac),
                Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
            ));
        }

        Ok(entries)
    }

    pub async fn remove(&mut self, mac: MacAddr) -> io::Result<()> {
        let mut entries = self.iter().await?;
        self.file.set_len(0).await?;

        entries.retain(|(m, _)| *m != mac);

        for (mac, ip) in entries {
            self.insert(mac, ip).await?;
        }

        Ok(())
    }
}
