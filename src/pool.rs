use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::Ipv4Addr;

use crate::{MacAddr, Op};

#[derive(Clone, Debug)]
pub struct Pool {
    leases: HashMap<MacAddr, Ipv4Addr>,
    addrs: HashSet<Ipv4Addr>,
}

impl Pool {
    pub fn new(leases: HashMap<MacAddr, Ipv4Addr>) -> Self {
        let mut addrs = HashSet::with_capacity(leases.len());
        for addr in leases.values() {
            addrs.insert(*addr);
        }

        Self { leases, addrs }
    }

    pub fn request_addr(&mut self, mac: MacAddr, ip: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        if let Some(ip) = ip {
            if !self.addrs.contains(&ip) && self.is_valid_ip(ip) {
                self.leases.insert(mac, ip);
                self.addrs.insert(ip);

                return Some(ip);
            }
        }

        let ip = self.generate_ip()?;
        self.leases.insert(mac, ip);
        Some(ip)
    }

    pub fn mac_has_ip(&self, mac: MacAddr, ip: Ipv4Addr) -> bool {
        if let Some(addr) = self.leases.get(&mac) {
            *addr == ip
        } else {
            false
        }
    }

    pub fn release_addr(&mut self, mac: MacAddr) {
        if let Some(ip) = self.leases.remove(&mac) {
            self.addrs.remove(&ip);
        }
    }

    fn generate_ip(&mut self) -> Option<Ipv4Addr> {
        Some(Ipv4Addr::new(192, 168, 122, 10))
    }

    fn is_valid_ip(&self, ip: Ipv4Addr) -> bool {
        true
    }
}

#[derive(Clone, Debug)]
struct Allocator {
    range: Ipv4Range,
    /// Sorted list of free blocks.
    blocks: Vec<Block>,
}

impl Allocator {
    pub fn new(range: Ipv4Range) -> Self {
        Self {
            blocks: vec![Block {
                start: range.start,
                len: range.len(),
            }],
            range,
        }
    }

    pub fn request(&mut self, ip: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        if let Some(ip) = ip {
            for (index, block) in self.blocks.iter_mut().enumerate() {
                // Ip is in this block.
                dbg!(block.contains(ip));
                if block.contains(ip) {
                    // Block only contains one address. Claim the address
                    // and remove the block.
                    if block.len == 1 {
                        self.blocks.remove(index);
                        return Some(ip);
                    }

                    // Block starts with the requested address.
                    // Bump it once to move the cursor forwards.
                    if block.start == ip {
                        block.bump();
                        return Some(ip);
                    }

                    // Block ends with the requested address.
                    // Reduce the len of the block by one.
                    if block.end_inclusive() == ip {
                        block.len -= 1;
                        return Some(ip);
                    }

                    // Address is the middle of the block.
                    // Split the block at the address we want to allocate.
                    dbg!(&block);
                    let (lhs, mut rhs) = block.split_at(ip);
                    *block = lhs;
                    rhs.bump();
                    self.blocks.insert(index + 1, rhs);
                    return Some(ip);
                }
            }
        }

        match self.blocks.first_mut() {
            Some(block) => {
                let addr = block.start;
                block.bump();

                if block.len == 0 {
                    self.blocks.remove(0);
                }

                Some(addr)
            }
            None => None,
        }
    }

    pub fn release(&mut self, ip: Ipv4Addr) {
        // Released ip the previously allocated ip. We move the cursor back once and
        // can reuse ip.
        // if u32::from_be_bytes(ip.octets()).wrapping_sub(1) == u32::from_le_bytes(self.next.octets())
        // {
        //     // self.next = ip;
        //     return;
        // }
    }
}

#[derive(Clone, Debug)]
pub struct Ipv4Range {
    start: Ipv4Addr,
    end: Ipv4Addr,
}

impl Ipv4Range {
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        ip >= self.start || ip <= self.end
    }

    pub fn len(&self) -> u32 {
        self.end.to_bits_() - self.start.to_bits_()
    }
}

#[derive(Clone, Debug)]
struct Block {
    start: Ipv4Addr,
    len: u32,
}

impl Block {
    fn bump(&mut self) {
        debug_assert!(self.len >= 1);

        let mut int = u32::from_be_bytes(self.start.octets());
        int += 1;
        let octets = int.to_be_bytes();
        self.start = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);

        self.len -= 1;
    }

    fn contains(&self, addr: Ipv4Addr) -> bool {
        let start = self.start.to_bits_();
        let end = self.start.to_bits_() + self.len;
        let addr = addr.to_bits_();
        addr >= start && addr < end
    }

    fn end_inclusive(&self) -> Ipv4Addr {
        Ipv4Addr::from_bits_(self.start.to_bits_() + self.len)
    }

    fn split_at(&self, addr: Ipv4Addr) -> (Block, Block) {
        debug_assert!(self.contains(addr));
        dbg!(self.contains(addr), addr);

        let index = addr.to_bits_() - self.start.to_bits_();
        (
            Block {
                start: self.start,
                len: index,
            },
            Block {
                start: Ipv4Addr::from_bits_(self.start.to_bits_() + index),
                len: self.len - index - 1,
            },
        )
    }
}

trait Ipv4AddrExt {
    fn to_bits_(&self) -> u32;
    fn from_bits_(bits: u32) -> Self;
}

impl Ipv4AddrExt for Ipv4Addr {
    fn from_bits_(bits: u32) -> Self {
        let octets = bits.to_be_bytes();
        Self::new(octets[0], octets[1], octets[2], octets[3])
    }

    fn to_bits_(&self) -> u32 {
        u32::from_be_bytes(self.octets())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{Allocator, Ipv4Range};

    #[test]
    fn allocator_request_any() {
        let mut allocator = Allocator::new(Ipv4Range {
            start: Ipv4Addr::new(10, 0, 0, 0),
            end: Ipv4Addr::new(10, 0, 0, 255),
        });

        for index in 0..255 {
            assert_eq!(
                allocator.request(None),
                Some(Ipv4Addr::new(10, 0, 0, index))
            );
        }

        assert_eq!(allocator.request(None), None);
    }

    #[test]
    fn allocator_request_targeted() {
        let mut allocator = Allocator::new(Ipv4Range {
            start: Ipv4Addr::new(10, 0, 0, 0),
            end: Ipv4Addr::new(10, 0, 0, 255),
        });

        let addrs = vec![
            Ipv4Addr::new(10, 0, 0, 100),
            Ipv4Addr::new(10, 0, 0, 20),
            Ipv4Addr::new(10, 0, 0, 170),
            Ipv4Addr::new(10, 0, 0, 0),
        ];

        for addr in addrs {
            assert_eq!(allocator.request(Some(addr)), Some(addr));
        }
    }
}
