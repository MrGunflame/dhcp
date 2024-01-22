use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, AsRawFd};

use crate::MacAddr;

// https://www.man7.org/linux/man-pages/man7/arp.7.html
pub fn arp_set(socket: impl AsFd, ip: Ipv4Addr, mac: MacAddr) -> io::Result<()> {
    // let addr_in = libc::sockaddr_in {
    //     sin_family: libc::AF_INET as u16,
    //     // client port
    //     sin_port: 68,
    //     sin_addr: libc::in_addr {
    //         s_addr: u32::from_be_bytes(ip.octets()),
    //     },
    //     sin_zero: [0; 8],
    // };

    // let arp_pa: libc::sockaddr = unsafe { core::mem::transmute(addr_in) };

    // let mut sa_data: [u8; 14] = [0; 14];
    // sa_data[..mac.octets().len()].copy_from_slice(&mac.octets());

    // let arp_ha = libc::sockaddr {
    //     // Hardware type 1 = Ethernet
    //     sa_family: 1,
    //     sa_data: unsafe { core::mem::transmute::<[u8; 14], [i8; 14]>(sa_data) },
    // };

    // let s = b"virbr0\0";

    // let mut arp_dev: [u8; 16] = [0; 16];
    // arp_dev[..s.len()].copy_from_slice(s);

    // let arp_req = libc::arpreq {
    //     arp_pa,
    //     arp_ha,
    //     arp_flags: libc::ATF_COM,
    //     arp_dev: unsafe { core::mem::transmute::<[u8; 16], [i8; 16]>(arp_dev) },
    //     ..unsafe { core::mem::zeroed() }
    // };

    // let fd = socket.as_fd().as_raw_fd();

    // let res = unsafe { libc::ioctl(fd, libc::SIOCSARP, &arp_req) };
    // if res == -1 {
    //     Err(io::Error::last_os_error())
    // } else {
    //     Ok(())
    // }

    Ok(())
}
