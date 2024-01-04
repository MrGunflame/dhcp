use std::mem::MaybeUninit;
use std::net::Ipv4Addr;

use bytes::{Buf, BufMut};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    let state = ();

    let socket = UdpSocket::bind("0.0.0.0:67").await.unwrap();

    loop {
        let mut buf = vec![0; 1500];
        let (len, addr) = socket.recv_from(&mut buf).await.unwrap();
        buf.truncate(len);
        tracing::info!("got packet from {:?}", addr);
    }
}

#[derive(Clone, Debug)]
pub struct Packet {
    pub op: Op,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    /// Transaction id
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    /// Client ip addr
    pub ciaddr: Ipv4Addr,
    /// "your" (client) addr
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    /// Client hardware addr
    pub chaddr: u128,
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub options: Vec<Option>,
}

impl Encode for Packet {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        self.op.encode(&mut buf);
        self.htype.encode(&mut buf);
        self.hlen.encode(&mut buf);
        self.hops.encode(&mut buf);
        self.xid.encode(&mut buf);
        self.secs.encode(&mut buf);
        self.flags.encode(&mut buf);
        self.ciaddr.encode(&mut buf);
        self.yiaddr.encode(&mut buf);
        self.siaddr.encode(&mut buf);
        self.giaddr.encode(&mut buf);
        self.chaddr.encode(&mut buf);
        self.sname.encode(&mut buf);
        self.file.encode(&mut buf);

        for option in &self.options {
            option.encode(&mut buf);
        }
    }
}

impl Decode for Packet {
    fn decode<B>(mut buf: B) -> Result<Self, Error>
    where
        B: Buf,
    {
        let op = Op::decode(&mut buf)?;
        let htype = u8::decode(&mut buf)?;
        let hlen = u8::decode(&mut buf)?;
        let hops = u8::decode(&mut buf)?;
        let xid = u32::decode(&mut buf)?;
        let secs = u16::decode(&mut buf)?;
        let flags = u16::decode(&mut buf)?;
        let ciaddr = Ipv4Addr::decode(&mut buf)?;
        let yiaddr = Ipv4Addr::decode(&mut buf)?;
        let siaddr = Ipv4Addr::decode(&mut buf)?;
        let giaddr = Ipv4Addr::decode(&mut buf)?;
        let chaddr = u128::decode(&mut buf)?;
        let sname = <[u8; 64]>::decode(&mut buf)?;
        let file = <[u8; 128]>::decode(&mut buf)?;

        let mut options = Vec::new();
        loop {
            if !buf.has_remaining() {
                return Err(Error::NotTerminated);
            }

            let code = u8::decode(&mut buf)?;
            let option = match code {
                // Pad
                0 => continue,
                // End
                255 => break,
                1 => Option::SubnetMask(SubnetMask::decode(&mut buf)?),
                2 => Option::TimeOffset(TimeOffset::decode(&mut buf)?),
                3 => Option::Routers(Routers::decode(&mut buf)?),
                4 => Option::TimeServers(TimeServers::decode(&mut buf)?),
                5 => Option::NameServers(NameServers::decode(&mut buf)?),
                6 => Option::DomainNameServers(DomainNameServers::decode(&mut buf)?),
                _ => return Err(Error::InvalidOption(code)),
            };
            options.push(option);
        }

        Ok(Self {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file,
            options,
        })
    }
}

async fn handle_packet(packet: Packet) {}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Op {
    BootRequest,
    BootReply,
}

impl Encode for Op {
    fn encode<B>(&self, buf: B)
    where
        B: BufMut,
    {
        let byte: u8 = match self {
            Self::BootRequest => 0x01,
            Self::BootReply => 0x02,
        };

        byte.encode(buf);
    }
}

impl Decode for Op {
    fn decode<B>(buf: B) -> Result<Self, Error>
    where
        B: Buf,
    {
        match u8::decode(buf)? {
            0x01 => Ok(Self::BootRequest),
            0x02 => Ok(Self::BootReply),
            b => Err(Error::InvaidOp(b)),
        }
    }
}

pub struct Pool {}

#[derive(Clone, Debug)]
pub enum Option {
    SubnetMask(SubnetMask),
    TimeOffset(TimeOffset),
    Routers(Routers),
    TimeServers(TimeServers),
    NameServers(NameServers),
    DomainNameServers(DomainNameServers),
}

impl Encode for Option {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        let tag: u8 = match self {
            Self::SubnetMask(_) => 1,
            Self::TimeOffset(_) => 2,
            Self::Routers(_) => 3,
            Self::TimeServers(_) => 4,
            Self::NameServers(_) => 5,
            Self::DomainNameServers(_) => 6,
        };
        tag.encode(&mut buf);

        match self {
            Self::SubnetMask(v) => v.encode(buf),
            Self::TimeOffset(v) => v.encode(buf),
            Self::Routers(v) => v.encode(buf),
            Self::TimeServers(v) => v.encode(buf),
            Self::NameServers(v) => v.encode(buf),
            Self::DomainNameServers(v) => v.encode(buf),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct SubnetMask(u32);

impl Encode for SubnetMask {
    fn encode<B>(&self, buf: B)
    where
        B: BufMut,
    {
        self.0.encode(buf);
    }
}

impl Decode for SubnetMask {
    fn decode<B>(buf: B) -> Result<Self, Error>
    where
        B: Buf,
    {
        u32::decode(buf).map(Self)
    }
}

#[derive(Copy, Clone, Debug)]
pub struct TimeOffset(u32);

impl Encode for TimeOffset {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        let len: u8 = 4;

        len.encode(&mut buf);
        self.0.encode(buf);
    }
}

impl Decode for TimeOffset {
    fn decode<B>(mut buf: B) -> Result<Self, Error>
    where
        B: Buf,
    {
        let len = u8::decode(&mut buf)?;
        u32::decode(buf).map(Self)
    }
}

// https://datatracker.ietf.org/doc/html/rfc1533#section-9.4
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum DhcpMessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
}

impl Encode for DhcpMessageType {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        let len = 1;

        let typ = match self {
            Self::Discover => 1,
            Self::Offer => 2,
            Self::Request => 3,
            Self::Decline => 4,
            Self::Ack => 5,
            Self::Nak => 6,
            Self::Release => 7,
        };

        buf.put_u8(len);
        buf.put_u8(typ);
    }
}

impl Decode for DhcpMessageType {
    fn decode<B>(mut buf: B) -> Result<Self, Error>
    where
        B: Buf,
    {
        let len = buf.get_u8();
        let typ = buf.get_u8();

        match typ {
            1 => Ok(Self::Discover),
            2 => Ok(Self::Offer),
            3 => Ok(Self::Request),
            4 => Ok(Self::Decline),
            5 => Ok(Self::Ack),
            6 => Ok(Self::Nak),
            7 => Ok(Self::Release),
            _ => Err(Error::InvalidDhcpMessageType(typ)),
        }
    }
}

enum Error {
    InvaidOp(u8),
    InvalidDhcpMessageType(u8),
    UnexpectedEof,
    NotTerminated,
    InvalidOption(u8),
}

trait Decode: Sized {
    fn decode<B>(buf: B) -> Result<Self, Error>
    where
        B: Buf;
}

trait Encode {
    fn encode<B>(&self, buf: B)
    where
        B: BufMut;
}

// https://datatracker.ietf.org/doc/html/rfc1533#section-9.5
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ServerIdentifier(Ipv4Addr);

impl Encode for ServerIdentifier {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        let len = 4;

        buf.put_u8(len);
        self.0.encode(buf);
    }
}

impl Decode for ServerIdentifier {
    fn decode<B>(mut buf: B) -> Result<Self, Error>
    where
        B: Buf,
    {
        let len = buf.get_u8();
        let addr = Ipv4Addr::decode(buf)?;
        Ok(Self(addr))
    }
}

impl Encode for Ipv4Addr {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        let bytes = self.octets();
        buf.put_slice(&bytes);
    }
}

impl Decode for Ipv4Addr {
    fn decode<B>(mut buf: B) -> Result<Self, Error>
    where
        B: Buf,
    {
        let a0 = buf.get_u8();
        let a1 = buf.get_u8();
        let a2 = buf.get_u8();
        let a3 = buf.get_u8();

        Ok(Self::new(a0, a1, a2, a3))
    }
}

// https://datatracker.ietf.org/doc/html/rfc1533#section-9.1
pub struct RequestedIpAddress(Ipv4Addr);

impl Encode for RequestedIpAddress {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        let len = 4;

        buf.put_u8(len);
        self.0.encode(buf);
    }
}

impl Decode for RequestedIpAddress {
    fn decode<B>(mut buf: B) -> Result<Self, Error>
    where
        B: Buf,
    {
        let len = buf.get_u8();
        let addr = Ipv4Addr::decode(buf)?;
        Ok(Self(addr))
    }
}

// https://datatracker.ietf.org/doc/html/rfc1533#section-9.6
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ParameterRequestList {}

impl Encode for u8 {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        buf.put_u8(*self);
    }
}

impl Decode for u8 {
    fn decode<B>(mut buf: B) -> Result<Self, Error>
    where
        B: Buf,
    {
        if buf.remaining() < 1 {
            Err(Error::UnexpectedEof)
        } else {
            Ok(buf.get_u8())
        }
    }
}

impl<T, const N: usize> Encode for [T; N]
where
    T: Encode,
{
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        for elem in self {
            elem.encode(&mut buf);
        }
    }
}

impl<T, const N: usize> Decode for [T; N]
where
    // T: Copy implies that needs_drop<T>() == false and we don't
    // we can drop the partially initialized array without dropping elements.
    T: Decode,
{
    fn decode<B>(mut buf: B) -> Result<Self, Error>
    where
        B: Buf,
    {
        let mut array: [MaybeUninit<T>; N] = unsafe { MaybeUninit::uninit().assume_init() };

        for index in 0..N {
            let elem = T::decode(&mut buf)?;
            array[index].write(elem);
        }

        let array = unsafe { core::mem::transmute_copy::<[MaybeUninit<T>; N], [T; N]>(&array) };
        Ok(array)
    }
}

macro_rules! impl_int {
    ($($t:ty),*) => {
        $(
            impl Encode for $t {
                fn encode<B: BufMut>(&self, buf: B) {
                    self.to_be_bytes().encode(buf);
                }
            }

            impl Decode for $t {
                fn decode<B: Buf>(buf: B) -> Result<Self, Error> {
                    <[u8; core::mem::size_of::<Self>()]>::decode(buf).map(Self::from_be_bytes)
                }
            }

        )*
    };
}

impl_int! { u16, u32, u64, u128 }

#[derive(Clone, Debug)]
pub struct Routers(Vec<Ipv4Addr>);

#[derive(Clone, Debug)]
pub struct TimeServers(Vec<Ipv4Addr>);

#[derive(Clone, Debug)]
pub struct NameServers(Vec<Ipv4Addr>);

#[derive(Clone, Debug)]
pub struct DomainNameServers(Vec<Ipv4Addr>);

macro_rules! server_list_impl {
    ($($t:ty),*) => {
        $(
            impl Encode for $t {
                fn encode<B>(&self, mut buf: B)
                where
                    B: BufMut,
                {
                    let len = (self.0.len() * 4) as u8;

                    len.encode(&mut buf);
                    for addr in &self.0 {
                        addr.encode(&mut buf);
                    }
                }
            }

            impl Decode for $t {
                fn decode<B>(mut buf: B) -> Result<Self, Error>
                where
                    B: Buf,
                {
                    let len = (u8::decode(&mut buf)? / 4) as usize;

                    let mut addrs = Vec::new();
                    for _ in 0..len {
                        let addr = Ipv4Addr::decode(&mut buf)?;
                        addrs.push(addr);
                    }

                    Ok(Self(addrs))
                }
            }
        )*
    };
}

server_list_impl! { Routers, TimeServers, NameServers, DomainNameServers }
