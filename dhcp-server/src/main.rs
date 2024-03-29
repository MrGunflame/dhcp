mod config;
mod database;
mod ioctl;
mod pool;

use std::collections::HashMap;
use std::fmt::{self, Debug, Formatter};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::task::Poll;
use std::time::SystemTime;

use bytes::{Buf, BufMut};
use config::Config;
use database::{Database, DecodeError};
use pool::Pool;
use tokio::net::UdpSocket;

const DHCP_MAGIC: [u8; 4] = [99, 130, 83, 99];

pub struct State {
    pool: MainPool,
    config: Config,
}

#[derive(Copy, Clone, Debug)]
pub struct Lease {
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
    pub valid_until: SystemTime,
}

impl Lease {
    pub fn is_valid(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug)]
pub struct TimeWheel {
    leases: Vec<Lease>,
}

impl TimeWheel {
    pub fn new() -> Self {
        Self { leases: Vec::new() }
    }

    pub fn insert(&mut self, lease: Lease) {
        let mut index = 0;
        while index < self.leases.len() {
            // Lease expires before the lease at index and takes
            // the place.
            if lease.valid_until < self.leases[index].valid_until {
                self.leases.insert(index, lease);
                return;
            }

            index += 1;
        }

        self.leases.push(lease);
    }

    pub fn remove(&mut self, mac: MacAddr) {
        self.leases.retain(|lease| lease.mac != mac);
    }

    /// Sleep until the first lease in the wheel expires.
    ///
    /// Never yields if no lease are in the wheel.
    pub async fn wait(&mut self) -> Lease {
        let Some(lease) = self.leases.first() else {
            // This will never yield but this is ok since we expect the executor
            // always drop and recreate the future when a new lease is created.
            futures::future::poll_fn(|_| Poll::<()>::Pending).await;
            unreachable!();
        };

        // If the duration is "negative" this returns an error. This can only
        // happen if the lease just expired and we don't have to go to sleep.
        let Ok(duration) = lease.valid_until.duration_since(SystemTime::now()) else {
            return self.leases.remove(0);
        };

        tokio::time::sleep(duration).await;
        self.leases.remove(0)
    }
}

pub struct MainPool {
    pool: Pool,
    database: Database,
    wheel: TimeWheel,
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("client error")]
    ClientError,
    #[error("decode: {0}")]
    Decode(#[from] DecodeError),
}

impl MainPool {
    pub async fn request_addr(
        &mut self,
        mac: MacAddr,
        ip: Option<Ipv4Addr>,
    ) -> Result<Option<Lease>, ServerError> {
        let Some(lease) = self.pool.request_addr(mac, ip) else {
            return Ok(None);
        };

        self.database.insert(lease).await?;
        self.wheel.insert(lease);
        Ok(Some(lease))
    }

    pub fn get(&self, mac: MacAddr) -> Option<Lease> {
        self.pool.get(mac)
    }

    pub async fn extend(&mut self, mac: MacAddr) -> Result<Option<Lease>, ServerError> {
        self.pool.extend(mac);
        if let Some(lease) = self.pool.get(mac) {
            self.database.insert(lease).await?;

            // Reset the wheel entry.
            self.wheel.remove(mac);
            self.wheel.insert(lease);
            Ok(Some(lease))
        } else {
            Ok(None)
        }
    }

    pub async fn wait_for_expired_lease(&mut self) -> Result<(), ServerError> {
        loop {
            let lease = self.wheel.wait().await;
            self.pool.release_addr(lease.mac);
            self.database.remove(lease.mac).await?;
        }
    }
}

#[tokio::main]
async fn main() {
    let config = match Config::from_file("config.toml") {
        Ok(config) => config,
        Err(err) => {
            eprintln!("failed to read config: {}", err);
            return;
        }
    };

    pretty_env_logger::init();

    let database = Database::new("./leases").await.unwrap();

    let mut leases = HashMap::new();
    let mut wheel = TimeWheel::new();
    for lease in database.leases() {
        leases.insert(lease.mac, lease);
        wheel.insert(lease);
    }

    let mut state = State {
        pool: MainPool {
            pool: Pool::new(config.start, config.end, leases),
            database,
            wheel,
        },
        config,
    };

    let socket = UdpSocket::bind("0.0.0.0:67").await.unwrap();

    let sock_ref = socket2::SockRef::from(&socket);
    sock_ref.set_broadcast(true).unwrap();

    loop {
        let mut buf = vec![0; 1500];

        let (len, addr) = tokio::select! {
            res = socket.recv_from(&mut buf) => match res {
                Ok((len, addr)) => (len, addr),
                Err(err) => {
                    tracing::error!("failed to receive data on socket: {}", err);
                    continue;
                }
            },
            // The future will never yield if no leases are stored so we need
            // drop the future if the other completes.
            _ = state.pool.wait_for_expired_lease() => continue,
        };

        buf.truncate(len);
        tracing::info!("got packet from {:?}", addr);

        let packet = match Packet::decode(&buf[..]) {
            Ok(packet) => packet,
            Err(err) => {
                tracing::error!("failed to decode packet: {:?}", err);
                continue;
            }
        };

        handle_packet(&mut state, &socket, addr, packet).await;
    }
}

async fn handle_packet(state: &mut State, socket: &UdpSocket, addr: SocketAddr, packet: Packet) {
    let Some(dhcp_type) = packet.options.get(&OptionCode::DhcpMessageType) else {
        tracing::debug!("not a DHCP packet");
        return;
    };

    // If the Server Identifier option is present we must only listen
    // to messages directed at us.
    if let Some(ident) = packet.options.get(&OptionCode::ServerIdentifier) {
        let ident = match ident {
            DhcpOption::ServerIdentifier(ident) => ident.0,
            _ => {
                tracing::trace!("malformed packet");
                return;
            }
        };

        if ident != state.config.local_addr {
            return;
        }
    }

    match dhcp_type {
        DhcpOption::DhcpMessageType(typ) => match typ {
            DhcpMessageType::Discover => handle_discover(state, socket, addr, packet).await,
            DhcpMessageType::Request => handle_request(state, socket, addr, packet).await,
            _ => (),
        },
        _ => (),
    }
}

/// Allocates a lease for a client.
async fn allocate_lease_for_client(
    state: &mut State,
    packet: &Packet,
) -> Result<Option<Lease>, ServerError> {
    // Chose an IP address for the client with priorities based on
    // https://datatracker.ietf.org/doc/html/rfc2131#section-4.3.1:
    // 1. The clients current "client address" (ciaddr) if the lease is valid.
    // 2. The clients "client address" (ciaddr) if the lease is expired and in
    //    the pool of available addresses.
    // 3. The address requested in the "Requested Ip Address" option if available.
    // 4. A server-chosen address.
    let mac = packet.mac();

    if !packet.ciaddr.is_unspecified() {
        // If the lease is still in the pool it is still valid and we can offer
        // if again.
        if let Some(lease) = state.pool.get(mac) {
            if lease.ip != packet.ciaddr {
                tracing::warn!(
                    "client thought he had {:?} but we know him as {:?}",
                    packet.ciaddr,
                    lease
                );
            }

            let lease = state.pool.extend(mac).await?.unwrap();
            return Ok(Some(lease));
        }

        // Client lease is expired but we attempt to allocate the requested client
        // address of the client if it is available.
        if let Some(lease) = state.pool.request_addr(mac, Some(packet.ciaddr)).await? {
            return Ok(Some(lease));
        }
    }

    let requested_ip = match packet.options.get(&OptionCode::RequestedIpAddress) {
        Some(opt) => match opt {
            DhcpOption::RequestedIpAddress(addr) => Some(addr.0),
            _ => return Err(ServerError::ClientError),
        },
        None => None,
    };

    let lease = state.pool.request_addr(mac, requested_ip).await?;
    Ok(lease)
}

async fn handle_discover(state: &mut State, socket: &UdpSocket, addr: SocketAddr, packet: Packet) {
    let lease = match allocate_lease_for_client(state, &packet).await {
        Ok(Some(lease)) => lease,
        Ok(None) => {
            tracing::error!("cannot offer lease, out of addresses");
            return;
        }
        Err(err) => {
            tracing::error!("server error: {}", err);
            return;
        }
    };

    let Some(params) = packet.options.get(&OptionCode::ParameterRequestList) else {
        tracing::debug!("client has not requested any paramters");
        return;
    };

    let params = match params {
        DhcpOption::ParameterRequestList(params) => params,
        _ => return,
    };

    let mut options = HashMap::new();
    options.insert(
        OptionCode::DhcpMessageType,
        DhcpOption::DhcpMessageType(DhcpMessageType::Offer),
    );
    options.insert(
        OptionCode::ServerIdentifier,
        DhcpOption::ServerIdentifier(ServerIdentifier(state.config.local_addr)),
    );
    options.insert(
        OptionCode::IpAddressLeaseTime,
        DhcpOption::IpAddressLeaseTime(IpAddressLeaseTime(3600)),
    );
    options.insert(
        OptionCode::RenewalTimeValue,
        DhcpOption::RenewalTimeValue(RenewalTimeValue(1800)),
    );
    options.insert(
        OptionCode::RebindingTimeValue,
        DhcpOption::RebindingTimeValue(RebindingTimeValue(3150)),
    );

    for code in &params.0 {
        match code {
            OptionCode::SubnetMask => {
                options.insert(
                    OptionCode::SubnetMask,
                    DhcpOption::SubnetMask(SubnetMask(state.config.subnet)),
                );
            }
            OptionCode::BroadcastAddress => {
                options.insert(
                    OptionCode::BroadcastAddress,
                    DhcpOption::BroadcastAddress(BroadcastAddress(state.config.broadcast)),
                );
            }
            OptionCode::Router => {
                options.insert(
                    OptionCode::Router,
                    DhcpOption::Routers(Routers(state.config.routers.clone())),
                );
            }
            OptionCode::DomainNameServer => {
                options.insert(
                    OptionCode::DomainNameServer,
                    DhcpOption::DomainNameServers(DomainNameServers(state.config.dns.clone())),
                );
            }
            _ => (),
        }
    }

    let resp = Packet {
        op: Op::BootReply,
        htype: 0x01,
        hlen: 6,
        hops: 0,
        xid: packet.xid,
        secs: 0,
        flags: packet.flags,
        ciaddr: packet.ciaddr,
        yiaddr: lease.ip,
        siaddr: state.config.local_addr,
        giaddr: packet.giaddr,
        chaddr: packet.chaddr,
        sname: [0; 64],
        file: [0; 128],
        options,
    };

    let mut buf = Vec::new();
    resp.encode(&mut buf);

    tracing::info!("offering {:?}", lease);

    //ioctl::arp_set(&socket, ip, mac).unwrap();
    let dst = SocketAddr::new(IpAddr::V4(state.config.broadcast), addr.port());
    socket.send_to(&buf, dst).await.unwrap();
}

async fn handle_request(state: &mut State, socket: &UdpSocket, addr: SocketAddr, packet: Packet) {
    let lease = match allocate_lease_for_client(state, &packet).await {
        Ok(Some(lease)) => lease,
        Ok(None) => {
            tracing::error!("cannot offer lease, out of addresses");
            return;
        }
        Err(err) => {
            tracing::error!("server error: {}", err);
            return;
        }
    };

    let Some(params) = packet.options.get(&OptionCode::ParameterRequestList) else {
        tracing::debug!("client has not requested any paramters");
        return;
    };

    let params = match params {
        DhcpOption::ParameterRequestList(params) => params,
        _ => return,
    };

    let mut options = HashMap::new();
    options.insert(
        OptionCode::DhcpMessageType,
        DhcpOption::DhcpMessageType(DhcpMessageType::Ack),
    );
    options.insert(
        OptionCode::ServerIdentifier,
        DhcpOption::ServerIdentifier(ServerIdentifier(state.config.local_addr)),
    );
    options.insert(
        OptionCode::IpAddressLeaseTime,
        DhcpOption::IpAddressLeaseTime(IpAddressLeaseTime(3600)),
    );
    options.insert(
        OptionCode::RenewalTimeValue,
        DhcpOption::RenewalTimeValue(RenewalTimeValue(1800)),
    );
    options.insert(
        OptionCode::RebindingTimeValue,
        DhcpOption::RebindingTimeValue(RebindingTimeValue(3150)),
    );

    for code in &params.0 {
        match code {
            OptionCode::SubnetMask => {
                options.insert(
                    OptionCode::SubnetMask,
                    DhcpOption::SubnetMask(SubnetMask(state.config.subnet)),
                );
            }
            OptionCode::BroadcastAddress => {
                options.insert(
                    OptionCode::BroadcastAddress,
                    DhcpOption::BroadcastAddress(BroadcastAddress(state.config.broadcast)),
                );
            }
            OptionCode::Router => {
                options.insert(
                    OptionCode::Router,
                    DhcpOption::Routers(Routers(state.config.routers.clone())),
                );
            }
            OptionCode::DomainNameServer => {
                options.insert(
                    OptionCode::DomainNameServer,
                    DhcpOption::DomainNameServers(DomainNameServers(state.config.dns.clone())),
                );
            }
            _ => (),
        }
    }

    let resp = Packet {
        op: Op::BootReply,
        htype: 0x01,
        hlen: 6,
        hops: 0,
        xid: packet.xid,
        secs: 0,
        flags: packet.flags,
        ciaddr: packet.ciaddr,
        yiaddr: lease.ip,
        siaddr: state.config.local_addr,
        giaddr: packet.giaddr,
        chaddr: packet.chaddr,
        sname: [0; 64],
        file: [0; 128],
        options,
    };

    let mut buf = Vec::new();
    resp.encode(&mut buf);

    //ioctl::arp_set(&socket, lease.ip, mac).unwrap();
    let dst = SocketAddr::new(IpAddr::V4(state.config.broadcast), addr.port());
    socket.send_to(&buf, dst).await.unwrap();
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
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub options: HashMap<OptionCode, DhcpOption>,
}

impl Packet {
    pub fn mac(&self) -> MacAddr {
        MacAddr::from_octets(self.chaddr[0..6].try_into().unwrap())
    }
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
        DHCP_MAGIC.encode(&mut buf);

        for (_, option) in &self.options {
            option.encode(&mut buf);
        }

        OptionCode::End.encode(&mut buf);
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
        let chaddr = <[u8; 16]>::decode(&mut buf)?;
        let sname = <[u8; 64]>::decode(&mut buf)?;
        let file = <[u8; 128]>::decode(&mut buf)?;
        let magic = <[u8; 4]>::decode(&mut buf)?;

        if magic != DHCP_MAGIC {
            return Err(Error::InvalidMagic(magic));
        }

        let mut options = HashMap::new();
        loop {
            if !buf.has_remaining() {
                return Err(Error::NotTerminated);
            }

            let code = u8::decode(&mut buf)?;
            let option = match OptionCode::from_u8(code) {
                // Pad
                Ok(OptionCode::Pad) => continue,
                // End
                Ok(OptionCode::End) => break,
                Ok(OptionCode::SubnetMask) => DhcpOption::SubnetMask(SubnetMask::decode(&mut buf)?),
                Ok(OptionCode::TimeOffset) => DhcpOption::TimeOffset(TimeOffset::decode(&mut buf)?),
                Ok(OptionCode::Router) => DhcpOption::Routers(Routers::decode(&mut buf)?),
                Ok(OptionCode::TimeServer) => {
                    DhcpOption::TimeServers(TimeServers::decode(&mut buf)?)
                }
                Ok(OptionCode::NameServer) => {
                    DhcpOption::NameServers(NameServers::decode(&mut buf)?)
                }
                Ok(OptionCode::DomainNameServer) => {
                    DhcpOption::DomainNameServers(DomainNameServers::decode(&mut buf)?)
                }
                Ok(OptionCode::RequestedIpAddress) => {
                    DhcpOption::RequestedIpAddress(RequestedIpAddress::decode(&mut buf)?)
                }
                Ok(OptionCode::DhcpMessageType) => {
                    DhcpOption::DhcpMessageType(DhcpMessageType::decode(&mut buf)?)
                }
                Ok(OptionCode::ServerIdentifier) => {
                    DhcpOption::ServerIdentifier(ServerIdentifier::decode(&mut buf)?)
                }
                Ok(OptionCode::ParameterRequestList) => {
                    DhcpOption::ParameterRequestList(ParameterRequestList::decode(&mut buf)?)
                }
                _ => {
                    let len = u8::decode(&mut buf)?;
                    for _ in 0..len {
                        u8::decode(&mut buf)?;
                    }

                    continue;
                }
            };

            let code = OptionCode::from_u8(code).unwrap();
            options.insert(code, option);
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

#[derive(Clone, Debug)]
pub enum DhcpOption {
    SubnetMask(SubnetMask),
    TimeOffset(TimeOffset),
    Routers(Routers),
    TimeServers(TimeServers),
    NameServers(NameServers),
    DomainNameServers(DomainNameServers),
    BroadcastAddress(BroadcastAddress),
    // DHCP
    RequestedIpAddress(RequestedIpAddress),
    IpAddressLeaseTime(IpAddressLeaseTime),
    DhcpMessageType(DhcpMessageType),
    ServerIdentifier(ServerIdentifier),
    ParameterRequestList(ParameterRequestList),
    RenewalTimeValue(RenewalTimeValue),
    RebindingTimeValue(RebindingTimeValue),
}

impl Encode for DhcpOption {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        let code = match self {
            Self::SubnetMask(_) => OptionCode::SubnetMask,
            Self::TimeOffset(_) => OptionCode::TimeOffset,
            Self::Routers(_) => OptionCode::Router,
            Self::TimeServers(_) => OptionCode::TimeServer,
            Self::NameServers(_) => OptionCode::NameServer,
            Self::DomainNameServers(_) => OptionCode::DomainNameServer,
            Self::BroadcastAddress(_) => OptionCode::BroadcastAddress,
            Self::RequestedIpAddress(_) => OptionCode::RequestedIpAddress,
            Self::IpAddressLeaseTime(_) => OptionCode::IpAddressLeaseTime,
            Self::DhcpMessageType(_) => OptionCode::DhcpMessageType,
            Self::ServerIdentifier(_) => OptionCode::ServerIdentifier,
            Self::ParameterRequestList(_) => OptionCode::ParameterRequestList,
            Self::RenewalTimeValue(_) => OptionCode::RenewalTimeValue,
            Self::RebindingTimeValue(_) => OptionCode::RebindingTimeValue,
        };
        code.encode(&mut buf);

        match self {
            Self::SubnetMask(v) => v.encode(buf),
            Self::TimeOffset(v) => v.encode(buf),
            Self::Routers(v) => v.encode(buf),
            Self::TimeServers(v) => v.encode(buf),
            Self::NameServers(v) => v.encode(buf),
            Self::DomainNameServers(v) => v.encode(buf),
            Self::BroadcastAddress(v) => v.encode(buf),
            Self::RequestedIpAddress(v) => v.encode(buf),
            Self::IpAddressLeaseTime(v) => v.encode(buf),
            Self::DhcpMessageType(v) => v.encode(buf),
            Self::ServerIdentifier(v) => v.encode(buf),
            Self::ParameterRequestList(v) => v.encode(buf),
            Self::RenewalTimeValue(v) => v.encode(buf),
            Self::RebindingTimeValue(v) => v.encode(buf),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct SubnetMask(Ipv4Addr);

impl Encode for SubnetMask {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        let len: u8 = 4;
        len.encode(&mut buf);
        self.0.encode(buf);
    }
}

impl Decode for SubnetMask {
    fn decode<B>(mut buf: B) -> Result<Self, Error>
    where
        B: Buf,
    {
        let _len = u8::decode(&mut buf)?;
        Ipv4Addr::decode(buf).map(Self)
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
        let _len = u8::decode(&mut buf)?;
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
        let _len = u8::decode(&mut buf)?;
        let typ = u8::decode(&mut buf)?;

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

#[derive(Clone, Debug)]
enum Error {
    InvaidOp(u8),
    InvalidDhcpMessageType(u8),
    UnexpectedEof,
    NotTerminated,
    InvalidOption(u8),
    InvalidMagic([u8; 4]),
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
        let _len = u8::decode(&mut buf)?;
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
        let a0 = u8::decode(&mut buf)?;
        let a1 = u8::decode(&mut buf)?;
        let a2 = u8::decode(&mut buf)?;
        let a3 = u8::decode(&mut buf)?;

        Ok(Self::new(a0, a1, a2, a3))
    }
}

// https://datatracker.ietf.org/doc/html/rfc1533#section-9.1
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
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
        let _len = u8::decode(&mut buf)?;
        let addr = Ipv4Addr::decode(buf)?;
        Ok(Self(addr))
    }
}

// https://datatracker.ietf.org/doc/html/rfc1533#section-9.6
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ParameterRequestList(Vec<OptionCode>);

impl Encode for ParameterRequestList {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        let len = self.0.len() as u8;
        len.encode(&mut buf);

        for code in &self.0 {
            code.to_u8().encode(&mut buf);
        }
    }
}

impl Decode for ParameterRequestList {
    fn decode<B>(mut buf: B) -> Result<Self, Error>
    where
        B: Buf,
    {
        let len = u8::decode(&mut buf)?;

        let mut codes = Vec::new();
        for _ in 0..len {
            let code = u8::decode(&mut buf)?;
            // Skip all unknown codes.
            if let Ok(code) = OptionCode::from_u8(code) {
                codes.push(code);
            }
        }

        Ok(Self(codes))
    }
}

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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BroadcastAddress(Ipv4Addr);

impl Encode for BroadcastAddress {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        let len: u8 = 4;

        len.encode(&mut buf);
        self.0.encode(&mut buf);
    }
}

impl Decode for BroadcastAddress {
    fn decode<B>(mut buf: B) -> Result<Self, Error>
    where
        B: Buf,
    {
        let _len = u8::decode(&mut buf)?;
        Ipv4Addr::decode(buf).map(Self)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum OptionCode {
    Pad,
    End,
    SubnetMask,
    TimeOffset,
    Router,
    TimeServer,
    NameServer,
    DomainNameServer,
    LogServer,
    CookieServer,
    LprServer,
    ImpressServer,
    ResourceLocationServer,
    HostName,
    BootFileSize,
    MeritDumpFile,
    DomainName,
    SwapServer,
    RootPath,
    ExtensionsPath,
    IpForwarding,
    NonLocalSourceRouting,
    PolicyFilter,
    MaximumDatagramReassemblySize,
    DefaultIpTtl,
    PathMtuAgingTimeout,
    PathMtuPlateuTable,
    InterfaceMtu,
    AllSubnetsAreLocal,
    BroadcastAddress,
    PerformMaskDiscovery,
    MaskSupplier,
    PerformRouterDiscovery,
    RouterSolicitationAddress,
    StaticRoute,
    TrailerEncapsulation,
    ArpCacheTimeout,
    EthernetEncapsulation,
    TcpDefaultTtl,
    TcpKeepaliveInterval,
    TcpKeepaliveGarbage,
    NetworkInformationServiceDomain,
    NetworkInformationServers,
    NetworkTimeProtocolServers,
    VendorSpecificInformation,
    NetBiosOverTcpIpNameServer,
    NetBiosOverTcpIpDatagramDistributionServer,
    NetBiosOverTcpIpNodeType,
    NetBiosOverTcpIpScope,
    XWindowSystemFontServer,
    XWindowSystemDisplayManager,
    RequestedIpAddress,
    IpAddressLeaseTime,
    OptionOverload,
    DhcpMessageType,
    ServerIdentifier,
    ParameterRequestList,
    Message,
    MaximumDhcpMessageSize,
    RenewalTimeValue,
    RebindingTimeValue,
    ClassIdentifier,
    ClientIdentifier,
}

impl Encode for OptionCode {
    fn encode<B>(&self, buf: B)
    where
        B: BufMut,
    {
        self.to_u8().encode(buf);
    }
}

impl OptionCode {
    fn to_u8(self) -> u8 {
        match self {
            Self::Pad => 0,
            Self::End => 255,
            Self::SubnetMask => 1,
            Self::TimeOffset => 2,
            Self::Router => 3,
            Self::TimeServer => 4,
            Self::NameServer => 5,
            Self::DomainNameServer => 6,
            Self::LogServer => 7,
            Self::CookieServer => 8,
            Self::LprServer => 9,
            Self::ImpressServer => 10,
            Self::ResourceLocationServer => 11,
            Self::HostName => 12,
            Self::BootFileSize => 13,
            Self::MeritDumpFile => 14,
            Self::DomainName => 15,
            Self::SwapServer => 16,
            Self::RootPath => 17,
            Self::ExtensionsPath => 18,
            Self::IpForwarding => 19,
            Self::NonLocalSourceRouting => 20,
            Self::PolicyFilter => 21,
            Self::MaximumDatagramReassemblySize => 22,
            Self::DefaultIpTtl => 23,
            Self::PathMtuAgingTimeout => 24,
            Self::PathMtuPlateuTable => 25,
            Self::InterfaceMtu => 26,
            Self::AllSubnetsAreLocal => 27,
            Self::BroadcastAddress => 28,
            Self::PerformMaskDiscovery => 29,
            Self::MaskSupplier => 30,
            Self::PerformRouterDiscovery => 31,
            Self::RouterSolicitationAddress => 32,
            Self::StaticRoute => 33,
            Self::TrailerEncapsulation => 34,
            Self::ArpCacheTimeout => 35,
            Self::EthernetEncapsulation => 36,
            Self::TcpDefaultTtl => 37,
            Self::TcpKeepaliveInterval => 38,
            Self::TcpKeepaliveGarbage => 39,
            Self::NetworkInformationServiceDomain => 40,
            Self::NetworkInformationServers => 41,
            Self::NetworkTimeProtocolServers => 42,
            Self::VendorSpecificInformation => 43,
            Self::NetBiosOverTcpIpNameServer => 44,
            Self::NetBiosOverTcpIpDatagramDistributionServer => 45,
            Self::NetBiosOverTcpIpNodeType => 46,
            Self::NetBiosOverTcpIpScope => 47,
            Self::XWindowSystemFontServer => 48,
            Self::XWindowSystemDisplayManager => 49,
            Self::RequestedIpAddress => 50,
            Self::IpAddressLeaseTime => 51,
            Self::OptionOverload => 52,
            Self::DhcpMessageType => 53,
            Self::ServerIdentifier => 54,
            Self::ParameterRequestList => 55,
            Self::Message => 56,
            Self::MaximumDhcpMessageSize => 57,
            Self::RenewalTimeValue => 58,
            Self::RebindingTimeValue => 59,
            Self::ClassIdentifier => 60,
            Self::ClientIdentifier => 61,
        }
    }

    fn from_u8(code: u8) -> Result<Self, Error> {
        match code {
            0 => Ok(Self::Pad),
            255 => Ok(Self::End),
            1 => Ok(Self::SubnetMask),
            2 => Ok(Self::TimeOffset),
            3 => Ok(Self::Router),
            4 => Ok(Self::TimeServer),
            5 => Ok(Self::NameServer),
            6 => Ok(Self::DomainNameServer),
            7 => Ok(Self::LogServer),
            8 => Ok(Self::CookieServer),
            9 => Ok(Self::LprServer),
            10 => Ok(Self::ImpressServer),
            11 => Ok(Self::ResourceLocationServer),
            12 => Ok(Self::HostName),
            13 => Ok(Self::BootFileSize),
            14 => Ok(Self::MeritDumpFile),
            15 => Ok(Self::DomainName),
            16 => Ok(Self::SwapServer),
            17 => Ok(Self::RootPath),
            18 => Ok(Self::ExtensionsPath),
            19 => Ok(Self::IpForwarding),
            20 => Ok(Self::NonLocalSourceRouting),
            21 => Ok(Self::PolicyFilter),
            22 => Ok(Self::MaximumDatagramReassemblySize),
            23 => Ok(Self::DefaultIpTtl),
            24 => Ok(Self::PathMtuAgingTimeout),
            25 => Ok(Self::PathMtuPlateuTable),
            26 => Ok(Self::InterfaceMtu),
            27 => Ok(Self::AllSubnetsAreLocal),
            28 => Ok(Self::BroadcastAddress),
            29 => Ok(Self::PerformMaskDiscovery),
            30 => Ok(Self::MaskSupplier),
            31 => Ok(Self::PerformRouterDiscovery),
            32 => Ok(Self::RouterSolicitationAddress),
            33 => Ok(Self::StaticRoute),
            34 => Ok(Self::TrailerEncapsulation),
            35 => Ok(Self::ArpCacheTimeout),
            36 => Ok(Self::EthernetEncapsulation),
            37 => Ok(Self::TcpDefaultTtl),
            38 => Ok(Self::TcpKeepaliveInterval),
            39 => Ok(Self::TcpKeepaliveGarbage),
            40 => Ok(Self::NetworkInformationServiceDomain),
            41 => Ok(Self::NetworkInformationServers),
            42 => Ok(Self::NetworkTimeProtocolServers),
            43 => Ok(Self::VendorSpecificInformation),
            44 => Ok(Self::NetBiosOverTcpIpNameServer),
            45 => Ok(Self::NetBiosOverTcpIpDatagramDistributionServer),
            46 => Ok(Self::NetBiosOverTcpIpNodeType),
            47 => Ok(Self::NetBiosOverTcpIpScope),
            48 => Ok(Self::XWindowSystemFontServer),
            49 => Ok(Self::XWindowSystemDisplayManager),
            50 => Ok(Self::RequestedIpAddress),
            51 => Ok(Self::IpAddressLeaseTime),
            52 => Ok(Self::OptionOverload),
            53 => Ok(Self::DhcpMessageType),
            54 => Ok(Self::ServerIdentifier),
            55 => Ok(Self::ParameterRequestList),
            56 => Ok(Self::Message),
            57 => Ok(Self::MaximumDhcpMessageSize),
            58 => Ok(Self::RenewalTimeValue),
            59 => Ok(Self::RebindingTimeValue),
            60 => Ok(Self::ClassIdentifier),
            61 => Ok(Self::ClientIdentifier),
            _ => Err(Error::InvalidOption(code)),
        }
    }
}

impl Decode for OptionCode {
    fn decode<B>(buf: B) -> Result<Self, Error>
    where
        B: Buf,
    {
        Self::from_u8(u8::decode(buf)?)
    }
}

/// A physical IEEE802 link-layer address.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct MacAddr {
    octets: [u8; 6],
}

impl MacAddr {
    pub fn from_octets(octets: [u8; 6]) -> Self {
        Self { octets }
    }

    pub fn octets(&self) -> [u8; 6] {
        self.octets
    }
}

impl Debug for MacAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            self.octets[0],
            self.octets[1],
            self.octets[2],
            self.octets[3],
            self.octets[4],
            self.octets[5],
        )
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct IpAddressLeaseTime(u32);

impl Encode for IpAddressLeaseTime {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        let len: u8 = 4;

        len.encode(&mut buf);
        self.0.encode(&mut buf);
    }
}

impl Decode for IpAddressLeaseTime {
    fn decode<B>(mut buf: B) -> Result<Self, Error>
    where
        B: Buf,
    {
        let _len = u8::decode(&mut buf)?;
        u32::decode(buf).map(Self)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct RenewalTimeValue(u32);

impl Encode for RenewalTimeValue {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        let len: u8 = 4;

        len.encode(&mut buf);
        self.0.encode(&mut buf);
    }
}

impl Decode for RenewalTimeValue {
    fn decode<B>(mut buf: B) -> Result<Self, Error>
    where
        B: Buf,
    {
        let _len = u8::decode(&mut buf)?;
        u32::decode(buf).map(Self)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct RebindingTimeValue(u32);

impl Encode for RebindingTimeValue {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        let len: u8 = 4;

        len.encode(&mut buf);
        self.0.encode(&mut buf);
    }
}

impl Decode for RebindingTimeValue {
    fn decode<B>(mut buf: B) -> Result<Self, Error>
    where
        B: Buf,
    {
        let _len = u8::decode(&mut buf)?;
        u32::decode(buf).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime};

    use crate::{Lease, MacAddr, TimeWheel};

    #[test]
    fn time_wheel_insert() {
        let mut wheel = TimeWheel::new();

        let lease0 = create_lease(0);
        std::thread::sleep(Duration::from_millis(100));
        let lease1 = create_lease(1);
        std::thread::sleep(Duration::from_millis(100));
        let lease2 = create_lease(2);

        wheel.insert(lease1);
        assert_eq!(wheel.leases.len(), 1);
        assert_eq!(wheel.leases[0].mac, MacAddr::from_octets([1; 6]));

        wheel.insert(lease2);
        assert_eq!(wheel.leases.len(), 2);
        assert_eq!(wheel.leases[0].mac, MacAddr::from_octets([1; 6]));
        assert_eq!(wheel.leases[1].mac, MacAddr::from_octets([2; 6]));

        wheel.insert(lease0);
        assert_eq!(wheel.leases.len(), 3);
        assert_eq!(wheel.leases[0].mac, MacAddr::from_octets([0; 6]));
        assert_eq!(wheel.leases[1].mac, MacAddr::from_octets([1; 6]));
        assert_eq!(wheel.leases[2].mac, MacAddr::from_octets([2; 6]));
    }

    fn create_lease(mac: u8) -> Lease {
        Lease {
            mac: MacAddr::from_octets([mac; 6]),
            ip: Ipv4Addr::UNSPECIFIED,
            valid_until: SystemTime::now(),
        }
    }
}
