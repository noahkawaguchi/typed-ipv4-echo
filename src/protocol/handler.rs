use {
    crate::{
        addr_pairs::Ipv4AddrPair,
        protocol::{
            Protocol, TcpConnections, icmp_echo::IcmpEchoHandler, tcp::TcpHandler, udp::UdpHandler,
        },
    },
    std::{fmt, io},
};

/// Trait for protocol-handling types that can be encoded into a byte buffer (and displayed as a
/// string).
pub trait Encode: fmt::Display {
    /// Copies data from `self` to write the protocol-specific header and payload into `buf`,
    /// returning the number of bytes written.
    fn write_into(&self, buf: &mut [u8], ip_pair: Ipv4AddrPair) -> Result<u16, String>;
}

pub enum ProtocolHandler<'a> {
    Icmp(IcmpEchoHandler<'a>),
    Tcp(TcpHandler),
    Udp(UdpHandler<'a>),
}

impl<'a> ProtocolHandler<'a> {
    /// Parses `data` as the header and payload of a packet of protocol type `protocol`.
    pub fn parse(data: &'a [u8], protocol: Protocol) -> Result<Self, String> {
        match protocol {
            Protocol::Icmp => IcmpEchoHandler::parse(data).map(Self::Icmp),
            Protocol::Tcp => TcpHandler::parse(data).map(Self::Tcp),
            Protocol::Udp => UdpHandler::parse(data).map(Self::Udp),
        }
    }

    /// Creates a protocol-specific header and payload for replying to `self`, or returns `Ok(None)`
    /// for no reply.
    pub fn into_reply(
        self,
        tcp_connections: &mut TcpConnections,
        ip_pair: Ipv4AddrPair,
    ) -> io::Result<Option<Self>> {
        match self {
            Self::Icmp(handler) => Ok(Some(Self::Icmp(handler.create_reply()))),
            Self::Udp(handler) => Ok(Some(Self::Udp(handler.create_reply()))),
            // TCP is the only one that's actually optional or fallible
            Self::Tcp(handler) => Ok(handler.into_reply(tcp_connections, ip_pair)?.map(Self::Tcp)),
        }
    }
}

impl Encode for ProtocolHandler<'_> {
    fn write_into(&self, buf: &mut [u8], ip_pair: Ipv4AddrPair) -> Result<u16, String> {
        match self {
            Self::Icmp(handler) => handler.write_into(buf, ip_pair),
            Self::Tcp(handler) => handler.write_into(buf, ip_pair),
            Self::Udp(handler) => handler.write_into(buf, ip_pair),
        }
    }
}

impl fmt::Display for ProtocolHandler<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Icmp(handler) => write!(f, "{handler}"),
            Self::Tcp(handler) => write!(f, "{handler}"),
            Self::Udp(handler) => write!(f, "{handler}"),
        }
    }
}
