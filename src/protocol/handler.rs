use {
    crate::{
        addr_pairs::Ipv4AddrPair,
        protocol::{
            Protocol, TcpConnections, icmp_echo::IcmpEchoHandler, tcp::TcpHandler, udp::UdpHandler,
        },
    },
    std::{fmt, io},
};

/// Trait for protocol-handling types that can be encoded into a byte buffer.
pub trait Encode: fmt::Display {
    /// Copies data from `self` to write the protocol-specific header and payload into `buf`,
    /// returning the number of bytes written.
    fn write_into(&self, buf: &mut [u8]) -> Result<u16, String>;

    /// Returns the protocol of `self`.
    fn proto(&self) -> Protocol;

    /// Returns the pair of IPv4 addresses of `self`.
    fn get_ip_pair(&self) -> Ipv4AddrPair;
}

/// Enum for static dispatch over the supported protocol-specific handlers.
pub enum ProtocolHandler<'a> {
    Icmp(IcmpEchoHandler<'a>),
    Tcp(TcpHandler),
    Udp(UdpHandler<'a>),
}

impl<'a> ProtocolHandler<'a> {
    /// Parses `data` as the header and payload of a packet of protocol type `protocol`.
    pub fn parse(
        data: &'a [u8],
        protocol: Protocol,
        ip_pair: Ipv4AddrPair,
    ) -> Result<Self, String> {
        match protocol {
            Protocol::Icmp => IcmpEchoHandler::parse(data, ip_pair).map(Self::Icmp),
            Protocol::Tcp => TcpHandler::parse(data, ip_pair).map(Self::Tcp),
            Protocol::Udp => UdpHandler::parse(data, ip_pair).map(Self::Udp),
        }
    }

    /// Creates a protocol-specific header and payload for replying to `self`, or returns `Ok(None)`
    /// for no reply.
    pub fn into_reply(self, tcp_connections: &mut TcpConnections) -> io::Result<Option<Self>> {
        match self {
            Self::Icmp(handler) => Ok(Some(Self::Icmp(handler.create_reply()))),
            // TCP is the only one that's actually optional or fallible
            Self::Tcp(handler) => Ok(handler.into_reply(tcp_connections)?.map(Self::Tcp)),
            Self::Udp(handler) => Ok(Some(Self::Udp(handler.create_reply()))),
        }
    }
}

impl Encode for ProtocolHandler<'_> {
    fn write_into(&self, buf: &mut [u8]) -> Result<u16, String> {
        match self {
            Self::Icmp(handler) => handler.write_into(buf),
            Self::Tcp(handler) => handler.write_into(buf),
            Self::Udp(handler) => handler.write_into(buf),
        }
    }

    fn proto(&self) -> Protocol {
        match self {
            Self::Icmp(handler) => handler.proto(),
            Self::Tcp(handler) => handler.proto(),
            Self::Udp(handler) => handler.proto(),
        }
    }

    fn get_ip_pair(&self) -> Ipv4AddrPair {
        match self {
            Self::Icmp(handler) => handler.get_ip_pair(),
            Self::Tcp(handler) => handler.get_ip_pair(),
            Self::Udp(handler) => handler.get_ip_pair(),
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
