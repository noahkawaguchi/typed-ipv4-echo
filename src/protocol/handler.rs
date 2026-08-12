use {
    crate::{
        Result,
        addr_pairs::Ipv4AddrPair,
        endpoint::{Endpoint, Local, Remote},
        protocol::{
            Protocol,
            display::PrettyPayload,
            icmp_echo::IcmpEchoHandler,
            tcp::{TcpConnections, TcpHandler},
            udp::UdpHandler,
        },
    },
    std::fmt,
};

/// Protocol-handling types that can be displayed as a string and can have their payload pretty
/// printed.
pub trait PrettyProtocol: fmt::Display {
    /// Wraps raw payload bytes that may be UTF-8, non-UTF-8, or empty in a `PrettyPayload` for
    /// pretty printing. If `include_content` is `false`, prints length only.
    fn pretty_payload(&self, include_content: bool) -> PrettyPayload<'_>;
}

/// Pretty protocol-handling types that can also be encoded into a byte buffer.
pub trait Encode<S: Endpoint>: PrettyProtocol {
    /// Copies data from `self` to write the protocol-specific header and payload into `buf`,
    /// returning the number of bytes written.
    fn write_into(&self, buf: &mut [u8]) -> Result<u16>;

    /// Returns the protocol of `self`.
    fn proto(&self) -> Protocol;

    /// Returns the pair of IPv4 addresses of `self`.
    fn get_ip_pair(&self) -> Ipv4AddrPair<S>;
}

/// Enum for static dispatch over the supported protocol-specific handlers. Sent from `S`.
#[cfg_attr(test, derive(Debug))]
pub enum ProtocolHandler<'a, S: Endpoint> {
    Icmp(IcmpEchoHandler<'a, S>),
    Tcp(TcpHandler<S>),
    Udp(UdpHandler<'a, S>),
}

impl<'a> ProtocolHandler<'a, Remote> {
    /// Parses `data` as the header and payload of a packet of protocol type `protocol`.
    pub fn parse(
        data: &'a [u8],
        protocol: Protocol,
        ip_pair: Ipv4AddrPair<Remote>,
    ) -> Result<Self> {
        match protocol {
            Protocol::Icmp => IcmpEchoHandler::parse(data, ip_pair)
                .map(Self::Icmp)
                .map_err(Into::into),
            Protocol::Tcp => TcpHandler::parse(data, ip_pair).map(Self::Tcp),
            Protocol::Udp => UdpHandler::parse(data, ip_pair).map(Self::Udp),
        }
    }

    /// Creates a protocol-specific header and payload for replying to `self`, or returns `Ok(None)`
    /// for no reply.
    pub fn create_reply(
        &self,
        tcp_connections: &mut TcpConnections,
    ) -> Result<Option<ProtocolHandler<'a, Local>>> {
        Ok(match self {
            Self::Icmp(handler) => Some(ProtocolHandler::<Local>::Icmp(handler.create_reply())),

            // TCP is the only one that's actually optional or fallible
            Self::Tcp(handler) => handler
                .create_reply(tcp_connections)?
                .map(ProtocolHandler::<Local>::Tcp),

            Self::Udp(handler) => Some(ProtocolHandler::<Local>::Udp(handler.create_reply())),
        })
    }
}

impl Encode<Local> for ProtocolHandler<'_, Local> {
    fn write_into(&self, buf: &mut [u8]) -> Result<u16> {
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

    fn get_ip_pair(&self) -> Ipv4AddrPair<Local> {
        match self {
            Self::Icmp(handler) => handler.get_ip_pair(),
            Self::Tcp(handler) => handler.get_ip_pair(),
            Self::Udp(handler) => handler.get_ip_pair(),
        }
    }
}

impl<S: Endpoint> PrettyProtocol for ProtocolHandler<'_, S> {
    fn pretty_payload(&self, include_content: bool) -> PrettyPayload<'_> {
        match self {
            Self::Icmp(handler) => handler.pretty_payload(include_content),
            Self::Tcp(handler) => handler.pretty_payload(include_content),
            Self::Udp(handler) => handler.pretty_payload(include_content),
        }
    }
}

impl<S: Endpoint> fmt::Display for ProtocolHandler<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Icmp(handler) => write!(f, "{handler}"),
            Self::Tcp(handler) => write!(f, "{handler}"),
            Self::Udp(handler) => write!(f, "{handler}"),
        }
    }
}
