use {
    crate::{
        Result,
        addr_pairs::Ipv4AddrPair,
        endpoint::{Endpoint, Local, Remote},
        protocol::{
            Protocol,
            display::PrettyPayload,
            icmp_echo::IcmpEchoMsg,
            tcp::{TcpConnections, TcpSegment},
            udp::UdpDatagram,
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

/// Enum for static dispatch over the supported protocol-specific structs. Sent from `S`.
#[cfg_attr(test, derive(Debug))]
pub enum ProtocolRouter<'a, S: Endpoint> {
    Icmp(IcmpEchoMsg<'a, S>),
    Tcp(TcpSegment<S>),
    Udp(UdpDatagram<'a, S>),
}

impl<'a> ProtocolRouter<'a, Remote> {
    /// Parses `data` as the header and payload of a packet of protocol type `protocol`.
    pub fn parse(
        data: &'a [u8],
        protocol: Protocol,
        ip_pair: Ipv4AddrPair<Remote>,
    ) -> Result<Self> {
        match protocol {
            Protocol::Icmp => IcmpEchoMsg::parse(data, ip_pair)
                .map(Self::Icmp)
                .map_err(Into::into),
            Protocol::Tcp => TcpSegment::parse(data, ip_pair).map(Self::Tcp),
            Protocol::Udp => UdpDatagram::parse(data, ip_pair).map(Self::Udp),
        }
    }

    /// Creates a protocol-specific header and payload for replying to `self`, or returns `Ok(None)`
    /// for no reply.
    pub fn create_reply(
        &self,
        tcp_connections: &mut TcpConnections,
    ) -> Result<Option<ProtocolRouter<'a, Local>>> {
        Ok(match self {
            Self::Icmp(msg) => Some(ProtocolRouter::<Local>::Icmp(msg.create_reply())),

            // TCP is the only one that's actually optional or fallible
            Self::Tcp(seg) => seg
                .create_reply(tcp_connections)?
                .map(ProtocolRouter::<Local>::Tcp),

            Self::Udp(dgram) => Some(ProtocolRouter::<Local>::Udp(dgram.create_reply())),
        })
    }
}

impl Encode<Local> for ProtocolRouter<'_, Local> {
    fn write_into(&self, buf: &mut [u8]) -> Result<u16> {
        match self {
            Self::Icmp(msg) => msg.write_into(buf),
            Self::Tcp(seg) => seg.write_into(buf),
            Self::Udp(dgram) => dgram.write_into(buf),
        }
    }

    fn proto(&self) -> Protocol {
        match self {
            Self::Icmp(msg) => msg.proto(),
            Self::Tcp(seg) => seg.proto(),
            Self::Udp(dgram) => dgram.proto(),
        }
    }

    fn get_ip_pair(&self) -> Ipv4AddrPair<Local> {
        match self {
            Self::Icmp(msg) => msg.get_ip_pair(),
            Self::Tcp(seg) => seg.get_ip_pair(),
            Self::Udp(dgram) => dgram.get_ip_pair(),
        }
    }
}

impl<S: Endpoint> PrettyProtocol for ProtocolRouter<'_, S> {
    fn pretty_payload(&self, include_content: bool) -> PrettyPayload<'_> {
        match self {
            Self::Icmp(msg) => msg.pretty_payload(include_content),
            Self::Tcp(seg) => seg.pretty_payload(include_content),
            Self::Udp(dgram) => dgram.pretty_payload(include_content),
        }
    }
}

impl<S: Endpoint> fmt::Display for ProtocolRouter<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Icmp(msg) => write!(f, "{msg}"),
            Self::Tcp(seg) => write!(f, "{seg}"),
            Self::Udp(dgram) => write!(f, "{dgram}"),
        }
    }
}
