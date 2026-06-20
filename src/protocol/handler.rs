use {
    crate::{
        Ipv4AddrPair,
        protocol::{
            Protocol, TcpConnections, icmp_echo::IcmpEchoHandler, tcp::TcpHandler, udp::UdpHandler,
        },
    },
    std::{
        fmt, io,
        time::{Duration, Instant},
    },
};

pub enum ProtocolHandler<'a> {
    Icmp(IcmpEchoHandler<'a>),
    Tcp(TcpHandler, Ipv4AddrPair),
    Udp(UdpHandler<'a>, Ipv4AddrPair),
}

impl<'a> ProtocolHandler<'a> {
    /// Parses `data` as the header and payload of a packet of protocol type `protocol`, returning a
    /// `ProtocolHandler` capable of writing replies.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the packet cannot be parsed as its type or is of an unimplemented type.
    pub fn parse(
        data: &'a [u8],
        protocol: Protocol,
        ip_pair: Ipv4AddrPair,
    ) -> Result<Self, String> {
        match protocol {
            Protocol::Icmp => IcmpEchoHandler::parse(data).map(Self::Icmp),
            Protocol::Tcp => TcpHandler::parse(data).map(|h| Self::Tcp(h, ip_pair)),
            Protocol::Udp => UdpHandler::parse(data).map(|h| Self::Udp(h, ip_pair)),
        }
    }

    /// Creates a protocol-specific header and payload for replying to `self`, or returns `Ok(None)`
    /// for no reply.
    pub fn into_reply(self, tcp_connections: &mut TcpConnections) -> io::Result<Option<Self>> {
        match self {
            Self::Icmp(handler) => Ok(Some(Self::Icmp(handler.create_reply()))),

            // Swap the source and destination IP addresses for the reply for UDP and TCP
            Self::Udp(handler, ip_pair) => {
                Ok(Some(Self::Udp(handler.create_reply(), ip_pair.swapped())))
            }

            // TCP is the only one that's actually optional
            Self::Tcp(handler, ip_pair) => Ok(handler
                .into_reply(tcp_connections, ip_pair)?
                .map(|h| Self::Tcp(h, ip_pair.swapped()))),
        }
    }

    /// Initiates active close for every established TCP connection, returning a `Self` ready to
    /// write as a FIN-ACK reply for each, along with the `Ipv4AddrPair` for its IPv4 header.
    pub fn close_established(tcp_connections: &mut TcpConnections) -> Vec<(Self, Ipv4AddrPair)> {
        TcpHandler::close_established(tcp_connections)
            .into_iter()
            .map(|(handler, ip_pair)| (Self::Tcp(handler, ip_pair), ip_pair))
            .collect()
    }

    /// Reproduces every TCP connection's pending unacked segment that is due for retransmission
    /// (`rto` elapsed since it was last sent), or gives up and removes the connection once it has
    /// been retried `max_retries` times.
    pub fn retransmit_expired(
        tcp_connections: &mut TcpConnections,
        now: Instant,
        rto: Duration,
        max_retries: u8,
    ) -> Vec<(Self, Ipv4AddrPair)> {
        TcpHandler::retransmit_expired(tcp_connections, now, rto, max_retries)
            .into_iter()
            .map(|(handler, ip_pair)| (Self::Tcp(handler, ip_pair), ip_pair))
            .collect()
    }

    /// Copies data from `self` to write the protocol-specific header and payload into `buf`,
    /// returning the number of bytes written.
    pub fn write_into(&self, buf: &mut [u8]) -> Result<u16, String> {
        match self {
            Self::Icmp(handler) => handler.write_into(buf),
            Self::Tcp(handler, ip_pair) => handler.write_into(buf, *ip_pair),
            Self::Udp(handler, ip_pair) => handler.write_into(buf, *ip_pair),
        }
    }
}

impl fmt::Display for ProtocolHandler<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Icmp(handler) => write!(f, "{handler}"),
            Self::Tcp(handler, _) => write!(f, "{handler}"),
            Self::Udp(handler, _) => write!(f, "{handler}"),
        }
    }
}
