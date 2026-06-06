mod icmp_echo;
mod tcp;
mod udp;

use crate::protocol::{icmp_echo::IcmpEchoHandler, tcp::TcpHandler, udp::UdpHandler};
use std::{fmt, io, net::Ipv4Addr};
pub use tcp::TcpConnections;

const PROTOCOL_ICMP: u8 = 1;
const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_UDP: u8 = 17;

/// Converts raw payload bytes to a printable string representation of the payload's length and
/// content. Escapes control and non-printable characters.
fn payload_to_string(payload: &[u8]) -> String {
    match str::from_utf8(payload) {
        Err(_) => format!(
            "{}-byte non-UTF-8 payload: {}",
            payload.len(),
            payload.escape_ascii()
        ),

        Ok("") => String::from("<no payload>"),

        Ok(s) => format!("{}-byte payload: {}", payload.len(), s.escape_debug()),
    }
}

pub enum ProtocolHandler<'a> {
    Icmp(IcmpEchoHandler<'a>),
    Tcp(TcpHandler<'a>, Ipv4Addr, Ipv4Addr),
    Udp(UdpHandler<'a>, Ipv4Addr, Ipv4Addr),
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
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
    ) -> Result<Self, String> {
        match protocol {
            Protocol::Icmp => IcmpEchoHandler::parse(data).map(Self::Icmp),
            Protocol::Tcp => TcpHandler::parse(data).map(|h| Self::Tcp(h, src_ip, dst_ip)),
            Protocol::Udp => UdpHandler::parse(data).map(|h| Self::Udp(h, src_ip, dst_ip)),
            Protocol::Other(other) => Err(format!(
                "Protocol {other} not implemented, only ICMP Echo, TCP, and UDP"
            )),
        }
    }

    /// Creates a protocol-specific header and payload for replying to `self`, or returns `Ok(None)`
    /// for no reply.
    pub fn create_reply(
        &self,
        tcp_connections: &mut TcpConnections,
    ) -> Result<Option<Self>, io::Error> {
        match self {
            Self::Icmp(handler) => Ok(Some(Self::Icmp(handler.create_reply()))),

            // Swap the source and destination IP addresses for the reply for UDP and TCP
            Self::Udp(handler, src_ip, dst_ip) => {
                Ok(Some(Self::Udp(handler.create_reply(), *dst_ip, *src_ip)))
            }

            // TCP is the only one that's actually optional
            Self::Tcp(handler, src_ip, dst_ip) => Ok(handler
                .create_reply(*src_ip, *dst_ip, tcp_connections)?
                .map(|h| Self::Tcp(h, *dst_ip, *src_ip))),
        }
    }

    /// Copies data from `self` to write the protocol-specific header and payload into `buf`,
    /// returning the number of bytes written.
    pub fn write_into(&self, buf: &mut [u8]) -> Result<u16, String> {
        match self {
            Self::Icmp(handler) => handler.write_into(buf),
            Self::Tcp(handler, src_ip, dst_ip) => handler.write_into(buf, *src_ip, *dst_ip),
            Self::Udp(handler, src_ip, dst_ip) => handler.write_into(buf, *src_ip, *dst_ip),
        }
    }
}

impl fmt::Display for ProtocolHandler<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Icmp(handler) => write!(f, "{handler}"),
            Self::Tcp(handler, _, _) => write!(f, "{handler}"),
            Self::Udp(handler, _, _) => write!(f, "{handler}"),
        }
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum Protocol {
    Icmp,
    Tcp,
    Udp,
    Other(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            PROTOCOL_ICMP => Self::Icmp,
            PROTOCOL_TCP => Self::Tcp,
            PROTOCOL_UDP => Self::Udp,
            other => Self::Other(other),
        }
    }
}

impl From<Protocol> for u8 {
    fn from(value: Protocol) -> Self {
        match value {
            Protocol::Icmp => PROTOCOL_ICMP,
            Protocol::Tcp => PROTOCOL_TCP,
            Protocol::Udp => PROTOCOL_UDP,
            Protocol::Other(other) => other,
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Icmp => write!(f, "ICMP"),
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Other(val) => write!(f, "Other ({val})"),
        }
    }
}
