mod icmp_echo;
mod tcp;
mod udp;

use crate::{
    ETHERNET_MTU,
    protocol::{icmp_echo::IcmpEchoHandler, tcp::TcpHandler, udp::UdpHandler},
};
use std::fmt;

const PROTOCOL_ICMP: u8 = 1;
const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_UDP: u8 = 17;

pub enum ProtocolHandler<'a> {
    Tcp(TcpHandler<'a>),
    Udp(UdpHandler<'a>),
    Icmp(IcmpEchoHandler<'a>),
}

impl<'a> ProtocolHandler<'a> {
    /// Parses `data` as the header and payload of a packet of protocol type `protocol`, returning a
    /// `ProtocolHandler` capable of writing replies.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the packet cannot be parsed as its type or is of an unimplemented type.
    pub fn parse(data: &'a [u8], protocol: Protocol) -> Result<Self, String> {
        match protocol {
            Protocol::Icmp => IcmpEchoHandler::parse(data).map(Self::Icmp),
            Protocol::Tcp => TcpHandler::parse(data).map(Self::Tcp),
            Protocol::Udp => UdpHandler::parse(data).map(Self::Udp),
            Protocol::Other(n) => Err(format!(
                "Protocol {n} not implemented, only ICMP Echo, TCP, and UDP"
            )),
        }
    }

    /// Writes the protocol-specific sections of the reply into the buffer, returning the total
    /// length of the reply packet in bytes (including the IP header and payload data), or
    /// `Ok(None)` if no reply should be sent.
    pub fn write_reply(&self, reply: &mut [u8; ETHERNET_MTU]) -> Result<Option<u16>, String> {
        match self {
            Self::Icmp(handler) => handler.write_reply(reply),
            Self::Tcp(handler) => handler.write_reply(reply),
            Self::Udp(handler) => handler.write_reply(reply),
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
