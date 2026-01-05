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

pub trait ProtocolHandler: fmt::Display {
    /// Writes the protocol-specific sections of the reply into the buffer, returning the total
    /// length of the reply packet in bytes (including the IP header and payload data), or `None` if
    /// no reply should be sent.
    fn write_reply(&self, reply: &mut [u8; ETHERNET_MTU]) -> Option<u16>;
}

/// Parses `data` as the header and payload of a packet of protocol type `protocol`, returning a
/// `ProtocolHandler` capable of writing replies.
///
/// # Errors
///
/// Returns `Err` if the packet is too short for its type or is of an unimplemented type.
pub fn parse_data<'a>(
    protocol: Protocol,
    data: &'a [u8],
) -> Result<Box<dyn ProtocolHandler + 'a>, String> {
    match protocol {
        Protocol::Icmp => Ok(Box::new(IcmpEchoHandler::parse(data)?) as Box<dyn ProtocolHandler>),
        Protocol::Tcp => Ok(Box::new(TcpHandler::parse(data)?) as Box<dyn ProtocolHandler>),
        Protocol::Udp => Ok(Box::new(UdpHandler::parse(data)?) as Box<dyn ProtocolHandler>),
        Protocol::Other(_) => Err(String::from("only ICMP Echo, TCP, and UDP implemented")),
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
