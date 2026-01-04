mod icmp_echo;
mod tcp;
mod udp;

use crate::{
    ETHERNET_MTU,
    protocol::{icmp_echo::IcmpEchoHandler, tcp::TcpHandler, udp::UdpHandler},
};
use std::fmt;

pub trait ProtocolHandler: std::fmt::Display {
    /// Writes the protocol-specific sections of the reply into the buffer, returning the total
    /// length of the reply packet in bytes (including the IP header and payload data), or `None` if
    /// no reply should be sent.
    fn write_reply(&self, reply: &mut [u8; ETHERNET_MTU]) -> Option<u16>;
}

pub enum Protocol {
    Icmp,
    Tcp,
    Udp,
    Other(u8),
}

impl Protocol {
    pub const fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            other => Self::Other(other),
        }
    }

    pub const fn as_u8(&self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Other(other) => *other,
        }
    }

    /// Parses `data` as the header and payload of a packet of the protocol type of `self`,
    /// returning a `ProtocolHandler` capable of writing replies.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the packet is too short for its type or is of an unimplemented type.
    pub fn parse_data<'a>(&self, data: &'a [u8]) -> Result<Box<dyn ProtocolHandler + 'a>, String> {
        match self {
            Self::Icmp => Ok(Box::new(IcmpEchoHandler::parse(data)?) as Box<dyn ProtocolHandler>),
            Self::Tcp => Ok(Box::new(TcpHandler::parse(data)?) as Box<dyn ProtocolHandler>),
            Self::Udp => Ok(Box::new(UdpHandler::parse(data)?) as Box<dyn ProtocolHandler>),
            Self::Other(_) => Err(String::from("only ICMP Echo, TCP, and UDP implemented")),
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
