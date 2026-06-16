pub use {handler::ProtocolHandler, tcp::TcpConnections};

mod handler;
mod icmp_echo;
mod tcp;
mod udp;

#[cfg(test)]
mod test_utils;

use std::fmt;

const PROTOCOL_ICMP: u8 = 1;
const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_UDP: u8 = 17;

/// Converts raw payload bytes to a printable string representation of the payload's length and
/// content. Escapes control and non-printable characters.
fn payload_to_string(payload: &[u8]) -> String {
    match str::from_utf8(payload) {
        Ok("") => String::from("<no payload>"),
        Ok(s) => format!("{}-byte payload: {}", payload.len(), s.escape_debug()),
        Err(_) => format!("{}-byte non-UTF-8 payload: {}", payload.len(), payload.escape_ascii()),
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
