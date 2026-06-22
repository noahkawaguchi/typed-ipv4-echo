pub mod handler;
pub use tcp::TcpConnections;

mod icmp_echo;
mod tcp;
mod udp;

#[cfg(test)]
mod test_utils;

use std::fmt;

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
#[repr(u8)]
pub enum Protocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
}

impl TryFrom<u8> for Protocol {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        const ICMP: u8 = Protocol::Icmp as u8;
        const TCP: u8 = Protocol::Tcp as u8;
        const UDP: u8 = Protocol::Udp as u8;

        match value {
            ICMP => Ok(Self::Icmp),
            TCP => Ok(Self::Tcp),
            UDP => Ok(Self::Udp),
            other => Err(format!("Unsupported protocol {other}")),
        }
    }
}

impl From<Protocol> for u8 {
    fn from(value: Protocol) -> Self { value as Self }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Icmp => write!(f, "ICMP"),
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
        }
    }
}
