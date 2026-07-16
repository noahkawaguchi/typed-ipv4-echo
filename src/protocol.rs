pub mod handler;
pub use tcp::TcpConnections;

mod icmp_echo;
mod tcp;
mod udp;

use {
    crate::{
        ETHERNET_MTU, Result,
        addr_pairs::Ipv4AddrPair,
        checksum,
        try_ops::{TryGet as _, TryGetMut as _},
    },
    std::fmt,
};

/// Calculates the TCP/UDP checksum of the pseudo-header + `data`. `data` should be the TCP/UDP
/// header and payload. Does not zero out the checksum field inside the header of `data` before
/// calculating.
fn pseudo_header_checksum(data: &[u8], ip_pair: Ipv4AddrPair, protocol: Protocol) -> Result<u16> {
    /// The number of bytes in a TCP/UDP pseudo-header.
    const PSEUDO_HDR_LEN: usize = 12;

    let proto_len = u16::try_from(data.len())?;
    let checksum_len = PSEUDO_HDR_LEN + usize::from(proto_len);

    let mut checksum_data = [0u8; PSEUDO_HDR_LEN + ETHERNET_MTU];
    checksum_data[0..4].copy_from_slice(&ip_pair.src.octets());
    checksum_data[4..8].copy_from_slice(&ip_pair.dst.octets());
    // Byte 8 is reserved padding for alignment
    checksum_data[9] = protocol.into();
    checksum_data[10..12].copy_from_slice(&proto_len.to_be_bytes());
    checksum_data
        .try_get_mut(PSEUDO_HDR_LEN..checksum_len)?
        .copy_from_slice(data);

    Ok(checksum::calculate(checksum_data.try_get(..checksum_len)?))
}

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

/// Test constants shared between protocols.
#[cfg(test)]
mod test_consts {
    use {crate::addr_pairs::Ipv4AddrPair, std::net::Ipv4Addr};

    /// Test source IP address: 10.0.0.2
    pub const SRC_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    /// Test destination IP address: 10.0.0.1
    pub const DST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

    /// An `Ipv4AddrPair` of `SRC_IP` and `DST_IP`.
    pub const IP_PAIR: Ipv4AddrPair = Ipv4AddrPair { src: SRC_IP, dst: DST_IP };
}
