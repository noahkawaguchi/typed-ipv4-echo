use crate::{
    ETHERNET_MTU, checksum,
    protocol::Protocol,
    protocol_header::{self, ProtocolHeader},
};
use std::{fmt, net::Ipv4Addr};

pub const IPV4_HEADER_MIN_LEN: u8 = 20;

pub struct Ipv4Packet<'a> {
    ipv4_header: Ipv4Header,
    protocol_header: Box<dyn ProtocolHeader>,
    payload: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, String> {
        let ipv4_header = Ipv4Header::parse(data)?;

        let protocol_header =
            protocol_header::parse(&data[ipv4_header.ihl_bytes..], &ipv4_header.protocol)?;

        let payload = &data[ipv4_header.ihl_bytes + protocol_header.len()..];

        Ok(Self { ipv4_header, protocol_header, payload })
    }

    pub fn create_reply(&self) -> Option<([u8; ETHERNET_MTU], usize)> {
        let mut reply = [0u8; ETHERNET_MTU];

        // IP header (no options, 20 bytes)
        reply[0] = 0x40 | (IPV4_HEADER_MIN_LEN / 4); // Version 4, IHL 5 (20 bytes)
        reply[1] = 0x00; // DSCP/ECN
        // Total length at [2..4] set later depending on protocol
        reply[4..6].copy_from_slice(&[0x00, 0x00]); // Identification
        reply[6..8].copy_from_slice(&[0x40, 0x00]); // Flags + Fragment offset (Don't Fragment)
        reply[8] = 64; // TTL
        reply[9] = self.ipv4_header.protocol.as_u8(); // Protocol

        // Swap src and dst IP addresses
        reply[12..16].copy_from_slice(&self.ipv4_header.dst_ip.octets());
        reply[16..20].copy_from_slice(&self.ipv4_header.src_ip.octets());

        // Let protocol handler fill in protocol-specific data and calculate total length
        let total_len = self.protocol_header.write_reply(&mut reply, self.payload)?;

        // Fill in total length before calculating checksum
        reply[2..4].copy_from_slice(&total_len.to_be_bytes());

        // Clear IP header checksum field before recalculating
        reply[10] = 0;
        reply[11] = 0;

        // Recalculate IP header checksum (covers only the IP header, always 20 bytes for replies)
        let ip_checksum = checksum::calculate(&reply[..usize::from(IPV4_HEADER_MIN_LEN)]);
        reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        Some((reply, total_len.into()))
    }
}

impl fmt::Display for Ipv4Packet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\n{}", self.ipv4_header, self.protocol_header)
    }
}

struct Ipv4Header {
    ihl_bytes: usize,
    total_len: u16,
    protocol: Protocol,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
}

impl Ipv4Header {
    fn parse(data: &[u8]) -> Result<Self, String> {
        let n = data.len();

        if n < IPV4_HEADER_MIN_LEN.into() {
            return Err(format!("Too short for IPv4 header ({n} bytes)"));
        }

        let version = data[0] >> 4;
        if version != 4 {
            return Err(format!("Non-IPv4 packet (version {version}), skipping"));
        }

        Ok(Self {
            ihl_bytes: usize::from(data[0] & 0xF) * 4, // Convert 32-bit words to bytes
            total_len: u16::from_be_bytes([data[2], data[3]]),
            protocol: Protocol::from_u8(data[9]),
            src_ip: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
            dst_ip: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
        })
    }
}

impl fmt::Display for Ipv4Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IPv4 | {} bytes | {} | {} -> {}",
            self.total_len, self.protocol, self.src_ip, self.dst_ip,
        )
    }
}
