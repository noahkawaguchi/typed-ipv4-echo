use crate::{
    ETHERNET_MTU, checksum,
    ipv4_packet::IPV4_HEADER_MIN_LEN,
    protocol::{Protocol, ProtocolHandler},
};
use std::fmt;

pub(super) struct UdpHandler<'a> {
    src_port: u16,
    dst_port: u16,
    payload: &'a [u8],
}

impl<'a> UdpHandler<'a> {
    const UDP_HEADER_LEN: u8 = 8;
    const PSEUDO_HEADER_LEN: usize = 12;

    pub(super) fn parse(data: &'a [u8]) -> Result<Self, String> {
        let n = data.len();

        if n < Self::UDP_HEADER_LEN.into() {
            return Err(format!("Too short for UDP header ({n} bytes)"));
        }

        Ok(Self {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            payload: &data[Self::UDP_HEADER_LEN.into()..],
        })
    }
}

impl ProtocolHandler for UdpHandler<'_> {
    fn write_reply(&self, reply: &mut [u8; ETHERNET_MTU]) -> Option<u16> {
        println!(
            "Received {} bytes of data: {}\nEchoing data back...",
            self.payload.len(),
            str::from_utf8(self.payload).unwrap_or("<non-UTF-8>")
        );

        let udp_start = usize::from(IPV4_HEADER_MIN_LEN);

        // UDP header
        // Swap src and dst ports
        reply[udp_start..udp_start + 2].copy_from_slice(&self.dst_port.to_be_bytes());
        reply[udp_start + 2..udp_start + 4].copy_from_slice(&self.src_port.to_be_bytes());

        // UDP length = header (8) + payload
        #[allow(clippy::cast_possible_truncation)] // `u16::MAX` (65_535) > `ETHERNET_MTU` (1500)
        let udp_len = u16::from(Self::UDP_HEADER_LEN) + self.payload.len() as u16;
        reply[udp_start + 4..udp_start + 6].copy_from_slice(&udp_len.to_be_bytes());

        // Checksum at bytes 6-7 calculated later

        // Copy payload for echo
        let payload_start = udp_start + usize::from(Self::UDP_HEADER_LEN);
        reply[payload_start..payload_start + self.payload.len()].copy_from_slice(self.payload);

        // Calculate UDP checksum with pseudo-header
        let mut pseudo_header = [0u8; Self::PSEUDO_HEADER_LEN];
        pseudo_header[0..4].copy_from_slice(&reply[12..16]); // Source IP
        pseudo_header[4..8].copy_from_slice(&reply[16..20]); // Dest IP
        pseudo_header[8] = 0; // Reserved padding for alignment
        pseudo_header[9] = Protocol::Udp.as_u8();
        pseudo_header[10..12].copy_from_slice(&udp_len.to_be_bytes());

        // Build checksum data: pseudo-header + UDP header + payload
        let checksum_len = Self::PSEUDO_HEADER_LEN + usize::from(udp_len);
        let mut checksum_data = [0u8; ETHERNET_MTU + Self::PSEUDO_HEADER_LEN];
        checksum_data[0..Self::PSEUDO_HEADER_LEN].copy_from_slice(&pseudo_header);
        checksum_data[Self::PSEUDO_HEADER_LEN..checksum_len]
            .copy_from_slice(&reply[udp_start..udp_start + usize::from(udp_len)]);

        // Zero out checksum field before calculating
        checksum_data[Self::PSEUDO_HEADER_LEN + 6] = 0;
        checksum_data[Self::PSEUDO_HEADER_LEN + 7] = 0;

        let udp_checksum = checksum::calculate(&checksum_data[..checksum_len]);
        reply[udp_start + 6..udp_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());

        // Total length: IPv4 header without options (20 bytes)
        //               + fixed UDP header length (8 bytes)
        //               + length of echo payload
        Some(u16::from(IPV4_HEADER_MIN_LEN) + udp_len)
    }
}

impl fmt::Display for UdpHandler<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UDP {} -> {}", self.src_port, self.dst_port)
    }
}
