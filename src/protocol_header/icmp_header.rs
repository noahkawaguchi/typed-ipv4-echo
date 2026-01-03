use crate::{
    ETHERNET_MTU, checksum, ipv4_packet::IPV4_HEADER_MIN_LEN, protocol_header::ProtocolHeader,
};
use std::fmt;

const ICMP_HEADER_LEN: u8 = 8;

pub(super) struct IcmpHeader {
    icmp_type: u8,
    icmp_code: u8,
    identifier: u16, // Specific to echo
    sequence: u16,   // Specific to echo
}

impl IcmpHeader {
    pub(super) fn parse(data: &[u8]) -> Result<Self, String> {
        let n = data.len();

        if n < ICMP_HEADER_LEN.into() {
            return Err(format!("Too short for ICMP header ({n} bytes)"));
        }

        Ok(Self {
            icmp_type: data[0],
            icmp_code: data[1],
            identifier: u16::from_be_bytes([data[4], data[5]]),
            sequence: u16::from_be_bytes([data[6], data[7]]),
        })
    }
}

impl ProtocolHeader for IcmpHeader {
    fn len(&self) -> usize { ICMP_HEADER_LEN.into() }

    fn write_reply_header(&self, reply: &mut [u8; ETHERNET_MTU], payload: &[u8]) -> Option<usize> {
        // ICMP Echo Request (ping): type=8, code=0
        if self.icmp_type != 8 || self.icmp_code != 0 {
            return None;
        }

        println!("Building ICMP echo reply...");

        #[allow(clippy::cast_possible_truncation)] // `u16::MAX` (65_535) > `ETHERNET_MTU` (1500)
        let payload_len = { payload.len() as u16 };

        // Total length: IPv4 header without options (20 bytes)
        //               + fixed ICMP header length (8 bytes)
        //               + length of echo payload
        let total_len = u16::from(IPV4_HEADER_MIN_LEN) + u16::from(ICMP_HEADER_LEN) + payload_len;
        reply[2..4].copy_from_slice(&total_len.to_be_bytes());

        let icmp_start = IPV4_HEADER_MIN_LEN.into();
        let payload_start = icmp_start + usize::from(ICMP_HEADER_LEN);

        // Copy payload into reply
        reply[payload_start..payload_start + payload.len()].copy_from_slice(payload);

        // ICMP Echo Reply header
        reply[icmp_start] = 0; // Type: Echo Reply
        reply[icmp_start + 1] = 0; // Code: 0

        // Checksum at bytes 2-3 calculated later

        // Identifier and sequence for echo request/reply
        reply[icmp_start + 4..icmp_start + 6].copy_from_slice(&self.identifier.to_be_bytes());
        reply[icmp_start + 6..icmp_start + 8].copy_from_slice(&self.sequence.to_be_bytes());

        // Clear ICMP checksum field before recalculating
        reply[icmp_start + 2] = 0;
        reply[icmp_start + 3] = 0;

        // Calculate ICMP checksum (covers the entire ICMP message: header + payload)
        let icmp_checksum = checksum::calculate(
            &reply[icmp_start..icmp_start + usize::from(ICMP_HEADER_LEN) + payload.len()],
        );
        reply[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

        Some(total_len.into())
    }
}

impl fmt::Display for IcmpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ICMP type={} code={}", self.icmp_type, self.icmp_code)
    }
}
