use crate::{ETHERNET_MTU, checksum, ipv4_packet::IPV4_HEADER_MIN_LEN, protocol::ProtocolHandler};
use std::fmt;

pub(super) struct IcmpEchoHandler<'a> {
    // Type and code are constant, must be 8 and 0
    identifier: u16,
    sequence: u16,
    payload: &'a [u8],
}

impl<'a> IcmpEchoHandler<'a> {
    const ICMP_HEADER_LEN: u8 = 8;
    const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
    const ICMP_TYPE_ECHO_REPLY: u8 = 0;
    const ICMP_CODE_ECHO: u8 = 0;

    pub(super) fn parse(data: &'a [u8]) -> Result<Self, String> {
        let n = data.len();

        if n < Self::ICMP_HEADER_LEN.into() {
            return Err(format!("Too short for ICMP header ({n} bytes)"));
        }

        let icmp_type = data[0];
        let icmp_code = data[1];

        // ICMP Echo Request (ping): type=8, code=0
        if icmp_type != Self::ICMP_TYPE_ECHO_REQUEST || icmp_code != Self::ICMP_CODE_ECHO {
            return Err(format!(
                "Not an Echo Request: got type={icmp_type}, code={icmp_code}"
            ));
        }

        Ok(Self {
            identifier: u16::from_be_bytes([data[4], data[5]]),
            sequence: u16::from_be_bytes([data[6], data[7]]),
            payload: &data[Self::ICMP_HEADER_LEN.into()..],
        })
    }
}

impl ProtocolHandler for IcmpEchoHandler<'_> {
    fn write_reply(&self, reply: &mut [u8; ETHERNET_MTU]) -> Option<u16> {
        println!("Building ICMP Echo Reply...");

        let icmp_start = IPV4_HEADER_MIN_LEN.into();
        let payload_start = icmp_start + usize::from(Self::ICMP_HEADER_LEN);

        // Copy payload into reply
        reply[payload_start..payload_start + self.payload.len()].copy_from_slice(self.payload);

        // ICMP Echo Reply header
        reply[icmp_start] = Self::ICMP_TYPE_ECHO_REPLY;
        reply[icmp_start + 1] = Self::ICMP_CODE_ECHO;

        // Checksum at bytes 2-3 calculated later

        // Identifier and sequence for echo request/reply
        reply[icmp_start + 4..icmp_start + 6].copy_from_slice(&self.identifier.to_be_bytes());
        reply[icmp_start + 6..icmp_start + 8].copy_from_slice(&self.sequence.to_be_bytes());

        // Clear ICMP checksum field before recalculating
        reply[icmp_start + 2] = 0;
        reply[icmp_start + 3] = 0;

        // Calculate ICMP checksum (covers the entire ICMP message: header + payload)
        let icmp_checksum = checksum::calculate(
            &reply
                [icmp_start..icmp_start + usize::from(Self::ICMP_HEADER_LEN) + self.payload.len()],
        );
        reply[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

        // Total length: IPv4 header without options (20 bytes)
        //               + fixed ICMP header length (8 bytes)
        //               + length of echo payload
        #[allow(clippy::cast_possible_truncation)] // `u16::MAX` (65_535) > `ETHERNET_MTU` (1500)
        Some(
            u16::from(IPV4_HEADER_MIN_LEN)
                + u16::from(Self::ICMP_HEADER_LEN)
                + self.payload.len() as u16,
        )
    }
}

impl fmt::Display for IcmpEchoHandler<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ICMP type={} code={} (Echo Request) | identifier={} sequence={}",
            Self::ICMP_TYPE_ECHO_REQUEST,
            Self::ICMP_CODE_ECHO,
            self.identifier,
            self.sequence,
        )
    }
}
