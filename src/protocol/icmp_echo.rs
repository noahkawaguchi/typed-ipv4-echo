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

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, anyhow};

    #[test]
    fn correctly_parses_valid_request() -> Result<()> {
        #[rustfmt::skip]
        let data = [
            8, 0,              // Type 8 (Echo Request), Code 0
            0x3a, 0x4b,        // Checksum
            0x12, 0x34,        // Identifier: 0x1234
            0x56, 0x78,        // Sequence: 0x5678
            0x41, 0x42, 0x43,  // Payload: "ABC"
        ];

        let handler = IcmpEchoHandler::parse(&data).map_err(|e| anyhow!(e))?;

        assert_eq!(handler.identifier, 0x1234);
        assert_eq!(handler.sequence, 0x5678);
        assert_eq!(handler.payload, &[0x41, 0x42, 0x43]);

        Ok(())
    }

    #[test]
    fn parsing_fails_when_too_short() {
        let data = [8, 0, 0x3a, 0x4b, 0x12]; // Only 5 bytes
        assert!(IcmpEchoHandler::parse(&data).is_err_and(|e| e.contains("Too short")));
    }

    #[test]
    fn parsing_fails_when_wrong_icmp_type() {
        #[rustfmt::skip]
        let data = [
            0, 0,              // Type 0 (Echo Reply), Code 0
            0x3a, 0x4b,        // Checksum
            0x12, 0x34,        // Identifier
            0x56, 0x78,        // Sequence
        ];

        assert!(IcmpEchoHandler::parse(&data).is_err_and(|e| e.contains("Not an Echo Request")));
    }

    #[test]
    fn parsing_fails_when_wrong_icmp_code() {
        #[rustfmt::skip]
        let data = [
            8, 1,              // Type 8 (Echo Request), Code 1 (invalid)
            0x3a, 0x4b,        // Checksum
            0x12, 0x34,        // Identifier
            0x56, 0x78,        // Sequence
        ];

        assert!(IcmpEchoHandler::parse(&data).is_err_and(|e| e.contains("Not an Echo Request")));
    }

    #[test]
    fn handles_empty_payload() -> Result<()> {
        #[rustfmt::skip]
        let data = [
            8, 0,              // Type 8 (Echo Request), Code 0
            0x3a, 0x4b,        // Checksum
            0x00, 0x00,        // Identifier: 0
            0x00, 0x01,        // Sequence: 1
        ];

        let handler = IcmpEchoHandler::parse(&data).map_err(|e| anyhow!(e))?;

        assert_eq!(handler.identifier, 0);
        assert_eq!(handler.sequence, 1);
        assert_eq!(handler.payload.len(), 0);

        Ok(())
    }

    #[test]
    fn creates_valid_echo_reply() -> Result<()> {
        #[rustfmt::skip]
        let request = [
            8, 0,                          // Type 8 (Echo Request), Code 0
            0x3a, 0x4b,                    // Checksum
            0x12, 0x34,                    // Identifier: 0x1234
            0x56, 0x78,                    // Sequence: 0x5678
            0x48, 0x65, 0x6c, 0x6c, 0x6f,  // Payload: "Hello"
        ];

        let handler = IcmpEchoHandler::parse(&request).map_err(|e| anyhow!(e))?;
        let mut reply = [0u8; ETHERNET_MTU];

        // Set up IP header portion (bytes 12-19 are source and dest IPs)
        reply[12..16].copy_from_slice(&[10, 0, 0, 2]); // Source: 10.0.0.2
        reply[16..20].copy_from_slice(&[10, 0, 0, 1]); // Dest: 10.0.0.1

        let total_len = handler
            .write_reply(&mut reply)
            .context("failed to write reply")?;

        // Verify ICMP header at offset 20
        assert_eq!(reply[20], 0); // Type 0 (Echo Reply)
        assert_eq!(reply[21], 0); // Code 0
        assert_eq!(&reply[24..26], &[0x12, 0x34]); // Identifier preserved
        assert_eq!(&reply[26..28], &[0x56, 0x78]); // Sequence preserved

        // Verify payload echoed
        assert_eq!(&reply[28..33], b"Hello");

        // Verify total length
        assert_eq!(total_len, 20 + 8 + 5);

        // Verify checksum is valid (checksum of ICMP message should be 0)
        let icmp_len = total_len - 20;
        let checksum = checksum::calculate(&reply[20..20 + usize::from(icmp_len)]);
        assert_eq!(checksum, 0x0000);

        Ok(())
    }
}
