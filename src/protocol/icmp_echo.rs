use crate::{
    ETHERNET_MTU, checksum,
    ipv4_packet::{IPV4_HDR_MIN_LEN_U8, IPV4_HDR_MIN_LEN_USIZE},
    try_ops::{TryAdd, TryGet, TryGetMut},
};
use std::fmt;

const ICMP_HEADER_LEN: u8 = 8;

/// Struct for managing ICMP Echo Request packets and creating Echo Reply packets. Includes the ICMP
/// type-specific data and the payload.
pub struct IcmpEchoHandler<'a> {
    // Type and code are omitted because they are constant (must be 8 and 0 for Echo Request)
    identifier: u16,
    sequence: u16,
    payload: &'a [u8],
}

impl<'a> IcmpEchoHandler<'a> {
    const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
    const ICMP_TYPE_ECHO_REPLY: u8 = 0;
    const ICMP_CODE_ECHO: u8 = 0;

    /// Parses `data` as an ICMP Echo Request header and payload.
    pub fn parse(data: &'a [u8]) -> Result<Self, String> {
        let Some(icmp_header) = data.first_chunk::<{ ICMP_HEADER_LEN as usize }>() else {
            return Err(format!("Too short for ICMP header ({} bytes)", data.len()));
        };

        let icmp_type = icmp_header[0];
        let icmp_code = icmp_header[1];

        // ICMP Echo Request (ping): type=8, code=0
        if icmp_type != Self::ICMP_TYPE_ECHO_REQUEST || icmp_code != Self::ICMP_CODE_ECHO {
            return Err(format!(
                "Not an Echo Request: got type={icmp_type}, code={icmp_code}"
            ));
        }

        Ok(Self {
            identifier: u16::from_be_bytes([icmp_header[4], icmp_header[5]]),
            sequence: u16::from_be_bytes([icmp_header[6], icmp_header[7]]),
            payload: data
                .get(ICMP_HEADER_LEN.into()..)
                .ok_or("No data after ICMP header")?,
        })
    }

    pub fn write_reply(&self, reply: &mut [u8; ETHERNET_MTU]) -> Result<Option<u16>, String> {
        const ICMP_START: usize = IPV4_HDR_MIN_LEN_USIZE;
        const PAYLOAD_START: usize = ICMP_START + ICMP_HEADER_LEN as usize;

        println!("Building ICMP Echo Reply...");

        // Copy payload into reply
        reply
            .try_get_mut(PAYLOAD_START..PAYLOAD_START.try_add(self.payload.len())?)?
            .copy_from_slice(self.payload);

        // ICMP Echo Reply header
        reply[ICMP_START] = Self::ICMP_TYPE_ECHO_REPLY;
        reply[ICMP_START + 1] = Self::ICMP_CODE_ECHO;

        // Checksum at bytes 2-3 calculated later

        // Identifier and sequence for echo request/reply
        reply[ICMP_START + 4..ICMP_START + 6].copy_from_slice(&self.identifier.to_be_bytes());
        reply[ICMP_START + 6..ICMP_START + 8].copy_from_slice(&self.sequence.to_be_bytes());

        // Clear ICMP checksum field before recalculating
        reply[ICMP_START + 2] = 0;
        reply[ICMP_START + 3] = 0;

        // Calculate ICMP checksum (covers the entire ICMP message: header + payload)
        let icmp_checksum = checksum::calculate(reply.try_get(
            ICMP_START..(ICMP_START + usize::from(ICMP_HEADER_LEN)).try_add(self.payload.len())?,
        )?);
        reply[ICMP_START + 2..ICMP_START + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

        #[expect(
            clippy::cast_possible_truncation,
            reason = "u16::MAX (65_535) > ETHERNET_MTU (1500)"
        )]
        Ok(Some(
            // Total length: IPv4 header without options (20 bytes)
            //               + fixed ICMP header length (8 bytes)
            //               + length of echo payload
            u16::from(IPV4_HDR_MIN_LEN_U8 + ICMP_HEADER_LEN).try_add(self.payload.len() as u16)?,
        ))
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

    #[test]
    fn correctly_parses_valid_request() -> Result<(), String> {
        #[rustfmt::skip]
        let data = [
            8, 0,              // Type 8 (Echo Request), Code 0
            0x3a, 0x4b,        // Checksum
            0x12, 0x34,        // Identifier: 0x1234
            0x56, 0x78,        // Sequence: 0x5678
            0x41, 0x42, 0x43,  // Payload: "ABC"
        ];

        let handler = IcmpEchoHandler::parse(&data)?;

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
    fn handles_empty_payload() -> Result<(), String> {
        #[rustfmt::skip]
        let data = [
            8, 0,              // Type 8 (Echo Request), Code 0
            0x3a, 0x4b,        // Checksum
            0x00, 0x00,        // Identifier: 0
            0x00, 0x01,        // Sequence: 1
        ];

        let handler = IcmpEchoHandler::parse(&data)?;

        assert_eq!(handler.identifier, 0);
        assert_eq!(handler.sequence, 1);
        assert_eq!(handler.payload.len(), 0);

        Ok(())
    }

    #[test]
    fn creates_valid_echo_reply() -> Result<(), String> {
        #[rustfmt::skip]
        let request = [
            8, 0,                          // Type 8 (Echo Request), Code 0
            0x3a, 0x4b,                    // Checksum
            0x12, 0x34,                    // Identifier: 0x1234
            0x56, 0x78,                    // Sequence: 0x5678
            0x48, 0x65, 0x6c, 0x6c, 0x6f,  // Payload: "Hello"
        ];

        let handler = IcmpEchoHandler::parse(&request)?;
        let mut reply = [0u8; ETHERNET_MTU];

        // Set up IP header portion (bytes 12-19 are source and dest IPs)
        reply[12..16].copy_from_slice(&[10, 0, 0, 2]); // Source: 10.0.0.2
        reply[16..20].copy_from_slice(&[10, 0, 0, 1]); // Dest: 10.0.0.1

        let total_len = handler
            .write_reply(&mut reply)?
            .ok_or("failed to write reply")?;

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
        let checksum = checksum::calculate(reply.try_get(20..20 + usize::from(icmp_len))?);
        assert_eq!(checksum, 0x0000);

        Ok(())
    }
}
