use crate::{
    checksum,
    protocol::payload_to_string,
    try_ops::{TryAdd as _, TryGet as _, TryGetMut as _},
};
use std::fmt;

const ICMP_HEADER_LEN: u16 = 8;

/// Struct for managing ICMP Echo Request packets and creating Echo Reply packets. Includes the ICMP
/// header and the payload.
#[cfg_attr(test, derive(Debug))]
pub struct IcmpEchoHandler<'a> {
    icmp_type: u8,
    // The code field is omitted because it is constant 0 for Echo Request/Reply
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
        let Some((icmp_header, payload)) = data.split_first_chunk::<{ ICMP_HEADER_LEN as usize }>()
        else {
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
            icmp_type,
            identifier: u16::from_be_bytes([icmp_header[4], icmp_header[5]]),
            sequence: u16::from_be_bytes([icmp_header[6], icmp_header[7]]),
            payload,
        })
    }

    /// Creates an ICMP header and payload for replying to `self`.
    pub const fn create_reply(&self) -> Self {
        // ICMP Echo Reply:
        // - Change type from 8 to 0
        // - Keep the same identifier, sequence number, and payload data
        Self {
            icmp_type: Self::ICMP_TYPE_ECHO_REPLY,
            identifier: self.identifier,
            sequence: self.sequence,
            payload: self.payload,
        }
    }

    /// Copies data from `self` to write an ICMP header and payload into `buf`, returning the number
    /// of bytes written.
    pub fn write_into(&self, buf: &mut [u8]) -> Result<u16, String> {
        // Copy echo payload
        buf.try_get_mut(
            usize::from(ICMP_HEADER_LEN)
                ..usize::from(ICMP_HEADER_LEN).try_add(self.payload.len())?,
        )?
        .copy_from_slice(self.payload);

        // ICMP Echo type and code
        *buf.try_get_mut(0)? = self.icmp_type;
        *buf.try_get_mut(1)? = Self::ICMP_CODE_ECHO;

        // Clear ICMP checksum field before recalculating
        buf.try_get_mut(2..4)?.copy_from_slice(&[0x00, 0x00]);

        // Identifier and sequence for echo request/reply
        buf.try_get_mut(4..6)?
            .copy_from_slice(&self.identifier.to_be_bytes());
        buf.try_get_mut(6..8)?
            .copy_from_slice(&self.sequence.to_be_bytes());

        // ICMP length: fixed ICMP header length (8 bytes) + length of echo payload
        #[expect(
            clippy::cast_possible_truncation,
            reason = "u16::MAX (65_535) > ETHERNET_MTU (1500)"
        )]
        let icmp_len = ICMP_HEADER_LEN.try_add(self.payload.len() as u16)?;

        // Calculate ICMP checksum (covers the entire ICMP message: header + payload)
        let icmp_checksum = checksum::calculate(buf.try_get(..usize::from(icmp_len))?);
        buf.try_get_mut(2..4)?
            .copy_from_slice(&icmp_checksum.to_be_bytes());

        Ok(icmp_len)
    }
}

impl fmt::Display for IcmpEchoHandler<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ICMP | type={} code={} ({}) | identifier={} sequence={}\n{}",
            self.icmp_type,
            Self::ICMP_CODE_ECHO,
            match self.icmp_type {
                Self::ICMP_TYPE_ECHO_REQUEST => "Echo Request",
                Self::ICMP_TYPE_ECHO_REPLY => "Echo Reply",
                _ => "unknown type",
            },
            self.identifier,
            self.sequence,
            payload_to_string(self.payload),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ETHERNET_MTU;
    use std::assert_matches;

    #[test]
    fn correctly_parses_valid_request() -> Result<(), String> {
        #[rustfmt::skip]
        const DATA: [u8; 11] = [
            8, 0,              // Type 8 (Echo Request), Code 0
            0x3a, 0x4b,        // Checksum
            0x12, 0x34,        // Identifier: 0x1234
            0x56, 0x78,        // Sequence: 0x5678
            0x41, 0x42, 0x43,  // Payload: "ABC"
        ];

        let handler = IcmpEchoHandler::parse(&DATA)?;

        assert_eq!(handler.identifier, 0x1234);
        assert_eq!(handler.sequence, 0x5678);
        assert_eq!(handler.payload, &[0x41, 0x42, 0x43]);

        Ok(())
    }

    #[test]
    fn parsing_fails_when_too_short() {
        const DATA: [u8; 5] = [8, 0, 0x3a, 0x4b, 0x12]; // Only 5 bytes
        assert_matches!(IcmpEchoHandler::parse(&DATA), Err(e) if e.contains("Too short"));
    }

    #[test]
    fn parsing_fails_when_wrong_icmp_type() {
        #[rustfmt::skip]
        const DATA: [u8; 8] = [
            0, 0,              // Type 0 (Echo Reply), Code 0
            0x3a, 0x4b,        // Checksum
            0x12, 0x34,        // Identifier
            0x56, 0x78,        // Sequence
        ];

        assert_matches!(IcmpEchoHandler::parse(&DATA), Err(e) if e.contains("Not an Echo Request"));
    }

    #[test]
    fn parsing_fails_when_wrong_icmp_code() {
        #[rustfmt::skip]
        const DATA: [u8; 8] = [
            8, 1,              // Type 8 (Echo Request), Code 1 (invalid)
            0x3a, 0x4b,        // Checksum
            0x12, 0x34,        // Identifier
            0x56, 0x78,        // Sequence
        ];

        assert_matches!(IcmpEchoHandler::parse(&DATA), Err(e) if e.contains("Not an Echo Request"));
    }

    #[test]
    fn handles_empty_payload() -> Result<(), String> {
        #[rustfmt::skip]
        const DATA: [u8; 8] = [
            8, 0,              // Type 8 (Echo Request), Code 0
            0x3a, 0x4b,        // Checksum
            0x00, 0x00,        // Identifier: 0
            0x00, 0x01,        // Sequence: 1
        ];

        let handler = IcmpEchoHandler::parse(&DATA)?;

        assert_eq!(handler.identifier, 0);
        assert_eq!(handler.sequence, 1);
        assert_eq!(handler.payload.len(), 0);

        Ok(())
    }

    #[test]
    fn creates_valid_echo_reply() -> Result<(), String> {
        #[rustfmt::skip]
        const REQUEST: [u8; 13] = [
            8, 0,                          // Type 8 (Echo Request), Code 0
            0x3a, 0x4b,                    // Checksum
            0x12, 0x34,                    // Identifier: 0x1234
            0x56, 0x78,                    // Sequence: 0x5678
            0x48, 0x65, 0x6c, 0x6c, 0x6f,  // Payload: "Hello"
        ];

        let handler = IcmpEchoHandler::parse(&REQUEST)?;
        let mut reply = [0u8; ETHERNET_MTU];

        let icmp_len = handler.create_reply().write_into(&mut reply[20..])?;

        // Verify ICMP header at offset 20
        assert_eq!(reply[20], 0); // Type 0 (Echo Reply)
        assert_eq!(reply[21], 0); // Code 0
        assert_eq!(&reply[24..26], &[0x12, 0x34]); // Identifier preserved
        assert_eq!(&reply[26..28], &[0x56, 0x78]); // Sequence preserved

        // Verify payload echoed
        assert_eq!(&reply[28..33], b"Hello");

        // Verify ICMP length
        assert_eq!(icmp_len, 8 + 5);

        // Verify checksum is valid (checksum of ICMP message should be 0)
        let checksum = checksum::calculate(reply.try_get(20..20 + usize::from(icmp_len))?);
        assert_eq!(checksum, 0x0000);

        Ok(())
    }
}
