use crate::{
    ETHERNET_MTU, checksum,
    ipv4_packet::IPV4_HEADER_MIN_LEN,
    protocol::{Protocol, ProtocolHandler},
};
use std::fmt;

/// Struct for managing and replying to UDP packets. Includes the UDP header and the payload.
pub(super) struct UdpHandler<'a> {
    src_port: u16,
    dst_port: u16,
    payload: &'a [u8],
}

impl<'a> UdpHandler<'a> {
    const UDP_HEADER_LEN: u8 = 8;
    const PSEUDO_HEADER_LEN: usize = 12;

    /// Parses `data` as a UDP header and payload.
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
        pseudo_header[9] = Protocol::Udp.into();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correctly_parses_valid_packet() -> Result<(), String> {
        #[rustfmt::skip]
        let data = [
            0x04, 0xd2,              // Source port: 1234
            0x00, 0x35,              // Dest port: 53 (DNS)
            0x00, 0x10,              // Length: 16 (8 byte header + 8 byte payload)
            0x00, 0x00,              // Checksum
            0x48, 0x65, 0x6c, 0x6c,  // Payload: "Hell"
            0x6f, 0x21, 0x21, 0x21,  // Payload: "o!!!"
        ];

        let handler = UdpHandler::parse(&data)?;

        assert_eq!(handler.src_port, 1234);
        assert_eq!(handler.dst_port, 53);
        assert_eq!(handler.payload, b"Hello!!!");

        Ok(())
    }

    #[test]
    fn parsing_fails_when_too_short() {
        let data = [0x04, 0xd2, 0x00]; // Only 3 bytes
        assert!(UdpHandler::parse(&data).is_err_and(|e| e.contains("Too short")));
    }

    #[test]
    fn parsing_handles_empty_payload() -> Result<(), String> {
        #[rustfmt::skip]
        let data = [
            0x1f, 0x90,              // Source port: 8080
            0x00, 0x50,              // Dest port: 80
            0x00, 0x08,              // Length: 8 (header only, no payload)
            0x00, 0x00,              // Checksum
        ];

        let handler = UdpHandler::parse(&data)?;

        assert_eq!(handler.src_port, 8080);
        assert_eq!(handler.dst_port, 80);
        assert_eq!(handler.payload.len(), 0);

        Ok(())
    }

    #[test]
    fn extracts_ports_correctly() -> Result<(), String> {
        #[rustfmt::skip]
        let data = [
            0xff, 0xff,              // Source port: 65535 (max)
            0x00, 0x01,              // Dest port: 1 (min non-zero)
            0x00, 0x0c,              // Length: 12
            0x00, 0x00,              // Checksum
            0x74, 0x65, 0x73, 0x74,  // Payload: "test"
        ];

        let handler = UdpHandler::parse(&data)?;

        assert_eq!(handler.src_port, 65535);
        assert_eq!(handler.dst_port, 1);

        Ok(())
    }

    #[test]
    fn creates_valid_echo_reply() -> Result<(), String> {
        #[rustfmt::skip]
        let request = [
            0x04, 0xd2,              // Source port: 1234
            0x00, 0x35,              // Dest port: 53
            0x00, 0x10,              // Length: 16
            0x00, 0x00,              // Checksum
            0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x21, 0x21,  // Payload: "Hello!!!"
        ];

        let handler = UdpHandler::parse(&request)?;
        let mut reply = [0u8; ETHERNET_MTU];

        // Set up IP header portion (bytes 12-19 are source and dest IPs)
        reply[12..16].copy_from_slice(&[10, 0, 0, 2]); // Source: 10.0.0.2
        reply[16..20].copy_from_slice(&[10, 0, 0, 1]); // Dest: 10.0.0.1

        let total_len = handler
            .write_reply(&mut reply)
            .ok_or("failed to write reply")?;

        // Verify UDP header at offset 20
        assert_eq!(&reply[20..22], &[0x00, 0x35]); // Source port: 53 (swapped)
        assert_eq!(&reply[22..24], &[0x04, 0xd2]); // Dest port: 1234 (swapped)
        assert_eq!(&reply[24..26], &[0x00, 0x10]); // Length: 16

        // Verify payload echoed
        assert_eq!(&reply[28..36], b"Hello!!!");

        // Verify total length
        assert_eq!(total_len, 20 + 8 + 8);

        // Verify checksum is valid using pseudo-header
        let udp_len = 16u16;
        let mut pseudo_header = [0u8; 12];
        pseudo_header[0..4].copy_from_slice(&reply[12..16]); // Source IP
        pseudo_header[4..8].copy_from_slice(&reply[16..20]); // Dest IP
        pseudo_header[8] = 0; // Reserved
        pseudo_header[9] = Protocol::Udp.into();
        pseudo_header[10..12].copy_from_slice(&udp_len.to_be_bytes());

        let mut checksum_data = [0u8; 12 + 16];
        checksum_data[0..12].copy_from_slice(&pseudo_header);
        checksum_data[12..28].copy_from_slice(&reply[20..36]);

        let checksum = checksum::calculate(&checksum_data);
        assert_eq!(checksum, 0x0000);

        Ok(())
    }
}
