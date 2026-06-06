use crate::{
    ETHERNET_MTU, checksum,
    protocol::{Protocol, payload_to_string},
    try_ops::{TryAdd, TryGet, TryGetMut},
};
use std::{fmt, net::Ipv4Addr};

const UDP_HEADER_LEN: u16 = 8;

/// Struct for managing and replying to UDP packets. Includes the UDP header and the payload.
#[cfg_attr(test, derive(Debug))]
pub struct UdpHandler<'a> {
    src_port: u16,
    dst_port: u16,
    payload: &'a [u8],
}

impl<'a> UdpHandler<'a> {
    const PSEUDO_HEADER_LEN: usize = 12;

    /// Parses `data` as a UDP header and payload.
    pub fn parse(data: &'a [u8]) -> Result<Self, String> {
        let Some(udp_header) = data.first_chunk::<{ UDP_HEADER_LEN as usize }>() else {
            return Err(format!("Too short for UDP header ({} bytes)", data.len()));
        };

        Ok(Self {
            src_port: u16::from_be_bytes([udp_header[0], udp_header[1]]),
            dst_port: u16::from_be_bytes([udp_header[2], udp_header[3]]),
            payload: data
                .get(UDP_HEADER_LEN.into()..)
                .ok_or("No data after UDP header")?,
        })
    }

    /// Creates a UDP header and payload for replying to `self`.
    pub const fn create_reply(&self) -> Self {
        // Swap source and destination ports, echo payload
        Self { src_port: self.dst_port, dst_port: self.src_port, payload: self.payload }
    }

    /// Copies data from `self` to write a UDP header and payload into `buf`, returning the number
    /// of bytes written.
    pub fn write_into(
        &self,
        buf: &mut [u8],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
    ) -> Result<u16, String> {
        // Source and destination ports
        buf.try_get_mut(..2)?
            .copy_from_slice(&self.src_port.to_be_bytes());
        buf.try_get_mut(2..4)?
            .copy_from_slice(&self.dst_port.to_be_bytes());

        // UDP length: fixed UDP header length (8 bytes) + length of echo payload
        #[expect(
            clippy::cast_possible_truncation,
            reason = "u16::MAX (65_535) > ETHERNET_MTU (1500)"
        )]
        let udp_len = UDP_HEADER_LEN.try_add(self.payload.len() as u16)?;
        buf.try_get_mut(4..6)?
            .copy_from_slice(&udp_len.to_be_bytes());

        // Checksum at bytes 6-7 calculated later with pseudo-header

        // Copy payload for echo
        buf.try_get_mut(
            usize::from(UDP_HEADER_LEN)..usize::from(UDP_HEADER_LEN).try_add(self.payload.len())?,
        )?
        .copy_from_slice(self.payload);

        // Calculate UDP checksum with pseudo-header
        let mut pseudo_header = [0u8; Self::PSEUDO_HEADER_LEN];
        pseudo_header[0..4].copy_from_slice(&src_ip.octets()); // Source IP
        pseudo_header[4..8].copy_from_slice(&dst_ip.octets()); // Dest IP
        pseudo_header[8] = 0; // Reserved padding for alignment
        pseudo_header[9] = Protocol::Udp.into();
        pseudo_header[10..12].copy_from_slice(&udp_len.to_be_bytes());

        // Build checksum data: pseudo-header + UDP header + payload
        let checksum_len = Self::PSEUDO_HEADER_LEN + usize::from(udp_len);
        let mut checksum_data = [0u8; ETHERNET_MTU + Self::PSEUDO_HEADER_LEN];
        checksum_data[0..Self::PSEUDO_HEADER_LEN].copy_from_slice(&pseudo_header);
        checksum_data
            .try_get_mut(Self::PSEUDO_HEADER_LEN..checksum_len)?
            .copy_from_slice(buf.try_get(..usize::from(udp_len))?);

        // Zero out checksum field before calculating
        checksum_data[Self::PSEUDO_HEADER_LEN + 6..Self::PSEUDO_HEADER_LEN + 8]
            .copy_from_slice(&[0x00, 0x00]);

        let udp_checksum = checksum::calculate(checksum_data.try_get(..checksum_len)?);
        buf.try_get_mut(6..8)?
            .copy_from_slice(&udp_checksum.to_be_bytes());

        Ok(udp_len)
    }
}

impl fmt::Display for UdpHandler<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UDP | {} -> {}\n{}",
            self.src_port,
            self.dst_port,
            payload_to_string(self.payload)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn correctly_parses_valid_packet() -> Result<(), String> {
        #[rustfmt::skip]
        const DATA: [u8; 16] = [
            0x04, 0xd2,              // Source port: 1234
            0x00, 0x35,              // Dest port: 53 (DNS)
            0x00, 0x10,              // Length: 16 (8 byte header + 8 byte payload)
            0x00, 0x00,              // Checksum
            0x48, 0x65, 0x6c, 0x6c,  // Payload: "Hell"
            0x6f, 0x21, 0x21, 0x21,  // Payload: "o!!!"
        ];

        let handler = UdpHandler::parse(&DATA)?;

        assert_eq!(handler.src_port, 1234);
        assert_eq!(handler.dst_port, 53);
        assert_eq!(handler.payload, b"Hello!!!");

        Ok(())
    }

    #[test]
    fn parsing_fails_when_too_short() {
        const DATA: [u8; 3] = [0x04, 0xd2, 0x00]; // Only 3 bytes
        assert_matches!(UdpHandler::parse(&DATA), Err(e) if e.contains("Too short"));
    }

    #[test]
    fn parsing_handles_empty_payload() -> Result<(), String> {
        #[rustfmt::skip]
        const DATA: [u8; 8] = [
            0x1f, 0x90,              // Source port: 8080
            0x00, 0x50,              // Dest port: 80
            0x00, 0x08,              // Length: 8 (header only, no payload)
            0x00, 0x00,              // Checksum
        ];

        let handler = UdpHandler::parse(&DATA)?;

        assert_eq!(handler.src_port, 8080);
        assert_eq!(handler.dst_port, 80);
        assert_eq!(handler.payload.len(), 0);

        Ok(())
    }

    #[test]
    fn extracts_ports_correctly() -> Result<(), String> {
        #[rustfmt::skip]
        const DATA: [u8; 12] = [
            0xff, 0xff,              // Source port: 65535 (max)
            0x00, 0x01,              // Dest port: 1 (min non-zero)
            0x00, 0x0c,              // Length: 12
            0x00, 0x00,              // Checksum
            0x74, 0x65, 0x73, 0x74,  // Payload: "test"
        ];

        let handler = UdpHandler::parse(&DATA)?;

        assert_eq!(handler.src_port, 65535);
        assert_eq!(handler.dst_port, 1);

        Ok(())
    }

    #[test]
    fn creates_valid_echo_reply() -> Result<(), String> {
        #[rustfmt::skip]
        const REQUEST: [u8; 16] = [
            0x04, 0xd2,              // Source port: 1234
            0x00, 0x35,              // Dest port: 53
            0x00, 0x10,              // Length: 16
            0x00, 0x00,              // Checksum
            0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x21, 0x21,  // Payload: "Hello!!!"
        ];

        // Set up addresses from IP header
        const SRC_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2); // Source: 10.0.0.2
        const DST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1); // Dest: 10.0.0.1

        let handler = UdpHandler::parse(&REQUEST)?;
        let mut reply = [0u8; ETHERNET_MTU];

        let udp_len = handler
            .create_reply()
            .write_into(&mut reply[20..], SRC_IP, DST_IP)?;

        // Verify UDP header at offset 20
        assert_eq!(&reply[20..22], &[0x00, 0x35]); // Source port: 53 (swapped)
        assert_eq!(&reply[22..24], &[0x04, 0xd2]); // Dest port: 1234 (swapped)
        assert_eq!(&reply[24..26], &[0x00, 0x10]); // Length: 16

        // Verify payload echoed
        assert_eq!(&reply[28..36], b"Hello!!!");

        // Verify UDP length
        assert_eq!(udp_len, 8 + 8);

        // Verify checksum is valid using pseudo-header
        let mut pseudo_header = [0u8; 12];
        pseudo_header[0..4].copy_from_slice(&SRC_IP.octets()); // Source IP
        pseudo_header[4..8].copy_from_slice(&DST_IP.octets()); // Dest IP
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
