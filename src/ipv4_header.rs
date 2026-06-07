use crate::{ETHERNET_MTU, Ipv4AddrPair, checksum, protocol::Protocol, try_ops::TryAdd};
use std::{fmt, net::Ipv4Addr};

/// The minimum number of bytes for an IPv4 header (no options) as a `u8`.
const IPV4_HDR_MIN_LEN_U8: u8 = 20;

/// The minimum number of bytes for an IPv4 header (no options) as a `usize`.
const IPV4_HDR_MIN_LEN_USIZE: usize = IPV4_HDR_MIN_LEN_U8 as usize;

/// Struct for managing IPv4 packet header fields and replies.
#[cfg_attr(test, derive(Debug))]
pub struct Ipv4Header {
    pub total_len: u16,
    pub protocol: Protocol,
    pub ip_pair: Ipv4AddrPair,
}

impl Ipv4Header {
    /// The length in bytes of an IPv4 header for a reply packet (no options).
    pub const REPLY_HEADER_LEN: usize = IPV4_HDR_MIN_LEN_USIZE;

    /// Parses `data` as an IPv4 packet, returning the header fields and a slice starting at the
    /// beginning of the payload.
    pub fn parse(data: &[u8]) -> Result<(Self, &[u8]), String> {
        let Some(ip_header) = data.first_chunk::<IPV4_HDR_MIN_LEN_USIZE>() else {
            return Err(format!("Too short for IPv4 header ({} bytes)", data.len()));
        };

        // Must be IPv4
        match ip_header[0] >> 4 {
            4 => {}
            6 => return Err(String::from("IPv6 packet")),
            version => return Err(format!("Unexpected IP version {version}")),
        }

        let ihl_bytes = usize::from(ip_header[0] & 0xF) * 4; // Convert 32-bit words to bytes

        Ok((
            Self {
                total_len: u16::from_be_bytes([ip_header[2], ip_header[3]]),
                protocol: Protocol::from(ip_header[9]),
                ip_pair: Ipv4AddrPair {
                    src: Ipv4Addr::new(ip_header[12], ip_header[13], ip_header[14], ip_header[15]),
                    dst: Ipv4Addr::new(ip_header[16], ip_header[17], ip_header[18], ip_header[19]),
                },
            },
            data.get(ihl_bytes..).ok_or("Data shorter than its IHL")?,
        ))
    }

    /// Creates an IPv4 header for replying to `self`. Total length is the length of the IP header +
    /// `proto_len`. Source and destination addresses are swapped from the original packet.
    pub fn create_reply(&self, proto_len: u16) -> Result<Self, String> {
        Ok(Self {
            total_len: u16::from(IPV4_HDR_MIN_LEN_U8).try_add(proto_len)?,
            protocol: self.protocol,
            ip_pair: self.ip_pair.swapped(),
        })
    }

    /// Writes an IPv4 header into `buf`, copying the header data from `self`.
    pub fn write_into(&self, buf: &mut [u8; ETHERNET_MTU]) {
        // IP header (no options, 20 bytes)
        buf[0] = 0x40 | (IPV4_HDR_MIN_LEN_U8 / 4); // Version 4, IHL 5 (20 bytes)
        buf[1] = 0x00; // DSCP/ECN
        buf[2..4].copy_from_slice(&self.total_len.to_be_bytes()); // Total length
        buf[4..6].copy_from_slice(&[0x00, 0x00]); // Identification
        buf[6..8].copy_from_slice(&[0x40, 0x00]); // Flags + Fragment offset (Don't Fragment)
        buf[8] = 64; // TTL
        buf[9] = self.protocol.into(); // Protocol

        // Clear IP header checksum field before recalculating
        buf[10..12].copy_from_slice(&[0x00, 0x00]);

        buf[12..16].copy_from_slice(&self.ip_pair.src.octets());
        buf[16..20].copy_from_slice(&self.ip_pair.dst.octets());

        // Recalculate IP header checksum (covers only the IP header, always 20 bytes for replies)
        let ip_checksum = checksum::calculate(&buf[..IPV4_HDR_MIN_LEN_USIZE]);
        buf[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    }
}

impl fmt::Display for Ipv4Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IPv4 | {} bytes total | {} | {} -> {}",
            self.total_len, self.protocol, self.ip_pair.src, self.ip_pair.dst,
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
        const DATA: [u8; 20] = [
            0x45, 0x00, 0x00, 0x3c,  // Version 4, IHL 5, TOS 0, Total Length 60
            0x1c, 0x46, 0x40, 0x00,  // ID, Flags, Fragment Offset
            0x40, 0x06, 0xb1, 0xe6,  // TTL 64, Protocol 6 (TCP), Checksum
            192, 168, 1, 100,        // Source IP: 192.168.1.100
            172, 16, 10, 12,         // Dest IP: 172.16.10.12
        ];

        let (header, payload) = Ipv4Header::parse(&DATA)?;

        assert_eq!(header.total_len, 60);
        assert_eq!(header.protocol, Protocol::Tcp);
        assert_eq!(header.ip_pair.src, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(header.ip_pair.dst, Ipv4Addr::new(172, 16, 10, 12));
        assert_eq!(payload, &DATA[20..]);

        Ok(())
    }

    #[test]
    fn parsing_fails_if_too_short() {
        const DATA: [u8; 3] = [0x45, 0x00, 0x00]; // Only 3 bytes
        assert_matches!(Ipv4Header::parse(&DATA), Err(e) if e.contains("Too short"));
    }

    #[test]
    fn parsing_fails_if_not_ipv4() {
        #[rustfmt::skip]
        const DATA: [u8; 24] = [
            0x60, 0x00, 0x00, 0x00,  // Version 6 (IPv6), not 4
            0x00, 0x14, 0x06, 0x40,
            0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ];

        assert_matches!(Ipv4Header::parse(&DATA), Err(e) if e.contains("IPv6"));
    }

    #[test]
    fn creates_valid_ipv4_header_for_reply() -> Result<(), String> {
        #[rustfmt::skip]
        const REQUEST: [u8; 20] = [
            0x45, 0x00, 0x00, 0x3c,  // Version 4, IHL 5, TOS 0, Total Length 60
            0x1c, 0x46, 0x40, 0x00,  // ID, Flags, Fragment Offset
            0x40, 0x11, 0xb1, 0xe6,  // TTL 64, Protocol 17 (UDP), Checksum
            192, 168, 1, 100,        // Source IP: 192.168.1.100
            172, 16, 10, 12,         // Dest IP: 172.16.10.12
        ];

        let (header, _) = Ipv4Header::parse(&REQUEST)?;
        let mut reply = [0u8; ETHERNET_MTU];
        let proto_len = 48 - 20; // Total length - IPv4 reply header length
        let reply_header = header.create_reply(proto_len)?;
        reply_header.write_into(&mut reply);
        assert_eq!(reply_header.total_len, 48);

        // Verify IPv4 header fields
        assert_eq!(reply[0], 0x45); // Version 4, IHL 5
        assert_eq!(reply[1], 0x00); // DSCP/ECN
        assert_eq!(&reply[2..4], &[0x00, 0x30]); // Total length: 48
        assert_eq!(&reply[4..6], &[0x00, 0x00]); // Identification: 0
        assert_eq!(&reply[6..8], &[0x40, 0x00]); // Flags: Don't Fragment
        assert_eq!(reply[8], 64); // TTL: 64
        assert_eq!(reply[9], 0x11); // Protocol: 17 (UDP)

        // Verify IPs are swapped
        assert_eq!(&reply[12..16], &[172, 16, 10, 12]); // Source (was dest)
        assert_eq!(&reply[16..20], &[192, 168, 1, 100]); // Dest (was source)

        // Verify IP header checksum is valid
        let ip_checksum = checksum::calculate(&reply[..20]);
        assert_eq!(ip_checksum, 0x0000);

        Ok(())
    }
}
