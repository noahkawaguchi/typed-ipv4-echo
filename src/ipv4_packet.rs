use crate::{ETHERNET_MTU, checksum, protocol::Protocol, try_ops::TryAdd};
use std::{fmt, net::Ipv4Addr};

/// The minimum number of bytes for an IPv4 header (no options) as a `u8`.
const IPV4_HDR_MIN_LEN_U8: u8 = 20;

/// The minimum number of bytes for an IPv4 header (no options) as a `usize`.
const IPV4_HDR_MIN_LEN_USIZE: usize = IPV4_HDR_MIN_LEN_U8 as usize;

/// Struct for managing IPv4 packet header fields and replies.
pub struct Ipv4Packet {
    total_len: u16,
    pub protocol: Protocol,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}

impl Ipv4Packet {
    /// The length in bytes of an IPv4 header for a reply packet (no options).
    pub const REPLY_HEADER_LEN: usize = IPV4_HDR_MIN_LEN_USIZE;

    /// Parses `data` as an IPv4 packet, returning the header fields and a slice starting at the
    /// beginning of the payload.
    pub fn parse(data: &[u8]) -> Result<(Self, &[u8]), String> {
        let Some(ip_header) = data.first_chunk::<IPV4_HDR_MIN_LEN_USIZE>() else {
            return Err(format!("Too short for IPv4 header ({} bytes)", data.len()));
        };

        let version = ip_header[0] >> 4;
        if version != 4 {
            return Err(format!("Non-IPv4 packet (version {version})"));
        }

        let ihl_bytes = usize::from(ip_header[0] & 0xF) * 4; // Convert 32-bit words to bytes

        Ok((
            Self {
                total_len: u16::from_be_bytes([ip_header[2], ip_header[3]]),
                protocol: Protocol::from(ip_header[9]),
                src_ip: Ipv4Addr::new(ip_header[12], ip_header[13], ip_header[14], ip_header[15]),
                dst_ip: Ipv4Addr::new(ip_header[16], ip_header[17], ip_header[18], ip_header[19]),
            },
            data.get(ihl_bytes..).ok_or("No data after IPv4 header")?,
        ))
    }

    /// Writes the IPv4 reply header into `reply`, using and returning the IPv4 header length +
    /// `proto_len` as the total length. Source and destination addresses are swapped from the
    /// original packet.
    pub fn write_reply(
        &self,
        reply: &mut [u8; ETHERNET_MTU],
        proto_len: u16,
    ) -> Result<usize, String> {
        let total_len = u16::from(IPV4_HDR_MIN_LEN_U8).try_add(proto_len)?;

        // IP header (no options, 20 bytes)
        reply[0] = 0x40 | (IPV4_HDR_MIN_LEN_U8 / 4); // Version 4, IHL 5 (20 bytes)
        reply[1] = 0x00; // DSCP/ECN
        reply[2..4].copy_from_slice(&total_len.to_be_bytes()); // Total length
        reply[4..6].copy_from_slice(&[0x00, 0x00]); // Identification
        reply[6..8].copy_from_slice(&[0x40, 0x00]); // Flags + Fragment offset (Don't Fragment)
        reply[8] = 64; // TTL
        reply[9] = self.protocol.into(); // Protocol

        // Swap src and dst IP addresses
        reply[12..16].copy_from_slice(&self.dst_ip.octets());
        reply[16..20].copy_from_slice(&self.src_ip.octets());

        // Clear IP header checksum field before recalculating
        reply[10] = 0;
        reply[11] = 0;

        // Recalculate IP header checksum (covers only the IP header, always 20 bytes for replies)
        let ip_checksum = checksum::calculate(&reply[..IPV4_HDR_MIN_LEN_USIZE]);
        reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        Ok(total_len.into())
    }
}

impl fmt::Display for Ipv4Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IPv4 | {} bytes | {} | {} -> {}",
            self.total_len, self.protocol, self.src_ip, self.dst_ip,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correctly_parses_valid_packet() -> Result<(), String> {
        #[rustfmt::skip]
        let data = [
            0x45, 0x00, 0x00, 0x3c,  // Version 4, IHL 5, TOS 0, Total Length 60
            0x1c, 0x46, 0x40, 0x00,  // ID, Flags, Fragment Offset
            0x40, 0x06, 0xb1, 0xe6,  // TTL 64, Protocol 6 (TCP), Checksum
            192, 168, 1, 100,        // Source IP: 192.168.1.100
            172, 16, 10, 12,         // Dest IP: 172.16.10.12
        ];

        let (packet, payload) = Ipv4Packet::parse(&data)?;

        assert_eq!(packet.total_len, 60);
        assert_eq!(packet.protocol, Protocol::Tcp);
        assert_eq!(packet.src_ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(packet.dst_ip, Ipv4Addr::new(172, 16, 10, 12));
        assert_eq!(payload, &data[20..]);

        Ok(())
    }

    #[test]
    fn parsing_fails_if_too_short() {
        let data = [0x45, 0x00, 0x00]; // Only 3 bytes
        assert!(Ipv4Packet::parse(&data).is_err_and(|e| e.contains("Too short")));
    }

    #[test]
    fn parsing_fails_if_not_ipv4() {
        #[rustfmt::skip]
        let data = [
            0x60, 0x00, 0x00, 0x00,  // Version 6 (IPv6), not 4
            0x00, 0x14, 0x06, 0x40,
            0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ];

        assert!(Ipv4Packet::parse(&data).is_err_and(|e| e.contains("Non-IPv4")));
    }

    #[test]
    fn creates_valid_ipv4_header_for_reply() -> Result<(), String> {
        #[rustfmt::skip]
        let request = [
            0x45, 0x00, 0x00, 0x3c,  // Version 4, IHL 5, TOS 0, Total Length 60
            0x1c, 0x46, 0x40, 0x00,  // ID, Flags, Fragment Offset
            0x40, 0x11, 0xb1, 0xe6,  // TTL 64, Protocol 17 (UDP), Checksum
            192, 168, 1, 100,        // Source IP: 192.168.1.100
            172, 16, 10, 12,         // Dest IP: 172.16.10.12
        ];

        let (packet, _) = Ipv4Packet::parse(&request)?;
        let mut reply = [0u8; ETHERNET_MTU];
        let proto_len = 48 - 20; // Total length - IPv4 reply header length
        let total_len = packet.write_reply(&mut reply, proto_len)?;
        assert_eq!(total_len, 48);

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
