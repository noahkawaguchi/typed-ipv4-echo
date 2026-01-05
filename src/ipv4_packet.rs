use crate::{
    ETHERNET_MTU, checksum,
    protocol::{Protocol, ProtocolHandler},
};
use std::{fmt, net::Ipv4Addr};

pub const IPV4_HEADER_MIN_LEN: u8 = 20;

pub struct Ipv4Packet<'a> {
    total_len: u16,
    protocol: Protocol,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol_handler: Box<dyn ProtocolHandler + 'a>,
}

impl<'a> Ipv4Packet<'a> {
    pub fn parse<F>(data: &'a [u8], protocol_handler_factory: F) -> Result<Self, String>
    where
        F: FnOnce(Protocol, &'a [u8]) -> Result<Box<dyn ProtocolHandler + 'a>, String>,
    {
        let n = data.len();
        if n < IPV4_HEADER_MIN_LEN.into() {
            return Err(format!("Too short for IPv4 header ({n} bytes)"));
        }

        let version = data[0] >> 4;
        if version != 4 {
            return Err(format!("Non-IPv4 packet (version {version})"));
        }

        let ihl_bytes = usize::from(data[0] & 0xF) * 4; // Convert 32-bit words to bytes
        let protocol = Protocol::from(data[9]);

        Ok(Self {
            total_len: u16::from_be_bytes([data[2], data[3]]),
            protocol,
            src_ip: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
            dst_ip: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
            protocol_handler: protocol_handler_factory(protocol, &data[ihl_bytes..])?,
        })
    }

    pub fn create_reply(&self) -> Option<([u8; ETHERNET_MTU], usize)> {
        let mut reply = [0u8; ETHERNET_MTU];

        // IP header (no options, 20 bytes)
        reply[0] = 0x40 | (IPV4_HEADER_MIN_LEN / 4); // Version 4, IHL 5 (20 bytes)
        reply[1] = 0x00; // DSCP/ECN
        // Total length at [2..4] set later depending on protocol
        reply[4..6].copy_from_slice(&[0x00, 0x00]); // Identification
        reply[6..8].copy_from_slice(&[0x40, 0x00]); // Flags + Fragment offset (Don't Fragment)
        reply[8] = 64; // TTL
        reply[9] = self.protocol.into(); // Protocol

        // Swap src and dst IP addresses
        reply[12..16].copy_from_slice(&self.dst_ip.octets());
        reply[16..20].copy_from_slice(&self.src_ip.octets());

        // Let protocol handler fill in protocol-specific data and calculate total length
        let total_len = self.protocol_handler.write_reply(&mut reply)?;

        // Fill in total length before calculating checksum
        reply[2..4].copy_from_slice(&total_len.to_be_bytes());

        // Clear IP header checksum field before recalculating
        reply[10] = 0;
        reply[11] = 0;

        // Recalculate IP header checksum (covers only the IP header, always 20 bytes for replies)
        let ip_checksum = checksum::calculate(&reply[..usize::from(IPV4_HEADER_MIN_LEN)]);
        reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        Some((reply, total_len.into()))
    }
}

impl fmt::Display for Ipv4Packet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IPv4 | {} bytes | {} | {} -> {}\n{}",
            self.total_len, self.protocol, self.src_ip, self.dst_ip, self.protocol_handler,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProtocolHandler {
        return_val: Option<u16>,
    }

    impl ProtocolHandler for MockProtocolHandler {
        fn write_reply(&self, _reply: &mut [u8; ETHERNET_MTU]) -> Option<u16> { self.return_val }
    }

    impl fmt::Display for MockProtocolHandler {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "mock protocol handler with return value {:#?}",
                self.return_val
            )
        }
    }

    /// Creates a factory function that returns a `ProtocolHandler` whose `write_reply` method
    /// returns `return_val`.
    fn make_factory_returning_mock_handler_returning<'a>(
        return_val: Option<u16>,
    ) -> impl Fn(Protocol, &'a [u8]) -> Result<Box<dyn ProtocolHandler + 'a>, String> {
        move |_protocol, _data| Ok(Box::new(MockProtocolHandler { return_val }))
    }

    #[test]
    fn correctly_parses_valid_packet() {
        #[rustfmt::skip]
        let data = [
            0x45, 0x00, 0x00, 0x3c,  // Version 4, IHL 5, TOS 0, Total Length 60
            0x1c, 0x46, 0x40, 0x00,  // ID, Flags, Fragment Offset
            0x40, 0x06, 0xb1, 0xe6,  // TTL 64, Protocol 6 (TCP), Checksum
            192, 168, 1, 100,        // Source IP: 192.168.1.100
            172, 16, 10, 12,         // Dest IP: 172.16.10.12
        ];

        let mock = make_factory_returning_mock_handler_returning(None);

        assert!(Ipv4Packet::parse(&data, mock).is_ok_and(|packet| {
            assert_eq!(packet.total_len, 60);
            assert_eq!(packet.protocol, Protocol::Tcp);
            assert_eq!(packet.src_ip, Ipv4Addr::new(192, 168, 1, 100));
            assert_eq!(packet.dst_ip, Ipv4Addr::new(172, 16, 10, 12));
            true
        }));
    }

    #[test]
    fn parsing_fails_if_too_short() {
        let data = [0x45, 0x00, 0x00]; // Only 3 bytes
        let mock = make_factory_returning_mock_handler_returning(None);
        assert!(Ipv4Packet::parse(&data, mock).is_err_and(|e| e.contains("Too short")));
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

        let mock = make_factory_returning_mock_handler_returning(None);

        assert!(Ipv4Packet::parse(&data, mock).is_err_and(|e| e.contains("Non-IPv4")));
    }
}
