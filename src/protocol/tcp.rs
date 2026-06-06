use crate::{
    ETHERNET_MTU, checksum,
    protocol::{Protocol, payload_to_string},
    try_ops::{TryAdd, TryGet, TryGetMut},
};
use std::{fmt, net::Ipv4Addr};

const TCP_HEADER_MIN_LEN: u8 = 20;

/// Struct for managing and replying to TCP packets. Includes the TCP header and the payload.
#[cfg_attr(test, derive(Debug))]
pub struct TcpHandler<'a> {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    offset_bytes: u8,
    syn_flag: bool,
    ack_flag: bool,
    payload: &'a [u8],
}

/// Struct for managing the TCP reply data that varies depending on the received packet.
struct TcpReplyInfo {
    seq_num: u32,
    ack_num: u32,
    syn_flag: bool,
    ack_flag: bool,
    /// Whether to echo the payload.
    echo: bool,
}

impl<'a> TcpHandler<'a> {
    const PSEUDO_HEADER_LEN: usize = 12;
    const SYN_FLAG: u8 = 0x02;
    const ACK_FLAG: u8 = 0x10;

    /// Parses `data` as a TCP header and payload.
    pub fn parse(data: &'a [u8]) -> Result<Self, String> {
        let Some(tcp_header) = data.first_chunk::<{ TCP_HEADER_MIN_LEN as usize }>() else {
            return Err(format!("Too short for TCP header ({} bytes)", data.len()));
        };

        // Convert length in 32-bit words in the upper 4 bits to length in bytes in the full 8 bits
        let offset_bytes = tcp_header[12] >> 4 << 2;

        let flags = tcp_header[13];

        Ok(Self {
            src_port: u16::from_be_bytes([tcp_header[0], tcp_header[1]]),
            dst_port: u16::from_be_bytes([tcp_header[2], tcp_header[3]]),
            seq_num: u32::from_be_bytes([
                tcp_header[4],
                tcp_header[5],
                tcp_header[6],
                tcp_header[7],
            ]),
            ack_num: u32::from_be_bytes([
                tcp_header[8],
                tcp_header[9],
                tcp_header[10],
                tcp_header[11],
            ]),
            offset_bytes,
            syn_flag: flags & Self::SYN_FLAG != 0,
            ack_flag: flags & Self::ACK_FLAG != 0,
            payload: data
                .get(offset_bytes.into()..)
                .ok_or("No data after TCP header")?,
        })
    }

    /// Creates a TCP header and payload for replying to `self`, or returns `None` for no reply.
    pub fn create_reply(&self) -> Option<Self> {
        let reply_info = self.determine_reply()?;

        Some(Self {
            // Swap source and destination ports
            src_port: self.dst_port,
            dst_port: self.src_port,
            seq_num: reply_info.seq_num,
            ack_num: reply_info.ack_num,
            offset_bytes: TCP_HEADER_MIN_LEN,
            syn_flag: reply_info.syn_flag,
            ack_flag: reply_info.ack_flag,
            payload: if reply_info.echo { self.payload } else { &[] },
        })
    }

    /// Copies data from `self` to write a TCP header and payload into `buf`, returning the number
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

        // Sequence number
        buf.try_get_mut(4..8)?
            .copy_from_slice(&self.seq_num.to_be_bytes());

        // Acknowledgment number
        buf.try_get_mut(8..12)?
            .copy_from_slice(&self.ack_num.to_be_bytes());

        // Data offset in upper 4 bits (bytes / 4 = 32-bit words), reserved zeros in lower 4 bits
        *buf.try_get_mut(12)? = (self.offset_bytes / 4) << 4;

        // Flags (SYN | ACK for handshake, ACK for data)
        *buf.try_get_mut(13)? = if self.syn_flag { Self::SYN_FLAG } else { 0 }
            | if self.ack_flag { Self::ACK_FLAG } else { 0 };

        // Window size for flow control, left at max for simplicity
        buf.try_get_mut(14..16)?
            .copy_from_slice(&u16::MAX.to_be_bytes());

        // Checksum at bytes 16-17 calculated later with pseudo-header

        // Urgent pointer
        buf.try_get_mut(18..20)?.copy_from_slice(&[0x00, 0x00]);

        // Copy payload into reply (may be empty if not echoing)
        buf.try_get_mut(
            usize::from(TCP_HEADER_MIN_LEN)
                ..usize::from(TCP_HEADER_MIN_LEN).try_add(self.payload.len())?,
        )?
        .copy_from_slice(self.payload);

        // TCP segment length: minimum TCP header length (20 bytes) + payload length (0+ bytes)
        #[expect(
            clippy::cast_possible_truncation,
            reason = "u16::MAX (65_535) > ETHERNET_MTU (1500)"
        )]
        let tcp_segment_len = u16::from(TCP_HEADER_MIN_LEN).try_add(self.payload.len() as u16)?;

        // Calculate TCP checksum with pseudo-header
        let mut pseudo_header = [0u8; Self::PSEUDO_HEADER_LEN];
        pseudo_header[0..4].copy_from_slice(&src_ip.octets()); // Source IP
        pseudo_header[4..8].copy_from_slice(&dst_ip.octets()); // Dest IP
        pseudo_header[8] = 0; // Reserved padding for alignment
        pseudo_header[9] = Protocol::Tcp.into();
        pseudo_header[10..12].copy_from_slice(&tcp_segment_len.to_be_bytes());

        // Build checksum data: pseudo-header + TCP header + payload if any
        let checksum_len = Self::PSEUDO_HEADER_LEN + usize::from(tcp_segment_len);
        let mut checksum_data = [0u8; ETHERNET_MTU + Self::PSEUDO_HEADER_LEN];
        checksum_data[..Self::PSEUDO_HEADER_LEN].copy_from_slice(&pseudo_header);
        checksum_data
            .try_get_mut(Self::PSEUDO_HEADER_LEN..checksum_len)?
            .copy_from_slice(buf.try_get(..usize::from(tcp_segment_len))?);

        // Zero out checksum field before calculating
        checksum_data[Self::PSEUDO_HEADER_LEN + 16..Self::PSEUDO_HEADER_LEN + 18]
            .copy_from_slice(&[0x00, 0x00]);

        let tcp_checksum = checksum::calculate(checksum_data.try_get(..checksum_len)?);
        buf.try_get_mut(16..18)?
            .copy_from_slice(&tcp_checksum.to_be_bytes());

        Ok(tcp_segment_len)
    }

    /// Determines the nature of the reply to send based on the received packet type or returns
    /// `None` for no reply.
    const fn determine_reply(&self) -> Option<TcpReplyInfo> {
        /// Local sequence number for SYN-ACK (can be random, using 0 for simplicity).
        const LOCAL_SEQ_SYN: u32 = 0;

        match (self.syn_flag, self.ack_flag, self.payload.len()) {
            // SYN packet (step 2 of handshake) -> send SYN-ACK, no payload echo
            (true, false, _) => {
                // SYN | ACK flags, seq = LOCAL_SEQ_SYN, local ack num = remote seq num + 1
                Some(TcpReplyInfo {
                    syn_flag: true,
                    ack_flag: true,
                    seq_num: LOCAL_SEQ_SYN,
                    ack_num: self.seq_num.wrapping_add(1),
                    echo: false,
                })
            }

            // Data packet (ACK with payload) -> send ACK, echo payload
            (false, true, payload_len) if payload_len > 0 => {
                // ACK flag only
                // Local seq num = what the client expects next (remote ack num)
                // Local ack num = remote seq num + payload length (intentionally wrapping)
                Some(TcpReplyInfo {
                    syn_flag: false,
                    ack_flag: true,
                    seq_num: self.ack_num,
                    #[expect(
                        clippy::cast_possible_truncation,
                        reason = "`u32::MAX` (4_294_967_295) > `ETHERNET_MTU` (1500)"
                    )]
                    ack_num: self.seq_num.wrapping_add(payload_len as u32),
                    echo: true,
                })
            }

            // Handshake ACK (step 3) -> no reply needed
            // Remote ack num should be the previous local seq num + 1
            (false, true, 0) if self.ack_num == LOCAL_SEQ_SYN.wrapping_add(1) => None,

            _ => None, // No reply implemented
        }
    }
}

impl fmt::Display for TcpHandler<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP | {} -> {} | seq={} ack={} | SYN={} ACK={}\n{}",
            self.src_port,
            self.dst_port,
            self.seq_num,
            self.ack_num,
            self.syn_flag,
            self.ack_flag,
            payload_to_string(self.payload),
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
        const DATA: [u8; 25] = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x00, 0x01,              // Sequence number: 1
            0x00, 0x00, 0x00, 0x02,              // Ack number: 2
            0x50, 0x12,                          // Data offset: 5 (20 bytes), Flags: SYN|ACK
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
            0x48, 0x65, 0x6c, 0x6c, 0x6f,        // Payload: "Hello"
        ];

        let handler = TcpHandler::parse(&DATA)?;

        assert_eq!(handler.src_port, 1234);
        assert_eq!(handler.dst_port, 80);
        assert_eq!(handler.seq_num, 1);
        assert_eq!(handler.ack_num, 2);
        assert_eq!(handler.offset_bytes, 20);
        assert!(handler.syn_flag);
        assert!(handler.ack_flag);
        assert_eq!(handler.payload, b"Hello");

        Ok(())
    }

    #[test]
    fn parsing_fails_when_too_short() {
        const DATA: [u8; 4] = [0x04, 0xd2, 0x00, 0x50]; // Only 4 bytes
        assert_matches!(TcpHandler::parse(&DATA), Err(e) if e.contains("Too short"));
    }

    #[test]
    fn extracts_syn_flag_correctly() -> Result<(), String> {
        #[rustfmt::skip]
        const DATA: [u8; 20] = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x00, 0x00,              // Sequence number: 0
            0x00, 0x00, 0x00, 0x00,              // Ack number: 0
            0x50, 0x02,                          // Data offset: 5, Flags: SYN only
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

        let handler = TcpHandler::parse(&DATA)?;

        assert!(handler.syn_flag);
        assert!(!handler.ack_flag);

        Ok(())
    }

    #[test]
    fn extracts_ack_flag_correctly() -> Result<(), String> {
        #[rustfmt::skip]
        const DATA: [u8; 20] = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x00, 0x01,              // Sequence number: 1
            0x00, 0x00, 0x00, 0x01,              // Ack number: 1
            0x50, 0x10,                          // Data offset: 5, Flags: ACK only
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

        let handler = TcpHandler::parse(&DATA)?;

        assert!(!handler.syn_flag);
        assert!(handler.ack_flag);

        Ok(())
    }

    #[test]
    fn parsing_handles_no_flags_set() -> Result<(), String> {
        #[rustfmt::skip]
        const DATA: [u8; 20] = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x00, 0x00,              // Sequence number: 0
            0x00, 0x00, 0x00, 0x00,              // Ack number: 0
            0x50, 0x00,                          // Data offset: 5, Flags: none
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

        let handler = TcpHandler::parse(&DATA)?;

        assert!(!handler.syn_flag);
        assert!(!handler.ack_flag);

        Ok(())
    }

    #[test]
    fn parsing_handles_large_sequence_numbers() -> Result<(), String> {
        #[rustfmt::skip]
        const DATA: [u8; 20] = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0xff, 0xff, 0xff, 0xff,              // Sequence number: u32::MAX
            0xfe, 0xdc, 0xba, 0x98,              // Ack number: 4275878552
            0x50, 0x10,                          // Data offset: 5, Flags: ACK
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

        let handler = TcpHandler::parse(&DATA)?;

        assert_eq!(handler.seq_num, u32::MAX);
        assert_eq!(handler.ack_num, 0xfedc_ba98);

        Ok(())
    }

    #[test]
    fn reply_creates_valid_syn_ack() -> Result<(), String> {
        #[rustfmt::skip]
        const SYN_PACKET: [u8; 20] = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x10, 0x00,              // Sequence number: 4096
            0x00, 0x00, 0x00, 0x00,              // Ack number: 0
            0x50, 0x02,                          // Data offset: 5, Flags: SYN
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

        // Set up addresses from IP header
        const SRC_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2); // Source: 10.0.0.2
        const DST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1); // Dest: 10.0.0.1

        let handler = TcpHandler::parse(&SYN_PACKET)?;
        let mut reply = [0u8; ETHERNET_MTU];

        let tcp_len = handler
            .create_reply()
            .ok_or("Unexpected None reply")?
            .write_into(&mut reply[20..], SRC_IP, DST_IP)?;

        // Verify TCP header at offset 20
        assert_eq!(&reply[20..22], &[0x00, 0x50]); // Source port: 80 (swapped)
        assert_eq!(&reply[22..24], &[0x04, 0xd2]); // Dest port: 1234 (swapped)
        assert_eq!(&reply[24..28], &[0x00, 0x00, 0x00, 0x00]); // Seq: 0 (LOCAL_SEQ_SYN)
        assert_eq!(&reply[28..32], &[0x00, 0x00, 0x10, 0x01]); // Ack: 4097 (client seq + 1)
        assert_eq!(reply[33], 0x12); // Flags: SYN|ACK

        // Verify TCP length (no payload for SYN-ACK)
        assert_eq!(tcp_len, 20);

        // Verify checksum is valid using pseudo-header
        let mut pseudo_header = [0u8; 12];
        pseudo_header[0..4].copy_from_slice(&SRC_IP.octets());
        pseudo_header[4..8].copy_from_slice(&DST_IP.octets());
        pseudo_header[8] = 0;
        pseudo_header[9] = Protocol::Tcp.into();
        pseudo_header[10..12].copy_from_slice(&tcp_len.to_be_bytes());

        let mut checksum_data = [0u8; 12 + 20];
        checksum_data[0..12].copy_from_slice(&pseudo_header);
        checksum_data[12..32].copy_from_slice(&reply[20..40]);

        let checksum = checksum::calculate(&checksum_data);
        assert_eq!(checksum, 0x0000);

        Ok(())
    }

    #[test]
    fn reply_creates_valid_data_echo() -> Result<(), String> {
        #[rustfmt::skip]
        const DATA_PACKET: [u8; 25] = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x10, 0x01,              // Sequence number: 4097
            0x00, 0x00, 0x00, 0x01,              // Ack number: 1
            0x50, 0x10,                          // Data offset: 5, Flags: ACK
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
            0x48, 0x65, 0x6c, 0x6c, 0x6f,        // Payload: "Hello"
        ];

        // Set up addresses from IP header
        const SRC_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2); // Source: 10.0.0.2
        const DST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1); // Dest: 10.0.0.1

        let handler = TcpHandler::parse(&DATA_PACKET)?;
        let mut reply = [0u8; ETHERNET_MTU];

        let tcp_len = handler
            .create_reply()
            .ok_or("Unexpected None reply")?
            .write_into(&mut reply[20..], SRC_IP, DST_IP)?;

        // Verify TCP header
        assert_eq!(&reply[20..22], &[0x00, 0x50]); // Source port: 80
        assert_eq!(&reply[22..24], &[0x04, 0xd2]); // Dest port: 1234
        assert_eq!(&reply[24..28], &[0x00, 0x00, 0x00, 0x01]); // Seq: 1 (client's ack_num)
        assert_eq!(&reply[28..32], &[0x00, 0x00, 0x10, 0x06]); // Ack: 4102 (seq + 5)
        assert_eq!(reply[33], 0x10); // Flags: ACK only

        // Verify payload echoed
        assert_eq!(&reply[40..45], b"Hello");

        // Verify TCP length
        assert_eq!(tcp_len, 20 + 5);

        // Verify checksum
        let mut pseudo_header = [0u8; 12];
        pseudo_header[0..4].copy_from_slice(&SRC_IP.octets());
        pseudo_header[4..8].copy_from_slice(&DST_IP.octets());
        pseudo_header[8] = 0;
        pseudo_header[9] = Protocol::Tcp.into();
        pseudo_header[10..12].copy_from_slice(&tcp_len.to_be_bytes());

        let mut checksum_data = [0u8; 12 + 25];
        checksum_data[0..12].copy_from_slice(&pseudo_header);
        checksum_data[12..37].copy_from_slice(&reply[20..45]);

        let checksum = checksum::calculate(&checksum_data);
        assert_eq!(checksum, 0x0000);

        Ok(())
    }

    #[test]
    fn reply_returns_none_for_handshake_ack() -> Result<(), String> {
        #[rustfmt::skip]
        const ACK_PACKET: [u8; 20] = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x10, 0x01,              // Sequence number: 4097
            0x00, 0x00, 0x00, 0x01,              // Ack number: 1 (LOCAL_SEQ_SYN + 1)
            0x50, 0x10,                          // Data offset: 5, Flags: ACK
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

        // Handshake ACK should not generate a reply
        assert_matches!(TcpHandler::parse(&ACK_PACKET)?.create_reply(), None);
        Ok(())
    }
}
