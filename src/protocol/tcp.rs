use crate::{
    ETHERNET_MTU, checksum,
    protocol::Protocol,
    try_ops::{TryAdd, TryGet, TryGetMut},
};
use std::{fmt, net::Ipv4Addr};

const TCP_HEADER_MIN_LEN: u8 = 20;

/// Struct for managing and replying to TCP packets. Includes the TCP header and the payload.
pub struct TcpHandler<'a> {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    offset_bytes: usize,
    syn_flag: bool,
    ack_flag: bool,
    payload: &'a [u8],
}

/// Struct for managing the TCP reply data that varies depending on the received packet.
struct TcpReplyInfo {
    flags: u8,
    seq_num: u32,
    ack_num: u32,
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

        let offset_bytes = usize::from(tcp_header[12] >> 4) * 4; // Convert 32-bit words to bytes
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
            payload: data.get(offset_bytes..).ok_or("No data after TCP header")?,
        })
    }

    pub fn write_reply(
        &self,
        reply: &mut [u8],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
    ) -> Result<Option<u16>, String> {
        let Some(reply_info) = self.determine_reply() else { return Ok(None) };

        // Swap ports
        reply
            .try_get_mut(..2)?
            .copy_from_slice(&self.dst_port.to_be_bytes());
        reply
            .try_get_mut(2..4)?
            .copy_from_slice(&self.src_port.to_be_bytes());

        // Sequence number
        reply
            .try_get_mut(4..8)?
            .copy_from_slice(&reply_info.seq_num.to_be_bytes());

        // Acknowledgment number
        reply
            .try_get_mut(8..12)?
            .copy_from_slice(&reply_info.ack_num.to_be_bytes());

        // Data offset (5 * 4 = 20 bytes) in upper 4 bits
        *reply.try_get_mut(12)? = (TCP_HEADER_MIN_LEN / 4) << 4;

        // Flags (SYN | ACK for handshake, ACK for data)
        *reply.try_get_mut(13)? = reply_info.flags;

        // Window size for flow control, left at max for simplicity
        reply
            .try_get_mut(14..16)?
            .copy_from_slice(&u16::MAX.to_be_bytes());

        // Checksum at bytes 16-17 calculated later with pseudo-header

        // Urgent pointer
        reply.try_get_mut(18..20)?.copy_from_slice(&[0x00, 0x00]);

        // Copy payload into reply if echoing
        let payload_len = if reply_info.echo {
            reply
                .try_get_mut(
                    usize::from(TCP_HEADER_MIN_LEN)
                        ..usize::from(TCP_HEADER_MIN_LEN).try_add(self.payload.len())?,
                )?
                .copy_from_slice(self.payload);

            self.payload.len()
        } else {
            0
        };

        // TCP segment length: minimum TCP header length (20 bytes) + payload length (0+ bytes)
        #[expect(
            clippy::cast_possible_truncation,
            reason = "u16::MAX (65_535) > ETHERNET_MTU (1500)"
        )]
        let tcp_segment_len = u16::from(TCP_HEADER_MIN_LEN).try_add(payload_len as u16)?;

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
            .copy_from_slice(reply.try_get(..usize::from(tcp_segment_len))?);

        // Zero out checksum field before calculating
        checksum_data[Self::PSEUDO_HEADER_LEN + 16] = 0;
        checksum_data[Self::PSEUDO_HEADER_LEN + 17] = 0;

        let tcp_checksum = checksum::calculate(checksum_data.try_get(..checksum_len)?);
        reply
            .try_get_mut(16..18)?
            .copy_from_slice(&tcp_checksum.to_be_bytes());

        Ok(Some(tcp_segment_len))
    }

    /// Determines the nature of the reply to send based on the received packet type or returns
    /// `None` for no reply.
    fn determine_reply(&self) -> Option<TcpReplyInfo> {
        /// Local sequence number for SYN-ACK (can be random, using 0 for simplicity).
        const LOCAL_SEQ_SYN: u32 = 0;

        match (self.syn_flag, self.ack_flag, self.payload.len()) {
            // SYN packet (step 2 of handshake) -> send SYN-ACK, no payload echo
            (true, false, _) => {
                println!("Received SYN, building SYN-ACK response...");

                // SYN | ACK flags, seq = LOCAL_SEQ_SYN, local ack num = remote seq num + 1
                Some(TcpReplyInfo {
                    flags: Self::SYN_FLAG | Self::ACK_FLAG,
                    seq_num: LOCAL_SEQ_SYN,
                    ack_num: self.seq_num.wrapping_add(1),
                    echo: false,
                })
            }

            // Data packet (ACK with payload) -> send ACK, echo payload
            (false, true, payload_len) if payload_len > 0 => {
                println!(
                    "Received {payload_len} bytes of data: {}\nEchoing data back...",
                    str::from_utf8(self.payload).unwrap_or("<non-UTF-8>")
                );

                // ACK flag only
                // Local seq num = what the client expects next (remote ack num)
                // Local ack num = remote seq num + payload length (intentionally wrapping)
                Some(TcpReplyInfo {
                    flags: Self::ACK_FLAG,
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
            (false, true, 0) if self.ack_num == LOCAL_SEQ_SYN.wrapping_add(1) => {
                println!("Received ACK, connection established!");
                None
            }

            _ => None, // No reply implemented
        }
    }
}

impl fmt::Display for TcpHandler<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP {} -> {} | {} bytes | seq={} ack={} | SYN={} ACK={}",
            self.src_port,
            self.dst_port,
            self.offset_bytes,
            self.seq_num,
            self.ack_num,
            self.syn_flag,
            self.ack_flag,
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

        let handler = TcpHandler::parse(&data)?;

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
        let data = [0x04, 0xd2, 0x00, 0x50]; // Only 4 bytes
        assert!(TcpHandler::parse(&data).is_err_and(|e| e.contains("Too short")));
    }

    #[test]
    fn extracts_syn_flag_correctly() -> Result<(), String> {
        #[rustfmt::skip]
        let data = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x00, 0x00,              // Sequence number: 0
            0x00, 0x00, 0x00, 0x00,              // Ack number: 0
            0x50, 0x02,                          // Data offset: 5, Flags: SYN only
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

        let handler = TcpHandler::parse(&data)?;

        assert!(handler.syn_flag);
        assert!(!handler.ack_flag);

        Ok(())
    }

    #[test]
    fn extracts_ack_flag_correctly() -> Result<(), String> {
        #[rustfmt::skip]
        let data = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x00, 0x01,              // Sequence number: 1
            0x00, 0x00, 0x00, 0x01,              // Ack number: 1
            0x50, 0x10,                          // Data offset: 5, Flags: ACK only
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

        let handler = TcpHandler::parse(&data)?;

        assert!(!handler.syn_flag);
        assert!(handler.ack_flag);

        Ok(())
    }

    #[test]
    fn parsing_handles_no_flags_set() -> Result<(), String> {
        #[rustfmt::skip]
        let data = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x00, 0x00,              // Sequence number: 0
            0x00, 0x00, 0x00, 0x00,              // Ack number: 0
            0x50, 0x00,                          // Data offset: 5, Flags: none
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

        let handler = TcpHandler::parse(&data)?;

        assert!(!handler.syn_flag);
        assert!(!handler.ack_flag);

        Ok(())
    }

    #[test]
    fn parsing_handles_large_sequence_numbers() -> Result<(), String> {
        #[rustfmt::skip]
        let data = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0xff, 0xff, 0xff, 0xff,              // Sequence number: u32::MAX
            0xfe, 0xdc, 0xba, 0x98,              // Ack number: 4275878552
            0x50, 0x10,                          // Data offset: 5, Flags: ACK
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

        let handler = TcpHandler::parse(&data)?;

        assert_eq!(handler.seq_num, u32::MAX);
        assert_eq!(handler.ack_num, 0xfedc_ba98);

        Ok(())
    }

    #[test]
    fn reply_creates_valid_syn_ack() -> Result<(), String> {
        #[rustfmt::skip]
        let syn_packet = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x10, 0x00,              // Sequence number: 4096
            0x00, 0x00, 0x00, 0x00,              // Ack number: 0
            0x50, 0x02,                          // Data offset: 5, Flags: SYN
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

        let handler = TcpHandler::parse(&syn_packet)?;
        let mut reply = [0u8; ETHERNET_MTU];

        // Set up addresses from IP header
        let src_ip = Ipv4Addr::new(10, 0, 0, 2); // Source: 10.0.0.2
        let dst_ip = Ipv4Addr::new(10, 0, 0, 1); // Dest: 10.0.0.1

        let tcp_len = handler
            .write_reply(&mut reply[20..], src_ip, dst_ip)?
            .ok_or("failed to write reply")?;

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
        pseudo_header[0..4].copy_from_slice(&src_ip.octets());
        pseudo_header[4..8].copy_from_slice(&dst_ip.octets());
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
        let data_packet = [
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

        let handler = TcpHandler::parse(&data_packet)?;
        let mut reply = [0u8; ETHERNET_MTU];

        // Set up addresses from IP header
        let src_ip = Ipv4Addr::new(10, 0, 0, 2); // Source: 10.0.0.2
        let dst_ip = Ipv4Addr::new(10, 0, 0, 1); // Dest: 10.0.0.1

        let tcp_len = handler
            .write_reply(&mut reply[20..], src_ip, dst_ip)?
            .ok_or("failed to write reply")?;

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
        pseudo_header[0..4].copy_from_slice(&src_ip.octets());
        pseudo_header[4..8].copy_from_slice(&dst_ip.octets());
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
        let ack_packet = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x10, 0x01,              // Sequence number: 4097
            0x00, 0x00, 0x00, 0x01,              // Ack number: 1 (LOCAL_SEQ_SYN + 1)
            0x50, 0x10,                          // Data offset: 5, Flags: ACK
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

        let handler = TcpHandler::parse(&ack_packet)?;
        let mut reply = [0u8; ETHERNET_MTU];

        // Set up addresses from IP header
        let src_ip = Ipv4Addr::new(10, 0, 0, 2); // Source: 10.0.0.2
        let dst_ip = Ipv4Addr::new(10, 0, 0, 1); // Dest: 10.0.0.1

        // Handshake ACK should not generate a reply
        assert!(
            handler
                .write_reply(&mut reply[20..], src_ip, dst_ip)?
                .is_none()
        );

        Ok(())
    }
}
