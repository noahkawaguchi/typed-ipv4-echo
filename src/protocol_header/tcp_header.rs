use crate::{
    ETHERNET_MTU, checksum, ipv4_packet::IPV4_HEADER_MIN_LEN, protocol::Protocol,
    protocol_header::ProtocolHeader,
};
use std::fmt;

pub(super) struct TcpHeader<'a> {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    offset_bytes: usize,
    syn_flag: bool,
    ack_flag: bool,
    payload: &'a [u8],
}

impl<'a> TcpHeader<'a> {
    const TCP_HEADER_MIN_LEN: u8 = 20;
    const PSEUDO_HEADER_LEN: usize = 12;

    const SYN_FLAG: u8 = 0x02;
    const ACK_FLAG: u8 = 0x10;

    pub(super) fn parse(data: &'a [u8]) -> Result<Self, String> {
        let n = data.len();

        if n < Self::TCP_HEADER_MIN_LEN.into() {
            return Err(format!("Too short for TCP header ({n} bytes)"));
        }

        let offset_bytes = usize::from(data[12] >> 4) * 4; // Convert 32-bit words to bytes
        let flags = data[13];

        Ok(Self {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            seq_num: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ack_num: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            offset_bytes,
            syn_flag: flags & Self::SYN_FLAG != 0,
            ack_flag: flags & Self::ACK_FLAG != 0,
            payload: &data[offset_bytes..],
        })
    }
}

impl ProtocolHeader for TcpHeader<'_> {
    fn write_reply(&self, reply: &mut [u8; ETHERNET_MTU]) -> Option<u16> {
        /// Local sequence number for SYN-ACK (can be random, using 0 for simplicity).
        const LOCAL_SEQ_SYN: u32 = 0;

        // Determine the nature of the reply to send, if any, based on the packet type
        let (reply_flags, local_seq, local_ack, echo_payload): (u8, u32, u32, bool) =
            match (self.syn_flag, self.ack_flag, self.payload.len()) {
                // SYN packet (step 2 of handshake) -> send SYN-ACK, no payload echo
                (true, false, _) => {
                    println!("Received SYN, building SYN-ACK response...");

                    // SYN | ACK flags, seq = LOCAL_SEQ_SYN, local ack num = remote seq num + 1
                    (
                        Self::SYN_FLAG | Self::ACK_FLAG,
                        LOCAL_SEQ_SYN,
                        self.seq_num.wrapping_add(1),
                        false,
                    )
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
                    (
                        Self::ACK_FLAG,
                        self.ack_num,
                        // `u32::MAX` (4_294_967_295) > `ETHERNET_MTU` (1500)
                        #[allow(clippy::cast_possible_truncation)]
                        self.seq_num.wrapping_add(payload_len as u32),
                        true,
                    )
                }

                // Handshake ACK (step 3) -> no reply needed
                // Remote ack num should be the previous local seq num + 1
                (false, true, 0) if self.ack_num == LOCAL_SEQ_SYN.wrapping_add(1) => {
                    println!("Received ACK, connection established!");
                    return None;
                }

                _ => return None, // No reply implemented
            };

        let tcp_start = IPV4_HEADER_MIN_LEN.into();

        // Swap ports
        reply[tcp_start..tcp_start + 2].copy_from_slice(&self.dst_port.to_be_bytes());
        reply[tcp_start + 2..tcp_start + 4].copy_from_slice(&self.src_port.to_be_bytes());

        // Sequence number
        reply[tcp_start + 4..tcp_start + 8].copy_from_slice(&local_seq.to_be_bytes());

        // Acknowledgment number
        reply[tcp_start + 8..tcp_start + 12].copy_from_slice(&local_ack.to_be_bytes());

        // Data offset (5 * 4 = 20 bytes) in upper 4 bits
        reply[tcp_start + 12] = (Self::TCP_HEADER_MIN_LEN / 4) << 4;

        // Flags (SYN | ACK for handshake, ACK for data)
        reply[tcp_start + 13] = reply_flags;

        // Window size for flow control, left at max for simplicity
        reply[tcp_start + 14..tcp_start + 16].copy_from_slice(&u16::MAX.to_be_bytes());

        // Checksum at bytes 16-17 calculated later with pseudo-header

        // Urgent pointer
        reply[tcp_start + 18..tcp_start + 20].copy_from_slice(&[0x00, 0x00]);

        // Copy payload into reply if echoing
        let payload_len = if echo_payload {
            let payload_start = tcp_start + usize::from(Self::TCP_HEADER_MIN_LEN);
            reply[payload_start..payload_start + self.payload.len()].copy_from_slice(self.payload);
            self.payload.len()
        } else {
            0
        };

        // TCP segment length (header + payload if any)
        #[allow(clippy::cast_possible_truncation)] // `u16::MAX` (65_535) > `ETHERNET_MTU` (1500)
        let tcp_segment_len = u16::from(Self::TCP_HEADER_MIN_LEN) + payload_len as u16;

        // Calculate TCP checksum with pseudo-header
        let mut pseudo_header = [0u8; Self::PSEUDO_HEADER_LEN];
        pseudo_header[0..4].copy_from_slice(&reply[12..16]); // Source IP
        pseudo_header[4..8].copy_from_slice(&reply[16..20]); // Dest IP
        pseudo_header[8] = 0; // Reserved padding for alignment
        pseudo_header[9] = Protocol::Tcp.as_u8();
        pseudo_header[10..12].copy_from_slice(&tcp_segment_len.to_be_bytes());

        // Build checksum data: pseudo-header + TCP header + payload if any
        let checksum_len = Self::PSEUDO_HEADER_LEN + usize::from(tcp_segment_len);
        let mut checksum_data = [0u8; ETHERNET_MTU + Self::PSEUDO_HEADER_LEN];
        checksum_data[0..Self::PSEUDO_HEADER_LEN].copy_from_slice(&pseudo_header);
        checksum_data[Self::PSEUDO_HEADER_LEN..checksum_len]
            .copy_from_slice(&reply[tcp_start..tcp_start + usize::from(tcp_segment_len)]);

        // Zero out checksum field before calculating
        checksum_data[Self::PSEUDO_HEADER_LEN + 16] = 0;
        checksum_data[Self::PSEUDO_HEADER_LEN + 17] = 0;

        let tcp_checksum = checksum::calculate(&checksum_data[..checksum_len]);
        reply[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

        // Total length: IPv4 header without options (20 bytes)
        //               + minimum TCP header length (20 bytes)
        //               + payload length (0+ bytes)
        Some(u16::from(IPV4_HEADER_MIN_LEN) + tcp_segment_len)
    }
}

impl fmt::Display for TcpHeader<'_> {
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
