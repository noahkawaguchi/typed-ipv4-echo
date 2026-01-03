use crate::{ETHERNET_MTU, checksum, ipv4_packet::IPV4_HEADER_MIN_LEN, protocol::Protocol};
use std::fmt;

const ICMP_HEADER_LEN: u8 = 8;
const TCP_HEADER_MIN_LEN: u8 = 20;
const UDP_HEADER_LEN: u8 = 8;

pub enum ProtocolHeader {
    Icmp(IcmpHeader),
    Tcp(TcpHeader),
    Udp,
    Other,
}

impl ProtocolHeader {
    pub fn parse(data: &[u8], protocol: &Protocol) -> Result<Self, String> {
        Ok(match protocol {
            Protocol::Icmp => Self::Icmp(IcmpHeader::parse(data)?),
            Protocol::Tcp => Self::Tcp(TcpHeader::parse(data)?),
            Protocol::Udp => Self::Udp,
            Protocol::Other(_) => Self::Other,
        })
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Icmp(_) => ICMP_HEADER_LEN.into(),
            Self::Tcp(tcp) => tcp.offset_bytes,
            Self::Udp => UDP_HEADER_LEN.into(),
            Self::Other => todo!(),
        }
    }

    pub fn write_reply_header(
        &self,
        reply: &mut [u8; ETHERNET_MTU],
        payload: &[u8],
    ) -> Option<usize> {
        match self {
            Self::Icmp(icmp) => icmp.write_reply_header(reply, payload),
            Self::Tcp(tcp) => tcp.write_reply_header(reply),
            _ => None,
        }
    }
}

impl fmt::Display for ProtocolHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Icmp(icmp) => write!(f, "{icmp}"),
            Self::Tcp(tcp) => write!(f, "{tcp}"),
            Self::Udp => write!(f, "UDP"),
            Self::Other => write!(f, "Other"),
        }
    }
}

struct IcmpHeader {
    icmp_type: u8,
    icmp_code: u8,
}

impl IcmpHeader {
    fn parse(data: &[u8]) -> Result<Self, String> {
        let n = data.len();

        if n < ICMP_HEADER_LEN.into() {
            return Err(format!("Too short for ICMP header ({n} bytes)"));
        }

        Ok(Self { icmp_type: data[0], icmp_code: data[1] })
    }

    fn write_reply_header(&self, reply: &mut [u8; ETHERNET_MTU], payload: &[u8]) -> Option<usize> {
        // ICMP Echo Request (ping): type=8, code=0
        if self.icmp_type != 8 || self.icmp_code != 0 {
            return None;
        }

        println!("Building ICMP echo reply...");

        // Total length: IPv4 header without options (20 bytes)
        //               + fixed ICMP header length (8 bytes)
        //               + length of echo payload
        let total_len =
            u16::from(IPV4_HEADER_MIN_LEN) + u16::from(ICMP_HEADER_LEN) + payload.len() as u16;
        reply[2..4].copy_from_slice(&total_len.to_be_bytes());

        let icmp_start = IPV4_HEADER_MIN_LEN.into();
        let payload_start = icmp_start + usize::from(ICMP_HEADER_LEN);

        // Copy payload into reply
        reply[payload_start..payload_start + payload.len()].copy_from_slice(payload);

        // ICMP type=0 for Echo Reply
        reply[icmp_start] = 0;

        // Clear ICMP checksum field before recalculating
        reply[icmp_start + 2] = 0;
        reply[icmp_start + 3] = 0;

        // Calculate ICMP checksum (covers the entire ICMP message)
        let icmp_checksum = checksum::calculate(&reply[icmp_start..icmp_start + payload.len()]);
        reply[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

        Some(total_len.into())
    }
}

impl fmt::Display for IcmpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ICMP type={} code={}", self.icmp_type, self.icmp_code)
    }
}

struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    offset_bytes: usize,
    syn_flag: bool,
    ack_flag: bool,
}

impl TcpHeader {
    fn parse(data: &[u8]) -> Result<Self, String> {
        let n = data.len();

        if n < TCP_HEADER_MIN_LEN.into() {
            return Err(format!("Too short for TCP header ({n} bytes)"));
        }

        let flags = data[13];

        Ok(Self {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            seq_num: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ack_num: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            offset_bytes: usize::from(data[12] >> 4) * 4, // Convert 32-bit words to bytes
            syn_flag: flags & 0x02 != 0,
            ack_flag: flags & 0x10 != 0,
        })
    }

    fn write_reply_header(&self, reply: &mut [u8; ETHERNET_MTU]) -> Option<usize> {
        // Build SYN-ACK response
        if !self.syn_flag || self.ack_flag {
            return None;
        }

        println!("Building SYN-ACK response...");

        // Total length: IPv4 header without options (20 bytes)
        //               + minimum TCP header length (20 bytes)
        let total_len = u16::from(IPV4_HEADER_MIN_LEN) + u16::from(TCP_HEADER_MIN_LEN);
        reply[2..4].copy_from_slice(&total_len.to_be_bytes());

        let tcp_start = IPV4_HEADER_MIN_LEN.into();

        // Swap ports
        reply[tcp_start..tcp_start + 2].copy_from_slice(&self.dst_port.to_be_bytes());
        reply[tcp_start + 2..tcp_start + 4].copy_from_slice(&self.src_port.to_be_bytes());

        // Our sequence number (can be random, using 0 for simplicity)
        let our_seq = 0u32;
        reply[tcp_start + 4..tcp_start + 8].copy_from_slice(&our_seq.to_be_bytes());

        // Acknowledgment number = their seq + 1
        let our_ack = self.seq_num.wrapping_add(1);
        reply[tcp_start + 8..tcp_start + 12].copy_from_slice(&our_ack.to_be_bytes());

        // Data offset (5 * 4 = 20 bytes) in upper 4 bits
        reply[tcp_start + 12] = 0x50; // 5 << 4

        // Flags: SYN + ACK
        reply[tcp_start + 13] = 0x12; // SYN (0x02) | ACK (0x10)

        // Window size
        reply[tcp_start + 14..tcp_start + 16].copy_from_slice(&8192u16.to_be_bytes());

        // Checksum at bytes 16-17 calculated later with pseudo-header

        // Urgent pointer
        reply[tcp_start + 18..tcp_start + 20].copy_from_slice(&[0x00, 0x00]);

        // Calculate TCP checksum with pseudo-header
        let mut pseudo_header = [0u8; 12];
        pseudo_header[0..4].copy_from_slice(&reply[12..16]); // Source IP
        pseudo_header[4..8].copy_from_slice(&reply[16..20]); // Dest IP
        pseudo_header[8] = 0; // Reserved
        pseudo_header[9] = Protocol::as_u8(&Protocol::Tcp);
        pseudo_header[10..12].copy_from_slice(&u16::from(TCP_HEADER_MIN_LEN).to_be_bytes());

        // Combine pseudo-header + TCP header for checksum
        let mut checksum_data = [0u8; 12 + 20];
        checksum_data[0..12].copy_from_slice(&pseudo_header);
        checksum_data[12..32]
            .copy_from_slice(&reply[tcp_start..tcp_start + usize::from(TCP_HEADER_MIN_LEN)]);

        // Zero out checksum field before calculating
        checksum_data[12 + 16] = 0;
        checksum_data[12 + 17] = 0;

        let tcp_checksum = checksum::calculate(&checksum_data);
        reply[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

        Some(total_len.into())
    }
}

impl fmt::Display for TcpHeader {
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
