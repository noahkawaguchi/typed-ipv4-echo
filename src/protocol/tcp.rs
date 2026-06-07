pub use connections::TcpConnections;

mod connections;
mod flags;

#[cfg(test)]
mod tests;

use crate::{
    ETHERNET_MTU, Ipv4AddrPair, checksum,
    protocol::{
        Protocol, payload_to_string,
        tcp::{connections::ConnKey, flags::TcpFlags},
    },
    sys,
    try_ops::{TryAdd, TryGet, TryGetMut},
};
use std::{fmt, io};

const TCP_HEADER_MIN_LEN: u8 = 20;

/// Struct for managing and replying to TCP packets. Includes the TCP header and the payload.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct TcpHandler<'a> {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    offset_bytes: u8,
    flags: TcpFlags,
    payload: &'a [u8],
}

impl<'a> TcpHandler<'a> {
    const PSEUDO_HEADER_LEN: usize = 12;

    /// Parses `data` as a TCP header and payload.
    pub fn parse(data: &'a [u8]) -> Result<Self, String> {
        let Some(tcp_header) = data.first_chunk::<{ TCP_HEADER_MIN_LEN as usize }>() else {
            return Err(format!("Too short for TCP header ({} bytes)", data.len()));
        };

        // Convert length in 32-bit words in the upper 4 bits to length in bytes in the full 8 bits
        let offset_bytes = tcp_header[12] >> 4 << 2;

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
            flags: tcp_header[13].try_into()?,
            payload: data
                .get(offset_bytes.into()..)
                .ok_or("Data shorter than its Data Offset")?,
        })
    }

    /// Creates a TCP header and payload for replying to `self`, or returns `Ok(None)` for no reply.
    pub fn create_reply(
        &self,
        connections: &mut TcpConnections,
        ip_pair: Ipv4AddrPair,
    ) -> Result<Option<Self>, io::Error> {
        let key = ConnKey {
            client_ip: ip_pair.src,
            client_port: self.src_port,
            server_ip: ip_pair.dst,
            server_port: self.dst_port,
        };

        match (self.flags, self.payload.len()) {
            // SYN packet (step 1 of handshake)
            // Reply with SYN-ACK (step 2), no payload echo
            (TcpFlags::Syn, _) => {
                // seq num = random ISN, local ack num = remote seq num + 1
                let isn = sys::random_u32()?;
                connections.store_isn(key, isn);

                Ok(Some(Self {
                    // Swap source and destination ports
                    src_port: self.dst_port,
                    dst_port: self.src_port,
                    seq_num: isn,
                    ack_num: self.seq_num.wrapping_add(1),
                    offset_bytes: TCP_HEADER_MIN_LEN,
                    flags: TcpFlags::SynAck,
                    payload: &[],
                }))
            }

            // Handshake ACK (step 3) -> transition to Established, no reply needed
            // Remote ack num should be the previous local ISN + 1
            (TcpFlags::Ack, 0)
                if connections
                    .pending_isn(&key)
                    .is_some_and(|isn| isn.wrapping_add(1) == self.ack_num) =>
            {
                connections.establish(&key);
                Ok(None)
            }

            // Data packet (ACK with payload) -> send ACK, echo payload
            (TcpFlags::Ack, 1..) if connections.is_established(&key) => {
                // Local seq num = what the client expects next (remote ack num)
                // Local ack num = remote seq num + payload length (intentionally wrapping)
                Ok(Some(Self {
                    // Swap source and destination ports
                    src_port: self.dst_port,
                    dst_port: self.src_port,
                    seq_num: self.ack_num,
                    #[expect(
                        clippy::cast_possible_truncation,
                        reason = "`u32::MAX` (4_294_967_295) > `ETHERNET_MTU` (1500)"
                    )]
                    ack_num: self.seq_num.wrapping_add(self.payload.len() as u32),
                    offset_bytes: TCP_HEADER_MIN_LEN,
                    flags: TcpFlags::Ack,
                    payload: self.payload,
                }))
            }

            // FIN-ACK (connection teardown) -> clean up local state and reply with FIN-ACK
            (TcpFlags::FinAck, _) => {
                connections.remove(&key);

                Ok(Some(Self {
                    src_port: self.dst_port,
                    dst_port: self.src_port,
                    seq_num: self.ack_num,
                    ack_num: self.seq_num.wrapping_add(1),
                    offset_bytes: TCP_HEADER_MIN_LEN,
                    flags: TcpFlags::FinAck,
                    payload: &[],
                }))
            }

            _ => Ok(None), // No reply implemented
        }
    }

    /// Copies data from `self` to write a TCP header and payload into `buf`, returning the number
    /// of bytes written.
    pub fn write_into(&self, buf: &mut [u8], ip_pair: Ipv4AddrPair) -> Result<u16, String> {
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

        // Flags
        *buf.try_get_mut(13)? = self.flags.into();

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
        pseudo_header[0..4].copy_from_slice(&ip_pair.src.octets());
        pseudo_header[4..8].copy_from_slice(&ip_pair.dst.octets());
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
}

impl fmt::Display for TcpHandler<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP | {} -> {} | seq={} ack={} | {}\n{}",
            self.src_port,
            self.dst_port,
            self.seq_num,
            self.ack_num,
            self.flags,
            payload_to_string(self.payload),
        )
    }
}
