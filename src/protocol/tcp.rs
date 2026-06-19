pub use connections::TcpConnections;

mod connections;
mod flags;

use {
    crate::{
        ETHERNET_MTU, Ipv4AddrPair, checksum,
        protocol::{
            Protocol, payload_to_string,
            tcp::{
                connections::{ConnKey, TcpState},
                flags::TcpFlags,
            },
        },
        sys,
        try_ops::{TryAdd as _, TryGet as _, TryGetMut as _},
    },
    std::{
        fmt, io,
        time::{Duration, Instant},
    },
};

const TCP_HEADER_MIN_LEN: u8 = 20;

/// Struct for managing and replying to TCP packets. Includes the TCP header and the payload. Field
/// definitions below from RFC 9293, Section 3.1.
#[cfg_attr(test, derive(Debug, PartialEq, Eq, Clone))]
pub struct TcpHandler {
    src_port: u16,
    dst_port: u16,

    /// "The sequence number of the first data octet in this segment (except when the SYN flag is
    /// set). If SYN is set, the sequence number is the initial sequence number (ISN) and the first
    /// data octet is ISN+1."
    seq_num: u32,

    /// "If the ACK control bit is set, this field contains the value of the next sequence number
    /// the sender of the segment is expecting to receive. Once a connection is established, this
    /// is always sent."
    ack_num: u32,

    /// **This field is stored in units of bytes.**
    ///
    /// "The number of 32-bit words in the TCP header. This indicates where the data begins. The
    /// TCP header (even one including options) is an integer multiple of 32 bits long."
    offset_bytes: u8,

    flags: TcpFlags,
    payload: Vec<u8>,
}

impl TcpHandler {
    const PSEUDO_HEADER_LEN: usize = 12;

    /// Parses `data` as a TCP header and payload.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
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
                .ok_or("TCP data shorter than its Data Offset")?
                .to_vec(),
        })
    }

    /// Creates a TCP header and payload for replying to `self`, or returns `Ok(None)` for no reply.
    #[expect(
        clippy::too_many_lines,
        reason = "Large match expression to express reply cases clearly"
    )]
    pub fn into_reply(
        self,
        connections: &mut TcpConnections,
        ip_pair: Ipv4AddrPair,
    ) -> io::Result<Option<Self>> {
        /// Fields to configure when determining a reply.
        struct ReplyInfo {
            seq_num: u32,
            ack_num: u32,
            flags: TcpFlags,
            echo_payload: bool,
        }

        let key = ConnKey {
            client_ip: ip_pair.src,
            client_port: self.src_port,
            server_ip: ip_pair.dst,
            server_port: self.dst_port,
        };

        Ok(match (connections.tcp_state_of(&key), self.flags, self.payload.len()) {
            // SYN packet (step 1 of handshake)
            // Reply with SYN-ACK (step 2), no payload echo
            (TcpState::Closed, TcpFlags::Syn, _) => {
                // seq num = random ISN, local ack num = remote seq num + 1
                let isn = sys::random_u32()?;
                connections.store_isn(key, isn);
                connections.record_pending(
                    &key,
                    isn,
                    1,
                    self.seq_num.wrapping_add(1),
                    TcpFlags::SynAck,
                    Vec::new(),
                );

                Some(ReplyInfo {
                    seq_num: isn,
                    ack_num: self.seq_num.wrapping_add(1),
                    flags: TcpFlags::SynAck,
                    echo_payload: false,
                })
            }

            // Duplicate SYN while awaiting the handshake ACK (client's retransmission timer resent
            // the SYN) -> resend the same SYN-ACK (which was likely lost) using the already-stored
            // ISN
            (TcpState::SynReceived, TcpFlags::Syn, _)
                if let Some(isn) = connections.pending_isn(&key) =>
            {
                connections.record_pending(
                    &key,
                    isn,
                    1,
                    self.seq_num.wrapping_add(1),
                    TcpFlags::SynAck,
                    Vec::new(),
                );

                Some(ReplyInfo {
                    seq_num: isn,
                    ack_num: self.seq_num.wrapping_add(1),
                    flags: TcpFlags::SynAck,
                    echo_payload: false,
                })
            }

            // Handshake ACK (step 3) -> transition to ESTABLISHED, no reply needed
            // Remote ack num should be the previous local ISN + 1, which also becomes snd_una
            (TcpState::SynReceived, TcpFlags::Ack, 0)
                if connections
                    .pending_isn(&key)
                    .is_some_and(|isn| isn.wrapping_add(1) == self.ack_num) =>
            {
                // Set local rcv_nxt to remote seq_num
                connections.establish(&key, self.seq_num);
                connections.update_snd_una(&key, self.ack_num);
                None
            }

            // ACK acknowledging data the server has not yet sent (ack_num is past snd_nxt) -> per
            // RFC 9293, Section 3.10.7.4, drop the segment and reply with an ACK reflecting current
            // state.
            (TcpState::Established, TcpFlags::Ack, _)
                if connections.ack_exceeds_snd_nxt(&key, self.ack_num)
                    && let Some((snd_nxt, rcv_nxt)) = connections.get_snd_rcv_nxt(&key) =>
            {
                Some(ReplyInfo {
                    seq_num: snd_nxt,
                    ack_num: rcv_nxt,
                    flags: TcpFlags::Ack,
                    echo_payload: false,
                })
            }

            // Pure ACK (no payload) on an established connection (acknowledgment of data sent by
            // the server) -> advance snd_una, no reply
            (TcpState::Established, TcpFlags::Ack, 0) => {
                connections.update_snd_una(&key, self.ack_num);
                None
            }

            // In-order data packet on an established connection -> send ACK, echo payload. Use
            // snd_nxt as seq_num and rcv_nxt + bytes received as ack_num, then advance both locally
            // by bytes received.
            (TcpState::Established, TcpFlags::Ack, 1..)
                if let Some((snd_nxt, rcv_nxt)) = connections.get_snd_rcv_nxt(&key)
                    && self.seq_num == rcv_nxt =>
            {
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "`u32::MAX` (4_294_967_295) > `ETHERNET_MTU` (1500)"
                )]
                let payload_len = self.payload.len() as u32;

                connections.update_snd_una(&key, self.ack_num);
                connections.advance_snd_nxt(&key, payload_len);
                connections.advance_rcv_nxt(&key, payload_len);
                connections.record_pending(
                    &key,
                    snd_nxt,
                    payload_len,
                    rcv_nxt.wrapping_add(payload_len),
                    TcpFlags::Ack,
                    self.payload.clone(),
                );

                Some(ReplyInfo {
                    seq_num: snd_nxt,
                    ack_num: rcv_nxt.wrapping_add(payload_len),
                    flags: TcpFlags::Ack,
                    echo_payload: true,
                })
            }

            // Out-of-order/duplicate data or out-of-order FIN-ACK on an established connection
            // -> duplicate ACK. ACK rcv_nxt so the client knows what the server expects next, but
            // don't echo data, start closing, or advance snd_nxt/rcv_nxt.
            (TcpState::Established, TcpFlags::Ack | TcpFlags::FinAck, _)
                if let Some((snd_nxt, rcv_nxt)) = connections.get_snd_rcv_nxt(&key)
                    && self.seq_num != rcv_nxt =>
            {
                connections.update_snd_una(&key, self.ack_num);

                Some(ReplyInfo {
                    seq_num: snd_nxt,
                    ack_num: rcv_nxt,
                    flags: TcpFlags::Ack,
                    echo_payload: false,
                })
            }

            // FIN-ACK (connection teardown) on an established connection, arriving in order ->
            // start closing to wait for client's final ACK, reply with FIN-ACK.
            (TcpState::Established, TcpFlags::FinAck, _)
                if let Some((snd_nxt, rcv_nxt)) = connections.get_snd_rcv_nxt(&key)
                    && self.seq_num == rcv_nxt =>
            {
                connections.start_last_ack(&key);
                connections.advance_snd_nxt(&key, 1); // FIN consumes one sequence number
                connections.record_pending(
                    &key,
                    snd_nxt,
                    1,
                    rcv_nxt.wrapping_add(1),
                    TcpFlags::FinAck,
                    Vec::new(),
                );

                Some(ReplyInfo {
                    seq_num: snd_nxt,
                    ack_num: rcv_nxt.wrapping_add(1),
                    flags: TcpFlags::FinAck,
                    echo_payload: false,
                })
            }

            // Final ACK completing passive close (LAST-ACK) or any RST (never RST a RST)
            // -> remove connection, no reply
            (TcpState::LastAck, TcpFlags::Ack, 0) | (_, TcpFlags::Rst | TcpFlags::RstAck, _) => {
                connections.remove(&key);
                None
            }

            // FIN-WAIT-1, our FIN has been acknowledged (and nothing else) -> FIN-WAIT-2, no reply
            (TcpState::FinWait1, TcpFlags::Ack, 0)
                if let Some((snd_nxt, _)) = connections.get_snd_rcv_nxt(&key)
                    && self.ack_num == snd_nxt =>
            {
                connections.update_snd_una(&key, self.ack_num);
                connections.start_fin_wait_2(&key);
                None
            }

            // FIN-WAIT-1, the remote peer's FIN arrives before ours is acknowledged (simultaneous
            // close) -> ACK it. If it also acknowledges our FIN, the connection is fully closed
            // (skipping FIN-WAIT-2/TIME-WAIT), otherwise move to CLOSING to await that ACK.
            (TcpState::FinWait1, TcpFlags::FinAck, 0)
                if let Some((snd_nxt, rcv_nxt)) = connections.get_snd_rcv_nxt(&key)
                    && self.seq_num == rcv_nxt =>
            {
                connections.update_snd_una(&key, self.ack_num);

                if self.ack_num == snd_nxt {
                    connections.remove(&key);
                } else {
                    connections.start_simultaneous_closing(&key);
                }

                Some(ReplyInfo {
                    seq_num: snd_nxt,
                    ack_num: rcv_nxt.wrapping_add(1),
                    flags: TcpFlags::Ack,
                    echo_payload: false,
                })
            }

            // FIN-WAIT-2, the remote peer's FIN arrives, in order -> ACK it and finish closing (no
            // TIME-WAIT)
            (TcpState::FinWait2, TcpFlags::FinAck, 0)
                if let Some((snd_nxt, rcv_nxt)) = connections.get_snd_rcv_nxt(&key)
                    && self.seq_num == rcv_nxt =>
            {
                connections.remove(&key);

                Some(ReplyInfo {
                    seq_num: snd_nxt,
                    ack_num: rcv_nxt.wrapping_add(1),
                    flags: TcpFlags::Ack,
                    echo_payload: false,
                })
            }

            // CLOSING (simultaneous close), the remote peer's ACK of our FIN arrives -> fully
            // closed, no reply
            (TcpState::Closing, TcpFlags::Ack, 0)
                if let Some((snd_nxt, _)) = connections.get_snd_rcv_nxt(&key)
                    && self.ack_num == snd_nxt =>
            {
                connections.remove(&key);
                None
            }

            // Something else unrecognized (other than RST caught above) -> RST so the peer fails
            // fast instead of hanging. Per RFC 9293, Section 3.10.7.1, any non-RST segment to a
            // CLOSED (unknown) connection gets a RST.
            _ => Some(ReplyInfo {
                seq_num: self.ack_num,
                // ack_num is 0 because sending bare RST with no ACK flag leaves ack_num undefined
                ack_num: 0,
                flags: TcpFlags::Rst,
                echo_payload: false,
            }),
        }
        .map(|info| Self {
            // Swap source and destination ports
            src_port: self.dst_port,
            dst_port: self.src_port,
            seq_num: info.seq_num,
            ack_num: info.ack_num,
            offset_bytes: TCP_HEADER_MIN_LEN,
            flags: info.flags,
            payload: if info.echo_payload { self.payload } else { Vec::new() },
        }))
    }

    /// Initiates active close (RFC 9293 "CLOSE" call) for every connection currently ESTABLISHED,
    /// transitioning each to FIN-WAIT-1 and returning a FIN-ACK reply for it along with the
    /// `Ipv4AddrPair` for its IPv4 header.
    pub fn close_established(connections: &mut TcpConnections) -> Vec<(Self, Ipv4AddrPair)> {
        connections
            .established_keys()
            .into_iter()
            .filter_map(|key| {
                let (snd_nxt, rcv_nxt) = connections.get_snd_rcv_nxt(&key)?;
                connections.start_active_close(&key);
                connections.record_pending(&key, snd_nxt, 1, rcv_nxt, TcpFlags::FinAck, Vec::new());

                Some((
                    Self {
                        src_port: key.server_port,
                        dst_port: key.client_port,
                        seq_num: snd_nxt,
                        ack_num: rcv_nxt,
                        offset_bytes: TCP_HEADER_MIN_LEN,
                        flags: TcpFlags::FinAck,
                        payload: Vec::new(),
                    },
                    Ipv4AddrPair { src: key.server_ip, dst: key.client_ip },
                ))
            })
            .collect()
    }

    /// Reproduces every connection's pending unacked segment that is due for retransmission (RTO
    /// elapsed since it was last sent), or gives up and removes the connection once it has been
    /// retried `max_retries` times.
    pub fn retransmit_expired(
        connections: &mut TcpConnections,
        now: Instant,
        rto: Duration,
        max_retries: u8,
    ) -> Vec<(Self, Ipv4AddrPair)> {
        connections
            .expired_retransmit_keys(now, rto)
            .into_iter()
            .filter_map(|key| {
                let (seq_num, ack_num, flags, payload) =
                    connections.pending_for_retransmit(&key)?;
                let gave_up = connections.retransmit_or_give_up(&key, now, max_retries);

                (!gave_up).then_some((
                    Self {
                        src_port: key.server_port,
                        dst_port: key.client_port,
                        seq_num,
                        ack_num,
                        offset_bytes: TCP_HEADER_MIN_LEN,
                        flags,
                        payload,
                    },
                    Ipv4AddrPair { src: key.server_ip, dst: key.client_ip },
                ))
            })
            .collect()
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
        .copy_from_slice(&self.payload);

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

impl fmt::Display for TcpHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP | {} -> {} | seq={} ack={} | {}\n{}",
            self.src_port,
            self.dst_port,
            self.seq_num,
            self.ack_num,
            self.flags,
            payload_to_string(&self.payload),
        )
    }
}

#[cfg(test)]
mod tests {
    use {super::*, std::assert_matches};

    mod parse;
    mod reply;
    mod retransmit;
    mod write;
}
