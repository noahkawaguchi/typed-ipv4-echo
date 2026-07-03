pub use connections::TcpConnections;

mod connections;
mod flags;

use {
    crate::{
        Result,
        addr_pairs::{Ipv4AddrPair, PortPair},
        protocol::{
            Protocol,
            handler::Encode,
            payload_to_string, pseudo_header_checksum,
            tcp::{
                connections::{ConnKey, TcpState},
                flags::TcpFlags,
            },
        },
        sys,
        try_ops::{TryAdd as _, TryGet as _, TryGetMut as _},
    },
    std::{fmt, num::TryFromIntError, rc::Rc},
};

const TCP_HEADER_MIN_LEN: u8 = 20;

/// Manages TCP headers, data, and reply logic. Field definitions below from RFC 9293, Section 3.1.
#[cfg_attr(test, derive(Debug, PartialEq, Eq, Clone))]
pub struct TcpHandler {
    /// Not a part of the TCP header, but required for connection state and checksum calculation.
    ip_pair: Ipv4AddrPair,

    ports: PortPair,

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
    payload: Option<Rc<[u8]>>,
}

/// Fields that differ when determining a segment to send.
#[derive(Clone)]
struct SendInfo {
    seq_num: u32,
    ack_num: u32,
    flags: TcpFlags,
    payload: Option<Rc<[u8]>>,
}

impl TcpHandler {
    /// Parses `data` as a TCP header and payload.
    pub(super) fn parse(data: &[u8], ip_pair: Ipv4AddrPair) -> Result<Self> {
        let Some(tcp_header) = data.first_chunk::<{ TCP_HEADER_MIN_LEN as usize }>() else {
            return Err(format!("Too short for TCP header ({} bytes)", data.len()).into());
        };

        if pseudo_header_checksum(data, ip_pair, Protocol::Tcp)? != 0 {
            return Err("Invalid TCP checksum".into());
        }

        // Convert length in 32-bit words in the upper 4 bits to length in bytes in the full 8 bits
        let offset_bytes = tcp_header[12] >> 4 << 2;

        Ok(Self {
            ip_pair,
            ports: PortPair {
                src: u16::from_be_bytes([tcp_header[0], tcp_header[1]]),
                dst: u16::from_be_bytes([tcp_header[2], tcp_header[3]]),
            },
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
                // Use `None` for empty payloads to avoid allocating
                .and_then(|p| (!p.is_empty()).then(|| Rc::from(p))),
        })
    }

    fn from_pairs_and_info(
        ip_pair: Ipv4AddrPair,
        ports: PortPair,
        SendInfo { seq_num, ack_num, flags, payload }: SendInfo,
    ) -> Self {
        Self { ip_pair, ports, seq_num, ack_num, offset_bytes: TCP_HEADER_MIN_LEN, flags, payload }
    }

    /// Creates a TCP header and payload for replying to `self`, or returns `Ok(None)` for no reply.
    #[expect(
        clippy::too_many_lines,
        reason = "Large match expression to express reply cases clearly"
    )]
    pub(super) fn create_reply(&self, connections: &mut TcpConnections) -> Result<Option<Self>> {
        let key = ConnKey {
            client_ip: self.ip_pair.src,
            client_port: self.ports.src,
            server_ip: self.ip_pair.dst,
            server_port: self.ports.dst,
        };

        Ok(match (connections.tcp_state_of(&key), self.flags, self.payload.as_ref()) {
            // SYN packet (step 1 of handshake)
            // Reply with SYN-ACK (step 2), no payload echo
            (TcpState::Closed, TcpFlags::Syn, _) => {
                // seq num = random ISN, local ack num = remote seq num + 1
                let isn = sys::random_u32()?;
                connections.store_isn(key, isn);

                let send_info = SendInfo {
                    seq_num: isn,
                    ack_num: self.seq_num.wrapping_add(1),
                    flags: TcpFlags::SynAck,
                    payload: None,
                };

                connections.record_pending(&key, send_info.clone(), 1);

                Some(send_info)
            }

            // Duplicate SYN while awaiting the handshake ACK (client's retransmission timer resent
            // the SYN) -> resend the same SYN-ACK (which was likely lost) using the already-stored
            // ISN
            (TcpState::SynReceived, TcpFlags::Syn, _)
                if let Some(isn) = connections.pending_isn(&key) =>
            {
                let send_info = SendInfo {
                    seq_num: isn,
                    ack_num: self.seq_num.wrapping_add(1),
                    flags: TcpFlags::SynAck,
                    payload: None,
                };

                connections.record_pending(&key, send_info.clone(), 1);

                Some(send_info)
            }

            // Stray SYN on a synchronized connection -> send a challenge ACK, do not reset the
            // connection (RFC 9293, Section 3.10.7.4).
            //
            // Out-of-window SYN is caught at the general "First, check sequence number," while
            // in-window SYN is caught at "Fourth, check the SYN bit," but both have the same
            // result.
            (_, TcpFlags::Syn, _)
                if let Some((snd_nxt, rcv_nxt)) = connections.get_snd_rcv_nxt(&key) =>
            {
                Some(SendInfo {
                    seq_num: snd_nxt,
                    ack_num: rcv_nxt,
                    flags: TcpFlags::Ack,
                    payload: None,
                })
            }

            // Handshake ACK (step 3) -> transition to ESTABLISHED, no reply needed
            // Remote ack num should be the previous local ISN + 1, which also becomes snd_una
            (TcpState::SynReceived, TcpFlags::Ack, None)
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
                Some(SendInfo {
                    seq_num: snd_nxt,
                    ack_num: rcv_nxt,
                    flags: TcpFlags::Ack,
                    payload: None,
                })
            }

            // Pure ACK (no payload) on an established connection (acknowledgment of data sent by
            // the server) -> advance snd_una, no reply
            (TcpState::Established, TcpFlags::Ack, None) => {
                connections.update_snd_una(&key, self.ack_num);
                None
            }

            // In-order data packet on an established connection -> send ACK, echo payload. Use
            // snd_nxt as seq_num and rcv_nxt + bytes received as ack_num, then advance both locally
            // by bytes received.
            (TcpState::Established, TcpFlags::Ack, Some(payload))
                if let Some((snd_nxt, rcv_nxt)) = connections.get_snd_rcv_nxt(&key)
                    && self.seq_num == rcv_nxt =>
            {
                let payload_len = u32::from(self.payload_len()?);

                connections.update_snd_una(&key, self.ack_num);
                connections.advance_snd_nxt(&key, payload_len);
                connections.advance_rcv_nxt(&key, payload_len);

                let send_info = SendInfo {
                    seq_num: snd_nxt,
                    ack_num: rcv_nxt.wrapping_add(payload_len),
                    flags: TcpFlags::Ack,
                    payload: Some(Rc::clone(payload)),
                };

                connections.record_pending(&key, send_info.clone(), payload_len);

                Some(send_info)
            }

            // Out-of-order/duplicate data or out-of-order FIN-ACK on an established connection
            // -> duplicate ACK. ACK rcv_nxt so the client knows what the server expects next, but
            // don't echo data, start closing, or advance snd_nxt/rcv_nxt.
            (TcpState::Established, TcpFlags::Ack | TcpFlags::FinAck, _)
                if let Some((snd_nxt, rcv_nxt)) = connections.get_snd_rcv_nxt(&key)
                    && self.seq_num != rcv_nxt =>
            {
                connections.update_snd_una(&key, self.ack_num);

                Some(SendInfo {
                    seq_num: snd_nxt,
                    ack_num: rcv_nxt,
                    flags: TcpFlags::Ack,
                    payload: None,
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

                let send_info = SendInfo {
                    seq_num: snd_nxt,
                    ack_num: rcv_nxt.wrapping_add(1),
                    flags: TcpFlags::FinAck,
                    payload: None,
                };

                connections.record_pending(&key, send_info.clone(), 1);

                Some(send_info)
            }

            // Final ACK completing passive close (LAST-ACK) -> remove connection, no reply
            (TcpState::LastAck, TcpFlags::Ack, None) => {
                connections.remove(&key);
                None
            }

            // In-order data arriving in FIN-WAIT-1/FIN-WAIT-2, i.e. after we've sent our own FIN
            // but before the peer's FIN has arrived (half closed) -> ACK it, don't echo because we
            // have no send side left, and advance rcv_nxt
            (TcpState::FinWait1 | TcpState::FinWait2, TcpFlags::Ack, Some(_))
                if let Some((snd_nxt, rcv_nxt)) = connections.get_snd_rcv_nxt(&key)
                    && self.seq_num == rcv_nxt =>
            {
                let payload_len = u32::from(self.payload_len()?);

                connections.update_snd_una(&key, self.ack_num);
                connections.advance_rcv_nxt(&key, payload_len);

                Some(SendInfo {
                    seq_num: snd_nxt,
                    ack_num: rcv_nxt.wrapping_add(payload_len),
                    flags: TcpFlags::Ack,
                    payload: None,
                })
            }

            // FIN-WAIT-1, our FIN has been acknowledged (and nothing else) -> FIN-WAIT-2, no reply
            (TcpState::FinWait1, TcpFlags::Ack, None)
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
            (TcpState::FinWait1, TcpFlags::FinAck, None)
                if let Some((snd_nxt, rcv_nxt)) = connections.get_snd_rcv_nxt(&key)
                    && self.seq_num == rcv_nxt =>
            {
                connections.update_snd_una(&key, self.ack_num);

                if self.ack_num == snd_nxt {
                    connections.remove(&key);
                } else {
                    connections.start_simultaneous_closing(&key);
                }

                Some(SendInfo {
                    seq_num: snd_nxt,
                    ack_num: rcv_nxt.wrapping_add(1),
                    flags: TcpFlags::Ack,
                    payload: None,
                })
            }

            // FIN-WAIT-2, the remote peer's FIN arrives, in order -> ACK it and finish closing (no
            // TIME-WAIT)
            (TcpState::FinWait2, TcpFlags::FinAck, None)
                if let Some((snd_nxt, rcv_nxt)) = connections.get_snd_rcv_nxt(&key)
                    && self.seq_num == rcv_nxt =>
            {
                connections.remove(&key);

                Some(SendInfo {
                    seq_num: snd_nxt,
                    ack_num: rcv_nxt.wrapping_add(1),
                    flags: TcpFlags::Ack,
                    payload: None,
                })
            }

            // CLOSING (simultaneous close), the remote peer's ACK of our FIN arrives -> fully
            // closed, no reply
            (TcpState::Closing, TcpFlags::Ack, None)
                if let Some((snd_nxt, _)) = connections.get_snd_rcv_nxt(&key)
                    && self.ack_num == snd_nxt =>
            {
                connections.remove(&key);
                None
            }

            // Any RST -> RFC 9293, Section 3.10.7.4 has three cases for when the RST bit is set,
            // protecting against a blind reset attack (as described in RFC 5961, Section 3):
            //
            // Case 1: SEG.SEQ outside window           -> silently drop segment
            // Case 2: SEG.SEQ == RCV.NXT               -> reset connection, no reply
            // Case 3: SEG.SEQ in window but != RCV.NXT -> no connection reset, send challenge ACK
            //
            // A RST from an unknown (CLOSED) connection is also silently dropped (never RST a RST)
            (_, TcpFlags::Rst | TcpFlags::RstAck, _) => {
                connections
                    .get_snd_rcv_nxt(&key)
                    .and_then(|(snd_nxt, rcv_nxt)| {
                        if self.seq_num == rcv_nxt {
                            // Case 2
                            connections.remove(&key);
                            None
                        } else {
                            // Cases 1 and 3
                            connections
                                .seq_in_recv_window(&key, self.seq_num)
                                .then_some(SendInfo {
                                    seq_num: snd_nxt,
                                    ack_num: rcv_nxt,
                                    flags: TcpFlags::Ack,
                                    payload: None,
                                })
                        }
                    })
            }

            // Something else unrecognized (other than RST caught above) -> RST so the peer fails
            // fast instead of hanging. Per RFC 9293, Section 3.10.7.1, any non-RST segment to a
            // CLOSED (unknown) connection gets a RST.
            _ => Some(SendInfo {
                seq_num: self.ack_num,
                // ack_num is 0 because sending bare RST with no ACK flag leaves ack_num undefined
                ack_num: 0,
                flags: TcpFlags::Rst,
                payload: None,
            }),
        }
        .map(|send_info| {
            Self::from_pairs_and_info(self.ip_pair.swapped(), self.ports.swapped(), send_info)
        }))
    }

    /// Returns the number of bytes in the payload, or 0 if the payload is `None`.
    fn payload_len(&self) -> Result<u16, TryFromIntError> {
        self.payload.as_ref().map_or(0, |p| p.len()).try_into()
    }
}

impl Encode for TcpHandler {
    fn write_into(&self, buf: &mut [u8]) -> Result<u16> {
        // Source and destination ports
        buf.try_get_mut(..2)?
            .copy_from_slice(&self.ports.src.to_be_bytes());
        buf.try_get_mut(2..4)?
            .copy_from_slice(&self.ports.dst.to_be_bytes());

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

        // Copy payload into reply if echoing
        if let Some(data) = self.payload.as_ref() {
            buf.try_get_mut(
                usize::from(TCP_HEADER_MIN_LEN)
                    ..usize::from(TCP_HEADER_MIN_LEN).try_add(data.len())?,
            )?
            .copy_from_slice(data);
        }

        // TCP segment length: minimum TCP header length (20 bytes) + payload length (0+ bytes)
        let tcp_segment_len = u16::from(TCP_HEADER_MIN_LEN).try_add(self.payload_len()?)?;

        // Zero out checksum field before calculating checksum
        buf.try_get_mut(16..18)?.copy_from_slice(&[0x00, 0x00]);

        let tcp_checksum = pseudo_header_checksum(
            buf.try_get(..usize::from(tcp_segment_len))?,
            self.ip_pair,
            self.proto(),
        )?;

        buf.try_get_mut(16..18)?
            .copy_from_slice(&tcp_checksum.to_be_bytes());

        Ok(tcp_segment_len)
    }

    fn proto(&self) -> Protocol { Protocol::Tcp }

    fn get_ip_pair(&self) -> Ipv4AddrPair { self.ip_pair }
}

impl fmt::Display for TcpHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP | {} | seq={} ack={} | {}\n{}",
            self.ports,
            self.seq_num,
            self.ack_num,
            self.flags,
            payload_to_string(self.payload.as_deref().unwrap_or_default()),
        )
    }
}

#[cfg(test)]
mod tests {
    mod parse;
    mod reply;
    mod retransmit;
    mod write;

    use {
        super::*,
        crate::protocol::test_consts::{DST_IP, IP_PAIR, SRC_IP},
        std::assert_matches,
    };

    /// Connection key shared by test modules.
    const KEY: ConnKey =
        ConnKey { client_ip: SRC_IP, client_port: 1234, server_ip: DST_IP, server_port: 80 };

    /// Builds an incoming packet from the client (port 1234) to the server (port 80).
    fn client_packet(seq_num: u32, ack_num: u32, flags: TcpFlags, payload: &[u8]) -> TcpHandler {
        TcpHandler {
            ip_pair: Ipv4AddrPair { src: KEY.client_ip, dst: KEY.server_ip },
            ports: PortPair { src: KEY.client_port, dst: KEY.server_port },
            seq_num,
            ack_num,
            offset_bytes: 20,
            flags,
            payload: (!payload.is_empty()).then(|| Rc::from(payload)),
        }
    }

    /// Builds an expected reply from the server (port 80) to the client (port 1234).
    fn server_reply(seq_num: u32, ack_num: u32, flags: TcpFlags, payload: &[u8]) -> TcpHandler {
        TcpHandler {
            ip_pair: Ipv4AddrPair { src: KEY.server_ip, dst: KEY.client_ip },
            ports: PortPair { src: KEY.server_port, dst: KEY.client_port },
            seq_num,
            ack_num,
            offset_bytes: 20,
            flags,
            payload: (!payload.is_empty()).then(|| Rc::from(payload)),
        }
    }
}
