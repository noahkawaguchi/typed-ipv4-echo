pub use connections::TcpConnections;

mod connections;
mod flags;
mod seq_space;
mod state;

use {
    crate::{
        Result,
        addr_pairs::{Ipv4AddrPair, PortPair},
        protocol::{
            Protocol,
            handler::Encode,
            payload_to_string, pseudo_header_checksum,
            tcp::{
                connections::ConnKey,
                flags::TcpFlags,
                seq_space::{AdvanceBy as _, SeqLe as _, SeqLt as _},
                state::{ConnState, PendingSegment, TcpState},
            },
        },
        sys,
        try_ops::{TryAdd as _, TryGet as _, TryGetMut as _},
    },
    std::{fmt, num::TryFromIntError, rc::Rc},
};

/// The minimum number of bytes in a TCP header (no options).
const TCP_HDR_MIN_LEN: u8 = 20;

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

    /// "The number of data octets beginning with the one indicated in the acknowledgment field
    /// that the sender of this segment is willing to accept."
    window: u16,

    payload: Option<Rc<[u8]>>,
}

/// Fields that differ when determining a segment to send.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
struct SendInfo {
    seq_num: u32,
    ack_num: u32,
    flags: TcpFlags,
    payload: Option<Rc<[u8]>>,
}

impl TcpHandler {
    /// "This represents the sequence numbers the local (receiving) TCP endpoint is willing to
    /// receive... segments overlapping the range RCV.NXT to RCV.NXT + RCV.WND - 1 carry acceptable
    /// data or control" (RFC 9293, Section 4).
    ///
    /// Currently left at max because as an echo server, there's no receive-side buffer accumulating
    /// data for an application.
    ///
    /// However, a dynamic RCV.WND could be used in the future to bound the send buffer's growth,
    /// throttling the peer's sending rate if they keep sending more data than they are willing to
    /// receive.
    const RCV_WND: u16 = u16::MAX;

    /// Parses `data` as a TCP header and payload.
    pub(super) fn parse(data: &[u8], ip_pair: Ipv4AddrPair) -> Result<Self> {
        let Some(tcp_header) = data.first_chunk::<{ TCP_HDR_MIN_LEN as usize }>() else {
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
            window: u16::from_be_bytes([tcp_header[14], tcp_header[15]]),
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
        Self {
            ip_pair,
            ports,
            seq_num,
            ack_num,
            offset_bytes: TCP_HDR_MIN_LEN,
            flags,
            window: Self::RCV_WND,
            payload,
        }
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

        Ok(match (connections.get_mut(&key), self.flags, self.payload.as_ref()) {
            // SYN packet (step 1 of handshake)
            // Reply with SYN-ACK (step 2), no payload echo
            (None, TcpFlags::Syn, _) => {
                // seq num = random ISN, local ack num = remote seq num + 1
                let send_info = SendInfo {
                    seq_num: sys::random_u32()?,
                    ack_num: self.seq_num.wrapping_add(1),
                    flags: TcpFlags::SynAck,
                    payload: None,
                };

                connections.store_isn(key, send_info.clone());

                Some(send_info)
            }

            // Duplicate SYN while awaiting the handshake ACK (client's retransmission timer resent
            // the SYN) -> resend the same SYN-ACK (which was likely lost) using the already-stored
            // ISN
            (
                Some(ConnState { tcp_state: TcpState::SynReceived, snd_una, pending, .. }),
                TcpFlags::Syn,
                _,
            ) => {
                let send_info = SendInfo {
                    seq_num: *snd_una, // ISN
                    ack_num: self.seq_num.wrapping_add(1),
                    flags: TcpFlags::SynAck,
                    payload: None,
                };

                pending.push(PendingSegment::new(send_info.clone(), 1));

                Some(send_info)
            }

            // Stray SYN on a synchronized connection -> send a challenge ACK, do not reset the
            // connection (RFC 9293, Section 3.10.7.4).
            //
            // Out-of-window SYN is caught at the general "First, check sequence number," while
            // in-window SYN is caught at "Fourth, check the SYN bit," but both have the same
            // result.
            (Some(&mut ConnState { tcp_state, snd_nxt, rcv_nxt, .. }), TcpFlags::Syn, _)
                if tcp_state != TcpState::SynReceived =>
            {
                Some(SendInfo {
                    seq_num: snd_nxt,
                    ack_num: rcv_nxt,
                    flags: TcpFlags::Ack,
                    payload: None,
                })
            }

            // ACK during SYN-RECEIVED with an unacceptable sequence number -> per RFC 9293, Section
            // 3.10.7.4, "First, check sequence number," reply with an ACK reflecting current state
            // and drop the segment.
            //
            // Due to the current simplification of not using a reassembly buffer, any SEG.SEQ other
            // than exactly RCV.NXT is treated as unacceptable rather than held for later.
            (
                Some(&mut ConnState { tcp_state: TcpState::SynReceived, snd_nxt, rcv_nxt, .. }),
                TcpFlags::Ack,
                None,
            ) if self.seq_num != rcv_nxt => Some(SendInfo {
                seq_num: snd_nxt,
                ack_num: rcv_nxt,
                flags: TcpFlags::Ack,
                payload: None,
            }),

            // Handshake ACK (step 3) -> transition to ESTABLISHED, no reply needed
            //
            // As per RFC 9293, Section 3.10.7.4, "Fifth, check the ACK field," "SYN-RECEIVED
            // STATE," if SND.UNA < SEG.ACK <= SND.NXT, enter ESTABLISHED and set SND.WND, SND.WL1,
            // and SND.WL2 without the freshness check used for ESTABLISHED state ACKs.
            (
                Some(conn @ ConnState { tcp_state: TcpState::SynReceived, .. }),
                TcpFlags::Ack,
                None,
            ) if self.seq_num == conn.rcv_nxt
                && conn.snd_una.seq_lt(self.ack_num)
                && self.ack_num.seq_le(conn.snd_nxt) =>
            {
                conn.tcp_state = TcpState::Established;
                conn.rcv_nxt = self.seq_num;
                conn.snd_una = self.ack_num;
                conn.snd_wnd = Some(self.window);
                conn.snd_wl1 = Some(self.seq_num);
                conn.snd_wl2 = Some(self.ack_num);
                conn.pending.clear(); // Only the SYN-ACK just acknowledged could have been pending

                None
            }

            // ACK acknowledging data the server has not yet sent (ack_num is past snd_nxt) ->
            // per RFC 9293, Section 3.10.7.4, drop the segment and reply with an ACK reflecting
            // current state.
            (
                Some(&mut ConnState { tcp_state: TcpState::Established, snd_nxt, rcv_nxt, .. }),
                TcpFlags::Ack,
                _,
            ) if snd_nxt.seq_lt(self.ack_num) => Some(SendInfo {
                seq_num: snd_nxt,
                ack_num: rcv_nxt,
                flags: TcpFlags::Ack,
                payload: None,
            }),

            // Pure ACK (no payload) on an established connection (acknowledgment of data sent by
            // the server) -> advance SND.UNA, then send however much the window allows from the
            // data queued to be sent, if any
            (
                Some(conn @ ConnState { tcp_state: TcpState::Established, .. }),
                TcpFlags::Ack,
                None,
            ) => {
                conn.incoming_ack_update(self)?;

                match conn.drain_transmittable()? {
                    Some(to_send) => Some(Self::data_payload(conn, to_send)?),
                    None => None,
                }
            }

            // In-order data packet on an established connection -> ACK receipt of data, advancing
            // RCV.NXT, and echo as much of the queued data as SND.WND currently allows. Buffer
            // anything that doesn't fit to go out later as the window opens.
            (
                Some(conn @ ConnState { tcp_state: TcpState::Established, .. }),
                TcpFlags::Ack,
                Some(payload),
            ) if self.seq_num == conn.rcv_nxt => {
                let payload_len = u32::from(self.payload_len()?);

                conn.incoming_ack_update(self)?;
                conn.rcv_nxt.advance_by(payload_len);
                conn.send_buffer.extend(payload.iter());

                Some(match conn.drain_transmittable()? {
                    Some(to_send) => Self::data_payload(conn, to_send)?,

                    None => SendInfo {
                        seq_num: conn.snd_nxt,
                        ack_num: conn.rcv_nxt,
                        flags: TcpFlags::Ack,
                        payload: None,
                    },
                })
            }

            // Out-of-order/duplicate data or out-of-order FIN-ACK on an established connection
            // -> duplicate ACK. ACK rcv_nxt so the client knows what the server expects next, but
            // don't echo data, start closing, or advance snd_nxt/rcv_nxt.
            (
                Some(conn @ ConnState { tcp_state: TcpState::Established, .. }),
                TcpFlags::Ack | TcpFlags::FinAck,
                _,
            ) if self.seq_num != conn.rcv_nxt => {
                conn.incoming_ack_update(self)?;

                Some(SendInfo {
                    seq_num: conn.snd_nxt,
                    ack_num: conn.rcv_nxt,
                    flags: TcpFlags::Ack,
                    payload: None,
                })
            }

            // FIN-ACK (connection teardown) on an established connection, arriving in order ->
            // start closing to wait for client's final ACK, reply with FIN-ACK.
            (
                Some(conn @ ConnState { tcp_state: TcpState::Established, .. }),
                TcpFlags::FinAck,
                _,
            ) if self.seq_num == conn.rcv_nxt => {
                let send_info = SendInfo {
                    seq_num: conn.snd_nxt,
                    ack_num: conn.rcv_nxt.wrapping_add(1),
                    flags: TcpFlags::FinAck,
                    payload: None,
                };

                conn.incoming_ack_update(self)?;

                conn.tcp_state = TcpState::LastAck;
                conn.snd_nxt.advance_by(1); // Our FIN consumes one sequence number
                conn.rcv_nxt.advance_by(1); // Peer's FIN consumes one sequence number

                conn.pending.push(PendingSegment::new(send_info.clone(), 1));

                Some(send_info)
            }

            // Final ACK completing passive close (LAST-ACK) -> remove connection, no reply
            (Some(ConnState { tcp_state: TcpState::LastAck, .. }), TcpFlags::Ack, None) => {
                connections.remove(&key);
                None
            }

            // In-order data arriving in FIN-WAIT-1/FIN-WAIT-2, i.e. after we've sent our own FIN
            // but before the peer's FIN has arrived (half closed) -> ACK it, don't echo because we
            // have no send side left, and advance rcv_nxt
            (
                Some(conn @ ConnState { tcp_state: TcpState::FinWait1 | TcpState::FinWait2, .. }),
                TcpFlags::Ack,
                Some(_),
            ) if self.seq_num == conn.rcv_nxt => {
                let payload_len = u32::from(self.payload_len()?);

                let send_info = SendInfo {
                    seq_num: conn.snd_nxt,
                    ack_num: conn.rcv_nxt.wrapping_add(payload_len),
                    flags: TcpFlags::Ack,
                    payload: None,
                };

                conn.incoming_ack_update(self)?;
                conn.rcv_nxt.advance_by(payload_len);

                Some(send_info)
            }

            // FIN-WAIT-1, our FIN has been acknowledged (and nothing else) -> FIN-WAIT-2, no reply
            (Some(conn @ ConnState { tcp_state: TcpState::FinWait1, .. }), TcpFlags::Ack, None)
                if self.ack_num == conn.snd_nxt =>
            {
                conn.incoming_ack_update(self)?;
                conn.tcp_state = TcpState::FinWait2;
                None
            }

            // FIN-WAIT-1, the remote peer's FIN arrives before ours is acknowledged (simultaneous
            // close) -> ACK it. If it also acknowledges our FIN, the connection is fully closed
            // (skipping FIN-WAIT-2/TIME-WAIT), otherwise move to CLOSING to await that ACK.
            (
                Some(conn @ ConnState { tcp_state: TcpState::FinWait1, .. }),
                TcpFlags::FinAck,
                None,
            ) if self.seq_num == conn.rcv_nxt => {
                let send_info = SendInfo {
                    seq_num: conn.snd_nxt,
                    ack_num: conn.rcv_nxt.wrapping_add(1),
                    flags: TcpFlags::Ack,
                    payload: None,
                };

                conn.incoming_ack_update(self)?;

                if self.ack_num == conn.snd_nxt {
                    connections.remove(&key);
                } else {
                    // Consume one sequence number in RCV.NXT for the peer's FIN
                    conn.rcv_nxt.advance_by(1);
                    conn.tcp_state = TcpState::Closing;
                }

                Some(send_info)
            }

            // FIN-WAIT-2, the remote peer's FIN arrives, in order -> ACK it and finish closing (no
            // TIME-WAIT)
            (
                Some(&mut ConnState { tcp_state: TcpState::FinWait2, snd_nxt, rcv_nxt, .. }),
                TcpFlags::FinAck,
                None,
            ) if self.seq_num == rcv_nxt => {
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
            (
                Some(&mut ConnState { tcp_state: TcpState::Closing, snd_nxt, .. }),
                TcpFlags::Ack,
                None,
            ) if self.ack_num == snd_nxt => {
                connections.remove(&key);
                None
            }

            // RST on a known connection -> RFC 9293, Section 3.10.7.4 has three cases for when the
            // RST bit is set, protecting against a blind reset attack (as described in RFC 5961,
            // Section 3):
            //   Case 1: SEG.SEQ outside window           -> silently drop segment
            //   Case 2: SEG.SEQ == RCV.NXT               -> reset connection, no reply
            //   Case 3: SEG.SEQ in window but != RCV.NXT -> no connection reset, send challenge ACK
            (
                Some(&mut ConnState { snd_nxt, rcv_nxt, .. }),
                TcpFlags::Rst | TcpFlags::RstAck,
                _,
            ) => {
                if self.seq_num == rcv_nxt {
                    // Case 2
                    connections.remove(&key);
                    None
                } else {
                    // Check whether `seq_num` falls within the receive window [RCV.NXT, RCV.NXT +
                    // RCV.WND). true -> Case 3, false -> Case 1.
                    (rcv_nxt.seq_le(self.seq_num)
                        && self
                            .seq_num
                            .seq_lt(rcv_nxt.wrapping_add(u32::from(Self::RCV_WND))))
                    .then_some(SendInfo {
                        seq_num: snd_nxt,
                        ack_num: rcv_nxt,
                        flags: TcpFlags::Ack,
                        payload: None,
                    })
                }
            }

            // RST from an unknown (CLOSED) connection -> silently drop segment (never RST a RST)
            (None, TcpFlags::Rst | TcpFlags::RstAck, _) => None,

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

    /// Creates a `SendInfo` for the payload `to_send`, using and then updating the state of `conn`.
    fn data_payload(conn: &mut ConnState, to_send: Rc<[u8]>) -> Result<SendInfo, TryFromIntError> {
        let send_len = u32::try_from(to_send.len())?;

        let send_info = SendInfo {
            seq_num: conn.snd_nxt,
            ack_num: conn.rcv_nxt,
            flags: TcpFlags::Ack,
            payload: Some(to_send),
        };

        conn.snd_nxt.advance_by(send_len);
        conn.pending
            .push(PendingSegment::new(send_info.clone(), send_len));

        Ok(send_info)
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

        // Window size for flow control
        buf.try_get_mut(14..16)?
            .copy_from_slice(&self.window.to_be_bytes());

        // Checksum at bytes 16-17 calculated later with pseudo-header

        // Urgent pointer
        buf.try_get_mut(18..20)?.copy_from_slice(&[0x00, 0x00]);

        // Copy payload into reply if echoing
        if let Some(data) = self.payload.as_ref() {
            buf.try_get_mut(
                usize::from(TCP_HDR_MIN_LEN)..usize::from(TCP_HDR_MIN_LEN).try_add(data.len())?,
            )?
            .copy_from_slice(data);
        }

        // TCP segment length: minimum TCP header length (20 bytes) + payload length (0+ bytes)
        let tcp_segment_len = u16::from(TCP_HDR_MIN_LEN).try_add(self.payload_len()?)?;

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
    mod abort;
    mod echo;
    mod establish;
    mod flow_control;
    mod parse;
    mod retransmit;
    mod stray_syn;
    mod terminate;
    mod utils;
    mod window;
    mod write;

    pub(super) use utils::*;
    use {
        super::*,
        crate::protocol::test_consts::{DST_IP, IP_PAIR, SRC_IP},
        std::{assert_matches, collections::VecDeque},
    };
}
