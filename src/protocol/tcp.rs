pub use connections::TcpConnections;

mod connections;
mod flags;
mod payload;
mod pending_segment;
mod seq_space;
mod state;

use {
    crate::{
        Result,
        addr_pairs::{Ipv4AddrPair, PortPair},
        protocol::{
            Protocol,
            display::{PrettyPayload, WithThousandsSeparators as _},
            handler::Encode,
            pseudo_header_checksum,
            tcp::{
                connections::ConnKey,
                flags::TcpFlags,
                payload::TcpPayload,
                pending_segment::PendingSegment,
                seq_space::{SeqDist, SeqPoint},
                state::{ConnState, TcpState, WindowState},
            },
        },
        sys,
        try_ops::{TryAdd as _, TryGet as _, TryGetMut as _},
    },
    std::{fmt, time::Instant},
};

/// The minimum number of bytes in a TCP header (no options).
const TCP_HDR_MIN_LEN: u8 = 20;

/// The single phantom byte consumed by SYN.
const SYN_BYTE: SeqDist<u32> = SeqDist::new(1);

/// The single phantom byte consumed by FIN.
const FIN_BYTE: SeqDist<u32> = SeqDist::new(1);

/// Manages TCP headers, data, and reply logic. Field definitions below from RFC 9293, Section 3.1.
#[cfg_attr(test, derive(Debug, PartialEq, Eq, Clone))]
pub struct TcpHandler {
    /// Not a part of the TCP header, but required for connection state and checksum calculation.
    ip_pair: Ipv4AddrPair,

    ports: PortPair,

    /// "The sequence number of the first data octet in this segment (except when the SYN flag is
    /// set). If SYN is set, the sequence number is the initial sequence number (ISN) and the first
    /// data octet is ISN+1."
    seq_num: SeqPoint,

    /// "If the ACK control bit is set, this field contains the value of the next sequence number
    /// the sender of the segment is expecting to receive. Once a connection is established, this
    /// is always sent."
    ack_num: SeqPoint,

    /// **This field is stored in units of bytes.**
    ///
    /// "The number of 32-bit words in the TCP header. This indicates where the data begins. The
    /// TCP header (even one including options) is an integer multiple of 32 bits long."
    offset_bytes: u8,

    flags: TcpFlags,

    /// "The number of data octets beginning with the one indicated in the acknowledgment field
    /// that the sender of this segment is willing to accept."
    window: SeqDist<u16>,

    payload: Option<TcpPayload>,
}

/// Fields that differ when determining a segment to send.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
struct SendInfo {
    seq_num: SeqPoint,
    ack_num: SeqPoint,
    flags: TcpFlags,
    payload: Option<TcpPayload>,
}

impl SendInfo {
    const fn pure_ack(seq_num: SeqPoint, ack_num: SeqPoint) -> Self {
        Self { seq_num, ack_num, flags: TcpFlags::Ack, payload: None }
    }
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
    const RCV_WND: SeqDist<u16> = SeqDist::new(u16::MAX);

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
            seq_num: SeqPoint::new(u32::from_be_bytes([
                tcp_header[4],
                tcp_header[5],
                tcp_header[6],
                tcp_header[7],
            ])),
            ack_num: SeqPoint::new(u32::from_be_bytes([
                tcp_header[8],
                tcp_header[9],
                tcp_header[10],
                tcp_header[11],
            ])),
            offset_bytes,
            flags: tcp_header[13].try_into()?,
            window: SeqDist::new(u16::from_be_bytes([tcp_header[14], tcp_header[15]])),
            payload: TcpPayload::try_from_iter(
                data.get(offset_bytes.into()..)
                    .into_iter()
                    .flatten()
                    .copied(),
            )?,
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

        Ok(match (connections.get_mut(&key), self.flags, &self.payload) {
            // SYN packet (step 1 of handshake)
            // Reply with SYN-ACK (step 2), no payload echo
            (None, TcpFlags::Syn, _) => {
                // seq num = random ISN, local ack num = remote seq num + 1
                let send_info = SendInfo {
                    seq_num: SeqPoint::new(sys::random_u32()?),
                    ack_num: self.seq_num + SYN_BYTE,
                    flags: TcpFlags::SynAck,
                    payload: None,
                };

                connections.insert_syn_rcv(key, ConnState::from_syn_ack(send_info.clone())?)?;

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
                    ack_num: self.seq_num + SYN_BYTE,
                    flags: TcpFlags::SynAck,
                    payload: None,
                };

                pending.push(PendingSegment::new(send_info.clone(), Instant::now()));

                Some(send_info)
            }

            // Stray SYN or SYN-ACK on a synchronized connection -> send a challenge ACK, do not
            // reset the connection (RFC 9293, Section 3.10.7.4).
            //
            // Out-of-window SYN is caught at the general "First, check sequence number," while
            // in-window SYN is caught at "Fourth, check the SYN bit," but both have the same
            // result. The ACK field and ACK bit are checked fifth, so SYN and SYN-ACK are treated
            // the same here.
            (
                Some(&mut ConnState { tcp_state, snd_nxt, rcv_nxt, .. }),
                TcpFlags::Syn | TcpFlags::SynAck,
                _,
            ) if tcp_state != TcpState::SynReceived => Some(SendInfo::pure_ack(snd_nxt, rcv_nxt)),

            // ACK during SYN-RECEIVED with an unacceptable sequence number (regardless of whether
            // it carries data) -> per RFC 9293, Section 3.10.7.4, "First, check sequence number,"
            // reply with an ACK reflecting current state and drop the segment.
            //
            // Due to the current simplification of not using a reassembly buffer, any SEG.SEQ other
            // than exactly RCV.NXT is treated as unacceptable rather than held for later.
            (
                Some(&mut ConnState { tcp_state: TcpState::SynReceived, snd_nxt, rcv_nxt, .. }),
                TcpFlags::Ack,
                _,
            ) if self.seq_num != rcv_nxt => Some(SendInfo::pure_ack(snd_nxt, rcv_nxt)),

            // Handshake ACK (step 3) -> transition to ESTABLISHED. If it also carries data, echo
            // it, otherwise no reply is needed.
            //
            // As per RFC 9293, Section 3.10.7.4, "Fifth, check the ACK field," "SYN-RECEIVED
            // STATE," if SND.UNA < SEG.ACK <= SND.NXT, enter ESTABLISHED and set SND.WND, SND.WL1,
            // and SND.WL2 without the freshness check used for ESTABLISHED state ACKs.
            (
                Some(conn @ ConnState { tcp_state: TcpState::SynReceived, .. }),
                TcpFlags::Ack,
                maybe_payload,
            ) if self.seq_num == conn.rcv_nxt
                && conn.snd_una < self.ack_num
                && self.ack_num <= conn.snd_nxt =>
            {
                conn.tcp_state = TcpState::Established;
                conn.rcv_nxt = self.seq_num;
                conn.snd_una = self.ack_num;
                conn.window_state = Some(WindowState {
                    snd_wnd: self.window,
                    snd_wl1: self.seq_num,
                    snd_wl2: self.ack_num,
                });
                conn.pending.clear(); // Only the SYN-ACK just acknowledged could have been pending

                maybe_payload
                    .as_ref()
                    .map(|payload| {
                        conn.rcv_nxt += payload.len().into();
                        conn.send_buffer.extend(payload.as_bytes().iter());

                        conn.drain_transmittable()
                            .map(|maybe_to_send| match maybe_to_send {
                                Some(to_send) => Self::data_payload(conn, to_send),
                                None => SendInfo::pure_ack(conn.snd_nxt, conn.rcv_nxt),
                            })
                    })
                    .transpose()?
            }

            // ACK acknowledging data the server has not yet sent (ack_num is past snd_nxt) ->
            // per RFC 9293, Section 3.10.7.4, drop the segment and reply with an ACK reflecting
            // current state.
            (
                Some(&mut ConnState { tcp_state: TcpState::Established, snd_nxt, rcv_nxt, .. }),
                TcpFlags::Ack,
                _,
            ) if snd_nxt < self.ack_num => Some(SendInfo::pure_ack(snd_nxt, rcv_nxt)),

            // Pure ACK (no payload) on an established connection (acknowledgment of data sent by
            // the server) -> advance SND.UNA, then send however much the window allows from the
            // data queued to be sent, if any
            (
                Some(conn @ ConnState { tcp_state: TcpState::Established, .. }),
                TcpFlags::Ack,
                None,
            ) => {
                conn.incoming_ack_update(self)?;
                conn.drain_transmittable()?
                    .map(|to_send| Self::data_payload(conn, to_send))
            }

            // In-order data packet on an established connection -> ACK receipt of data, advancing
            // RCV.NXT, and echo as much of the queued data as SND.WND currently allows. Buffer
            // anything that doesn't fit to go out later as the window opens.
            (
                Some(conn @ ConnState { tcp_state: TcpState::Established, .. }),
                TcpFlags::Ack,
                Some(payload),
            ) if self.seq_num == conn.rcv_nxt => {
                conn.incoming_ack_update(self)?;
                conn.rcv_nxt += payload.len().into();
                conn.send_buffer.extend(payload.as_bytes().iter());

                Some(match conn.drain_transmittable()? {
                    Some(to_send) => Self::data_payload(conn, to_send),
                    None => SendInfo::pure_ack(conn.snd_nxt, conn.rcv_nxt),
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
                Some(SendInfo::pure_ack(conn.snd_nxt, conn.rcv_nxt))
            }

            // FIN-ACK (connection teardown) on an established connection, arriving in order ->
            // echo any trailing data (as much as the window allows, same as plain in-order data),
            // then start closing to wait for client's final ACK, replying with FIN-ACK. Unlike
            // FIN-WAIT-1/2, our own FIN hasn't gone out yet, so we can piggyback the data echo on
            // this same reply.
            (
                Some(conn @ ConnState { tcp_state: TcpState::Established, .. }),
                TcpFlags::FinAck,
                maybe_payload,
            ) if self.seq_num == conn.rcv_nxt => {
                conn.incoming_ack_update(self)?;

                if let Some(payload) = maybe_payload {
                    conn.rcv_nxt += payload.len().into();
                    conn.send_buffer.extend(payload.as_bytes().iter());
                }

                conn.rcv_nxt += FIN_BYTE; // Peer's FIN consumes one sequence number
                conn.tcp_state = TcpState::LastAck;

                let to_send = conn.drain_transmittable()?;
                let send_len = to_send
                    .as_ref()
                    .map_or_else(|| SeqDist::new(0), |payload| payload.len().into());

                let send_info = SendInfo {
                    seq_num: conn.snd_nxt,
                    ack_num: conn.rcv_nxt,
                    flags: TcpFlags::FinAck,
                    payload: to_send,
                };

                conn.snd_nxt += send_len;
                conn.snd_nxt += FIN_BYTE; // Our FIN consumes one sequence number

                conn.pending
                    .push(PendingSegment::new(send_info.clone(), Instant::now()));

                Some(send_info)
            }

            // Partial ACK in LAST-ACK, not yet covering our FIN -> update send-side state like a
            // plain ACK, keep waiting in LAST-ACK for the real final ACK
            (Some(conn @ ConnState { tcp_state: TcpState::LastAck, .. }), TcpFlags::Ack, None)
                if self.ack_num != conn.snd_nxt =>
            {
                conn.incoming_ack_update(self)?;
                None
            }

            // Final ACK completing passive close (LAST-ACK), fully acknowledging our FIN -> remove
            // connection, no reply
            (
                Some(&mut ConnState { tcp_state: TcpState::LastAck, snd_nxt, .. }),
                TcpFlags::Ack,
                None,
            ) if self.ack_num == snd_nxt => {
                connections.remove(&key);
                None
            }

            // In-order data arriving in FIN-WAIT-1/FIN-WAIT-2, i.e. after we've sent our own FIN
            // but before the peer's FIN has arrived (half closed) -> ACK it, don't echo because we
            // have no send side left, and advance rcv_nxt
            (
                Some(conn @ ConnState { tcp_state: TcpState::FinWait1 | TcpState::FinWait2, .. }),
                TcpFlags::Ack,
                Some(payload),
            ) if self.seq_num == conn.rcv_nxt => {
                conn.rcv_nxt += payload.len().into();

                let send_info = SendInfo::pure_ack(conn.snd_nxt, conn.rcv_nxt);
                conn.incoming_ack_update(self)?;

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
            //
            // Our own FIN has already been sent, so any trailing data can't be echoed (same as
            // plain data arriving in FIN-WAIT-1), but RCV.NXT must still advance past it.
            (
                Some(conn @ ConnState { tcp_state: TcpState::FinWait1, .. }),
                TcpFlags::FinAck,
                maybe_payload,
            ) if self.seq_num == conn.rcv_nxt => {
                if let Some(payload) = maybe_payload {
                    conn.rcv_nxt += payload.len().into();
                }

                // Consume one sequence number in RCV.NXT for the peer's FIN
                conn.rcv_nxt += FIN_BYTE;

                let send_info = SendInfo::pure_ack(conn.snd_nxt, conn.rcv_nxt);

                if self.ack_num == conn.snd_nxt {
                    connections.remove(&key);
                } else {
                    conn.incoming_ack_update(self)?;
                    conn.tcp_state = TcpState::Closing;
                }

                Some(send_info)
            }

            // FIN-WAIT-2, the remote peer's FIN arrives, in order -> ACK it and finish closing (no
            // TIME-WAIT). Our own FIN has already been sent, so any trailing data can't be echoed,
            // but the ACK must still reflect RCV.NXT advanced past it as well as the FIN.
            (
                Some(&mut ConnState { tcp_state: TcpState::FinWait2, snd_nxt, rcv_nxt, .. }),
                TcpFlags::FinAck,
                maybe_payload,
            ) if self.seq_num == rcv_nxt => {
                connections.remove(&key);

                let payload_len = maybe_payload
                    .as_ref()
                    .map_or_else(|| SeqDist::new(0), |payload| payload.len().into());

                Some(SendInfo::pure_ack(snd_nxt, rcv_nxt + payload_len + FIN_BYTE))
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
                    (rcv_nxt <= self.seq_num && self.seq_num < rcv_nxt + Self::RCV_WND.into())
                        .then_some(SendInfo::pure_ack(snd_nxt, rcv_nxt))
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
                ack_num: SeqPoint::new(0),
                flags: TcpFlags::Rst,
                payload: None,
            }),
        }
        .map(|send_info| {
            Self::from_pairs_and_info(self.ip_pair.swapped(), self.ports.swapped(), send_info)
        }))
    }

    /// Creates a `SendInfo` for the payload `to_send`, using and then updating the state of `conn`.
    fn data_payload(conn: &mut ConnState, to_send: TcpPayload) -> SendInfo {
        let send_len = to_send.len().into();

        let send_info = SendInfo {
            seq_num: conn.snd_nxt,
            ack_num: conn.rcv_nxt,
            flags: TcpFlags::Ack,
            payload: Some(to_send),
        };

        conn.snd_nxt += send_len;
        conn.pending
            .push(PendingSegment::new(send_info.clone(), Instant::now()));

        send_info
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

        // Copy payload into reply if echoing and determine segment length
        // TCP segment length = minimum TCP header length (20 bytes) + payload length (0+ bytes)
        let tcp_seg_len = u16::from(TCP_HDR_MIN_LEN).try_add(
            self.payload
                .as_ref()
                .map(|payload| -> Result<u16, String> {
                    let payload_len = payload.len().get();

                    buf.try_get_mut(
                        usize::from(TCP_HDR_MIN_LEN)
                            ..usize::from(TCP_HDR_MIN_LEN).try_add(usize::from(payload_len))?,
                    )?
                    .copy_from_slice(payload.as_bytes());

                    Ok(payload_len)
                })
                .transpose()?
                .unwrap_or_default(),
        )?;

        // Zero out checksum field before calculating checksum
        buf.try_get_mut(16..18)?.copy_from_slice(&[0x00, 0x00]);

        let tcp_checksum = pseudo_header_checksum(
            buf.try_get(..usize::from(tcp_seg_len))?,
            self.ip_pair,
            self.proto(),
        )?;

        buf.try_get_mut(16..18)?
            .copy_from_slice(&tcp_checksum.to_be_bytes());

        Ok(tcp_seg_len)
    }

    fn proto(&self) -> Protocol { Protocol::Tcp }

    fn get_ip_pair(&self) -> Ipv4AddrPair { self.ip_pair }

    fn pretty_payload(&self, include_content: bool) -> PrettyPayload<'_> {
        PrettyPayload {
            data: self
                .payload
                .as_ref()
                .map(TcpPayload::as_bytes)
                .unwrap_or_default(),
            include_content,
        }
    }
}

impl fmt::Display for TcpHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP | {} | seq={} ack={} win={} | {}",
            self.ports,
            self.seq_num.with_thousands_separators(),
            self.ack_num.with_thousands_separators(),
            self.window.with_thousands_separators(),
            self.flags
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

    impl TcpHandler {
        /// A SYN requesting a new connection using the regular `CLIENT_PACKET` consts, which should
        /// generate a SYN-ACK reply.
        pub(crate) const CLIENT_SYN: Self = Self { flags: TcpFlags::Syn, ..CLIENT_PACKET };

        /// The server's SYN-ACK reply for the standard SYN-RECEIVED connection using the module's
        /// standard test consts.
        pub(crate) const SERVER_SYN_ACK: Self = Self {
            seq_num: SERVER_ISN,
            ack_num: CLIENT_ISN.const_add(SYN_BYTE),
            flags: TcpFlags::SynAck,
            ..SERVER_REPLY
        };

        /// The handshake-completing ACK matching the module's standard test consts, which should be
        /// accepted if in SYN-RECEIVED by transitioning to ESTABLISHED and replying with `None`.
        pub(crate) const CLIENT_ACK_COMPLETING_HANDSHAKE: Self = Self {
            seq_num: CLIENT_ISN.const_add(SYN_BYTE),
            ack_num: SERVER_ISN.const_add(SYN_BYTE),
            ..CLIENT_PACKET
        };

        /// The server's FIN-ACK reply when actively initiating close right after the handshake for
        /// the standard connection using the module's test consts.
        pub(crate) const SERVER_FIN_ACK_INITIATING_CLOSE: Self = Self {
            seq_num: SERVER_ISN.const_add(SYN_BYTE),
            ack_num: CLIENT_ISN.const_add(SYN_BYTE),
            flags: TcpFlags::FinAck,
            ..SERVER_REPLY
        };

        /// The client's FIN-ACK completing active close after our own FIN was sent (FIN-WAIT-1),
        /// which also acknowledges our FIN, so the connection should close immediately.
        pub(crate) const CLIENT_FIN_ACK_COMPLETING_CLOSE: Self = Self {
            seq_num: CLIENT_ISN.const_add(SYN_BYTE),
            ack_num: SERVER_ISN.const_add(SYN_BYTE.const_add(FIN_BYTE)),
            flags: TcpFlags::FinAck,
            ..CLIENT_PACKET
        };

        /// The server's final ACK completing close from FIN-WAIT-1, matching the module's standard
        /// test consts for a connection closing right after the handshake, after its FIN
        /// was both acked and matched by the peer's own FIN in the same segment.
        pub(crate) const SERVER_FINAL_ACK_COMPLETING_CLOSE: Self = Self {
            seq_num: SERVER_ISN.const_add(SYN_BYTE.const_add(FIN_BYTE)),
            ack_num: CLIENT_ISN.const_add(SYN_BYTE.const_add(FIN_BYTE)),
            ..SERVER_REPLY
        };
    }
}
