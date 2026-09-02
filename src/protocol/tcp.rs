pub use connections::{RtoConfig, TcpConnections};

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
        endpoint::{Endpoint, Local, Remote},
        protocol::{
            Protocol,
            display::{PrettyPayload, WithThousandsSeparators as _},
            pseudo_hdr_cksum,
            router::{Encode, PrettyProtocol},
            tcp::{
                connections::ConnKey,
                flags::TcpFlags,
                payload::{LenOrDefault as _, TcpPayload},
                pending_segment::PendingSegment,
                seq_space::{SeqOffset, SeqPoint},
                state::{
                    Closing, ConnState, Established, FinWait1, FinWait2, LastAck, SynReceived,
                    SyncedState, TcpState,
                },
            },
        },
        sys,
        try_ops::{TryAdd as _, TryGet as _, TryGetMut as _},
    },
    std::{fmt, time::Instant},
};

/// The minimum number of bytes in a TCP header (no options).
const TCP_HDR_MIN_LEN: u8 = 20;

/// The single phantom byte consumed by SYN in the stream going in the local to remote direction.
const LOCAL_SYN_BYTE: SeqOffset<u32, Local> = SeqOffset::new(1);

/// The single phantom byte consumed by FIN in the stream going in the local to remote direction.
const LOCAL_FIN_BYTE: SeqOffset<u32, Local> = SeqOffset::new(1);

/// The single phantom byte consumed by SYN in the stream going in the remote to local direction.
const REMOTE_SYN_BYTE: SeqOffset<u32, Remote> = SeqOffset::new(1);

/// The single phantom byte consumed by FIN in the stream going in the remote to local direction.
const REMOTE_FIN_BYTE: SeqOffset<u32, Remote> = SeqOffset::new(1);

/// Fields that differ when determining a segment to send.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
struct SendInfo {
    seq_num: SeqPoint<Local>,
    ack_num: SeqPoint<Remote>,
    flags: TcpFlags,
    payload: Option<TcpPayload>,
}

impl SendInfo {
    const fn pure_ack(seq_num: SeqPoint<Local>, ack_num: SeqPoint<Remote>) -> Self {
        Self { seq_num, ack_num, flags: TcpFlags::Ack, payload: None }
    }

    const fn rst(seq_num: SeqPoint<Local>) -> Self {
        Self {
            seq_num,
            // ack_num is 0 because sending bare RST with no ACK flag leaves ack_num undefined
            ack_num: SeqPoint::new(0),
            flags: TcpFlags::Rst,
            payload: None,
        }
    }
}

/// Manages TCP headers, data, and reply logic. Field definitions below from RFC 9293, Section 3.1.
/// Endpoint `S` is the sender (values based on the sender's ISN), while endpoint `S::Peer` is the
/// receiver (values based on the receiver's ISN).
#[cfg_attr(test, derive(Debug, PartialEq, Eq, Clone))]
pub struct TcpSegment<S: Endpoint> {
    /// Not a part of the TCP header, but required for connection state and checksum calculation.
    ip_pair: Ipv4AddrPair<S>,

    ports: PortPair<S>,

    /// "The sequence number of the first data octet in this segment (except when the SYN flag is
    /// set). If SYN is set, the sequence number is the initial sequence number (ISN) and the first
    /// data octet is ISN+1."
    seq_num: SeqPoint<S>,

    /// "If the ACK control bit is set, this field contains the value of the next sequence number
    /// the sender of the segment is expecting to receive. Once a connection is established, this
    /// is always sent."
    ack_num: SeqPoint<S::Peer>,

    /// **This field is stored in units of bytes.**
    ///
    /// "The number of 32-bit words in the TCP header. This indicates where the data begins. The
    /// TCP header (even one including options) is an integer multiple of 32 bits long."
    offset_bytes: u8,

    flags: TcpFlags,

    /// "The number of data octets beginning with the one indicated in the acknowledgment field
    /// that the sender of this segment is willing to accept."
    window: SeqOffset<u16, S::Peer>,

    payload: Option<TcpPayload>,
}

impl TcpSegment<Remote> {
    /// Parses `data` as a TCP header and payload in the remote to local direction.
    pub(super) fn parse(data: &[u8], ip_pair: Ipv4AddrPair<Remote>) -> Result<Self> {
        Self::inner_parse(data, ip_pair)
    }

    /// Creates a TCP header and payload for replying to `self`, or returns `Ok(None)` for no reply.
    pub(super) fn create_reply(
        &self,
        connections: &mut TcpConnections,
    ) -> Result<Option<TcpSegment<Local>>> {
        let key = ConnKey {
            client_ip: self.ip_pair.src,
            client_port: self.ports.src,
            server_ip: self.ip_pair.dst,
            server_port: self.ports.dst,
        };

        Ok(match connections.get_mut(&key) {
            None => self.handle_unknown_conn(connections, key)?,

            Some(conn) => match self.flags {
                // RST on a known connection -> RFC 9293, Section 3.10.7.4 has three cases for when
                // the RST bit is set, protecting against a blind reset attack (as described in RFC
                // 5961, Section 3):
                //   Case 1: SEG.SEQ outside window           -> silently drop segment
                //   Case 2: SEG.SEQ == RCV.NXT               -> reset connection, no reply
                //   Case 3: SEG.SEQ in window but != RCV.NXT -> don't reset, send challenge ACK
                TcpFlags::Rst | TcpFlags::RstAck => {
                    if self.seq_num == conn.rcv_nxt {
                        // Case 2
                        connections.remove(&key);
                        None
                    } else if conn.rcv_nxt.precedes_or_eq(self.seq_num)
                        && self
                            .seq_num
                            .precedes(conn.rcv_nxt + TcpSegment::<Local>::RCV_WND.into())
                    {
                        Some(SendInfo::pure_ack(conn.snd_nxt, conn.rcv_nxt)) // Case 3
                    } else {
                        None // Case 1
                    }
                }

                // Stray SYN or SYN-ACK on a synchronized connection -> send a challenge ACK, do not
                // reset the connection (RFC 9293, Section 3.10.7.4).
                //
                // Out-of-window SYN is caught at the general "First, check sequence number," while
                // in-window SYN is caught at "Fourth, check the SYN bit," but both have the same
                // result. The ACK field and ACK bit are checked fifth, so SYN and SYN-ACK are
                // treated the same here.
                TcpFlags::Syn | TcpFlags::SynAck
                    if !matches!(conn.tcp_state, TcpState::SynReceived(_)) =>
                {
                    Some(SendInfo::pure_ack(conn.snd_nxt, conn.rcv_nxt))
                }

                _ => match conn.tcp_state {
                    TcpState::SynReceived(syn_received) => {
                        self.handle_syn_rcv(conn, syn_received)?
                    }

                    TcpState::Established(established) => {
                        self.handle_established(conn, established)?
                    }

                    TcpState::FinWait1(fin_wait_1) => {
                        let (maybe_send_info, remove_conn) =
                            self.handle_fin_wait_1(conn, fin_wait_1);
                        if remove_conn {
                            connections.remove(&key);
                        }
                        maybe_send_info
                    }

                    TcpState::FinWait2(fin_wait_2) => {
                        let (send_info, remove_conn) = self.handle_fin_wait_2(conn, fin_wait_2);
                        if remove_conn {
                            connections.remove(&key);
                        }
                        Some(send_info)
                    }

                    TcpState::Closing(closing) => {
                        let (maybe_send_info, remove_conn) = self.handle_closing(conn, closing);
                        if remove_conn {
                            connections.remove(&key);
                        }
                        maybe_send_info
                    }

                    TcpState::LastAck(last_ack) => {
                        let (maybe_send_info, remove_conn) = self.handle_last_ack(conn, last_ack);
                        if remove_conn {
                            connections.remove(&key);
                        }
                        maybe_send_info
                    }
                },
            },
        }
        .map(|send_info| {
            TcpSegment::<Local>::from_pairs_and_info(
                self.ip_pair.swapped(),
                self.ports.swapped(),
                send_info,
            )
        }))
    }

    fn handle_unknown_conn(
        &self,
        connections: &mut TcpConnections,
        key: ConnKey,
    ) -> Result<Option<SendInfo>> {
        Ok(match self.flags {
            // SYN packet (step 1 of handshake) -> reply with SYN-ACK (step 2)
            TcpFlags::Syn => {
                let send_info = SendInfo {
                    seq_num: SeqPoint::new(sys::random_u32()?),
                    ack_num: self.seq_num + REMOTE_SYN_BYTE,
                    flags: TcpFlags::SynAck,
                    payload: None,
                };

                connections.insert_syn_rcv(key, ConnState::from_syn_ack(send_info.clone())?)?;

                Some(send_info)
            }

            // RST from an unknown connection -> silently drop segment (never RST a RST)
            TcpFlags::Rst | TcpFlags::RstAck => None,

            _ => Some(SendInfo::rst(self.ack_num)),
        })
    }

    fn handle_syn_rcv(
        &self,
        conn: &mut ConnState,
        syn_received: SynReceived,
    ) -> Result<Option<SendInfo>> {
        Ok(match (self.flags, &self.payload) {
            // Duplicate SYN while awaiting the handshake ACK (client's retransmission timer resent
            // the SYN) -> resend the same SYN-ACK (which was likely lost) using the already-stored
            // ISN
            (TcpFlags::Syn, _) => {
                let send_info = SendInfo {
                    seq_num: conn.snd_una, // ISN
                    ack_num: self.seq_num + REMOTE_SYN_BYTE,
                    flags: TcpFlags::SynAck,
                    payload: None,
                };

                conn.pending
                    .push(PendingSegment::new(send_info.clone(), Instant::now()));

                Some(send_info)
            }

            // ACK or FIN-ACK during SYN-RECEIVED with an unacceptable sequence number (regardless
            // of whether it carries data) -> per RFC 9293, Section 3.10.7.4, "First, check sequence
            // number," reply with an ACK reflecting current state and drop the segment.
            //
            // Due to the current simplification of not using a reassembly buffer, any SEG.SEQ other
            // than exactly RCV.NXT gets a current state ACK and is not held for later.
            (TcpFlags::Ack | TcpFlags::FinAck, _) if self.seq_num != conn.rcv_nxt => {
                Some(SendInfo::pure_ack(conn.snd_nxt, conn.rcv_nxt))
            }

            // Acceptable handshake-completing ACK (step 3) -> transition to ESTABLISHED. If it also
            // carries data, echo it, otherwise no reply is needed.
            (TcpFlags::Ack, maybe_payload)
                if self.seq_num == conn.rcv_nxt
                    && conn.snd_una.precedes(self.ack_num)
                    && self.ack_num.precedes_or_eq(conn.snd_nxt) =>
            {
                let established = self.complete_handshake(conn, syn_received);

                maybe_payload
                    .as_ref()
                    .map(|payload| {
                        conn.rcv_nxt += payload.len().into();
                        conn.send_buffer.extend(payload.as_bytes());

                        established.drain_transmittable(conn).map(|maybe_to_send| {
                            match maybe_to_send {
                                Some(to_send) => Self::data_payload(conn, to_send),
                                None => SendInfo::pure_ack(conn.snd_nxt, conn.rcv_nxt),
                            }
                        })
                    })
                    .transpose()?
            }

            // Handshake-completing FIN-ACK (step 3 combined with the peer's own close) -> as per
            // RFC 9293, Section 3.10.7.4, complete the handshake, transitioning to ESTABLISHED
            // ("Fifth, check the ACK field"), then immediately start closing ("Eighth, check the
            // FIN bit"), skipping CLOSE-WAIT under the current simplification, the same as a
            // FIN-ACK arriving on an ESTABLISHED connection. Also echo as much trailing data as
            // possible, if any.
            (TcpFlags::FinAck, maybe_payload)
                if self.seq_num == conn.rcv_nxt
                    && conn.snd_una.precedes(self.ack_num)
                    && self.ack_num.precedes_or_eq(conn.snd_nxt) =>
            {
                let established = self.complete_handshake(conn, syn_received);

                Some(self.begin_passive_close_without_close_wait(
                    conn,
                    maybe_payload.as_ref(),
                    established,
                )?)
            }

            _ => Some(SendInfo::rst(self.ack_num)),
        })
    }

    /// Completes the initial three-way handshake, updating `conn` and returning a copy of the inner
    /// struct that was placed inside `conn.tcp_state`.
    fn complete_handshake(
        &self,
        conn: &mut ConnState,
        syn_received: SynReceived,
    ) -> SyncedState<Established> {
        let established = syn_received.establish(self);

        conn.tcp_state = TcpState::Established(established);
        conn.rcv_nxt = self.seq_num;
        conn.snd_una = self.ack_num;
        conn.pending.clear(); // Only the SYN-ACK just acknowledged could have been pending

        established
    }

    fn handle_established(
        &self,
        conn: &mut ConnState,
        established: SyncedState<Established>,
    ) -> Result<Option<SendInfo>> {
        Ok(match (self.flags, &self.payload) {
            // ACK acknowledging data the server has not yet sent (ack_num is past snd_nxt) ->
            // per RFC 9293, Section 3.10.7.4, drop the segment and reply with an ACK reflecting
            // current state.
            (TcpFlags::Ack, _) if conn.snd_nxt.precedes(self.ack_num) => {
                Some(SendInfo::pure_ack(conn.snd_nxt, conn.rcv_nxt))
            }

            // Pure ACK (no payload) on an established connection (acknowledgment of data sent by
            // the server) -> advance SND.UNA, then send however much the window allows from the
            // data queued to be sent, if any
            (TcpFlags::Ack, None) => {
                let new_established = established.incoming_ack_update(conn, self);
                conn.tcp_state = TcpState::Established(new_established);
                new_established
                    .drain_transmittable(conn)?
                    .map(|to_send| Self::data_payload(conn, to_send))
            }

            // In-order data packet on an established connection -> ACK receipt of data, advancing
            // RCV.NXT, and echo as much of the queued data as SND.WND currently allows. Buffer
            // anything that doesn't fit to go out later as the window opens.
            (TcpFlags::Ack, Some(payload)) if self.seq_num == conn.rcv_nxt => {
                let new_established = established.incoming_ack_update(conn, self);

                conn.tcp_state = TcpState::Established(new_established);
                conn.rcv_nxt += payload.len().into();
                conn.send_buffer.extend(payload.as_bytes());

                Some(match new_established.drain_transmittable(conn)? {
                    Some(to_send) => Self::data_payload(conn, to_send),
                    None => SendInfo::pure_ack(conn.snd_nxt, conn.rcv_nxt),
                })
            }

            // Out-of-order/duplicate data or out-of-order FIN-ACK on an established connection
            // -> duplicate ACK. ACK rcv_nxt so the client knows what the server expects next, but
            // don't echo data, start closing, or advance snd_nxt/rcv_nxt.
            (TcpFlags::Ack | TcpFlags::FinAck, _) if self.seq_num != conn.rcv_nxt => {
                conn.tcp_state = TcpState::Established(established.incoming_ack_update(conn, self));
                Some(SendInfo::pure_ack(conn.snd_nxt, conn.rcv_nxt))
            }

            // FIN-ACK (connection teardown) on an established connection, arriving in order ->
            // echo any trailing data (as much as the window allows, same as plain in-order data),
            // then start closing to wait for client's final ACK, replying with FIN-ACK. Unlike
            // FIN-WAIT-1/2, our own FIN hasn't gone out yet, so we can piggyback the data echo on
            // this same reply.
            (TcpFlags::FinAck, maybe_payload) if self.seq_num == conn.rcv_nxt => {
                Some(self.begin_passive_close_without_close_wait(
                    conn,
                    maybe_payload.as_ref(),
                    established,
                )?)
            }

            _ => Some(SendInfo::rst(self.ack_num)),
        })
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

    /// Transitions from ESTABLISHED straight to LAST-ACK, skipping over CLOSE-WAIT (TODO: implement
    /// CLOSE-WAIT), updating `conn` accordingly and returning a FIN-ACK `SendInfo` with as much
    /// data as the window allows if there is anything to send.
    fn begin_passive_close_without_close_wait(
        &self,
        conn: &mut ConnState,
        maybe_payload: Option<&TcpPayload>,
        old_established: SyncedState<Established>,
    ) -> Result<SendInfo> {
        if let Some(payload) = maybe_payload {
            conn.rcv_nxt += payload.len().into();
            conn.send_buffer.extend(payload.as_bytes());
        }

        conn.rcv_nxt += REMOTE_FIN_BYTE; // Peer's FIN consumes one sequence number

        let new_established = old_established.incoming_ack_update(conn, self);
        let to_send = new_established.drain_transmittable(conn)?;
        let send_len = to_send.len_or_default();

        conn.tcp_state = TcpState::LastAck(new_established.skip_close_wait());

        let send_info = SendInfo {
            seq_num: conn.snd_nxt,
            ack_num: conn.rcv_nxt,
            flags: TcpFlags::FinAck,
            payload: to_send,
        };

        conn.snd_nxt += send_len;
        conn.snd_nxt += LOCAL_FIN_BYTE; // Our FIN consumes one sequence number

        conn.pending
            .push(PendingSegment::new(send_info.clone(), Instant::now()));

        Ok(send_info)
    }

    fn handle_fin_wait_1(
        &self,
        conn: &mut ConnState,
        fin_wait_1: SyncedState<FinWait1>,
    ) -> (Option<SendInfo>, bool) {
        match (self.flags, &self.payload) {
            // In-order data arriving in FIN-WAIT-1, i.e. after we've sent our own FIN but before
            // the peer's FIN has arrived (half closed) -> ACK it, don't echo because we have no
            // send side left, and advance rcv_nxt
            (TcpFlags::Ack, Some(payload)) if self.seq_num == conn.rcv_nxt => {
                conn.rcv_nxt += payload.len().into();
                let send_info = SendInfo::pure_ack(conn.snd_nxt, conn.rcv_nxt);
                conn.tcp_state = TcpState::FinWait1(fin_wait_1.incoming_ack_update(conn, self));
                (Some(send_info), false)
            }

            // FIN-WAIT-1, our FIN has been acknowledged (and nothing else) -> FIN-WAIT-2, no reply
            (TcpFlags::Ack, None) if self.ack_num == conn.snd_nxt => {
                conn.tcp_state =
                    TcpState::FinWait2(fin_wait_1.incoming_ack_update(conn, self).rcv_ack_of_fin());
                (None, false)
            }

            // FIN-WAIT-1, the remote peer's FIN arrives before ours is acknowledged (simultaneous
            // close), and it also acknowledges our FIN -> ACK it, and the connection is fully
            // closed (skipping FIN-WAIT-2/TIME-WAIT).
            //
            // Our own FIN has already been sent, so any trailing data can't be echoed (same as
            // plain data arriving in FIN-WAIT-1), but RCV.NXT must still advance past it.
            (TcpFlags::FinAck, maybe_payload)
                if self.seq_num == conn.rcv_nxt && self.ack_num == conn.snd_nxt =>
            {
                conn.rcv_nxt += maybe_payload.len_or_default();
                // Consume one sequence number in RCV.NXT for the peer's FIN
                conn.rcv_nxt += REMOTE_FIN_BYTE;
                (Some(SendInfo::pure_ack(conn.snd_nxt, conn.rcv_nxt)), true)
            }

            // FIN-WAIT-1, the remote peer's FIN arrives before ours is acknowledged (simultaneous
            // close), but it doesn't acknowledge our FIN -> ACK it and move to CLOSING to await the
            // ACK of our FIN.
            //
            // Our own FIN has already been sent, so any trailing data can't be echoed (same as
            // plain data arriving in FIN-WAIT-1), but RCV.NXT must still advance past it.
            (TcpFlags::FinAck, maybe_payload)
                if self.seq_num == conn.rcv_nxt && self.ack_num != conn.snd_nxt =>
            {
                conn.rcv_nxt += maybe_payload.len_or_default();

                // Consume one sequence number in RCV.NXT for the peer's FIN
                conn.rcv_nxt += REMOTE_FIN_BYTE;

                let send_info = SendInfo::pure_ack(conn.snd_nxt, conn.rcv_nxt);

                conn.tcp_state = TcpState::Closing(
                    fin_wait_1
                        .incoming_ack_update(conn, self)
                        .rcv_fin_before_fin_is_acked(),
                );

                (Some(send_info), false)
            }

            _ => (Some(SendInfo::rst(self.ack_num)), false),
        }
    }

    fn handle_fin_wait_2(
        &self,
        conn: &mut ConnState,
        fin_wait_2: SyncedState<FinWait2>,
    ) -> (SendInfo, bool) {
        match (self.flags, &self.payload) {
            // In-order data arriving in FIN-WAIT-2, i.e. after we've sent our own FIN but before
            // the peer's FIN has arrived (half closed) -> ACK it, don't echo because we have no
            // send side left, and advance rcv_nxt
            (TcpFlags::Ack, Some(payload)) if self.seq_num == conn.rcv_nxt => {
                conn.rcv_nxt += payload.len().into();
                let send_info = SendInfo::pure_ack(conn.snd_nxt, conn.rcv_nxt);
                conn.tcp_state = TcpState::FinWait2(fin_wait_2.incoming_ack_update(conn, self));
                (send_info, false)
            }

            // FIN-WAIT-2, the remote peer's FIN arrives, in order -> ACK it and finish closing (no
            // TIME-WAIT). Our own FIN has already been sent, so any trailing data can't be echoed,
            // but the ACK must still reflect RCV.NXT advanced past it as well as the FIN.
            (TcpFlags::FinAck, maybe_payload) if self.seq_num == conn.rcv_nxt => (
                SendInfo::pure_ack(
                    conn.snd_nxt,
                    conn.rcv_nxt + maybe_payload.len_or_default() + REMOTE_FIN_BYTE,
                ),
                true,
            ),

            _ => (SendInfo::rst(self.ack_num), false),
        }
    }

    fn handle_closing(
        &self,
        conn: &ConnState,
        _closing: SyncedState<Closing>,
    ) -> (Option<SendInfo>, bool) {
        match (self.flags, &self.payload) {
            // CLOSING (simultaneous close), the remote peer's ACK of our FIN arrives -> fully
            // closed, no reply
            (TcpFlags::Ack, None) if self.ack_num == conn.snd_nxt => (None, true),

            _ => (Some(SendInfo::rst(self.ack_num)), false),
        }
    }

    fn handle_last_ack(
        &self,
        conn: &mut ConnState,
        last_ack: SyncedState<LastAck>,
    ) -> (Option<SendInfo>, bool) {
        match (self.flags, &self.payload) {
            // Partial ACK in LAST-ACK, not yet covering our FIN -> update send-side state like a
            // plain ACK, keep waiting in LAST-ACK for the real final ACK
            (TcpFlags::Ack, None) if self.ack_num != conn.snd_nxt => {
                conn.tcp_state = TcpState::LastAck(last_ack.incoming_ack_update(conn, self));
                (None, false)
            }

            // Final ACK completing passive close (LAST-ACK), fully acknowledging our FIN -> remove
            // connection, no reply
            (TcpFlags::Ack, None) if self.ack_num == conn.snd_nxt => (None, true),

            _ => (Some(SendInfo::rst(self.ack_num)), false),
        }
    }
}

impl TcpSegment<Local> {
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
    const RCV_WND: SeqOffset<u16, Remote> = SeqOffset::new(u16::MAX);

    fn from_pairs_and_info(
        ip_pair: Ipv4AddrPair<Local>,
        ports: PortPair<Local>,
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
}

impl Encode<Local> for TcpSegment<Local> {
    fn write_into(&self, buf: &mut [u8]) -> Result<u16> { self.inner_write_into(buf) }
    fn proto(&self) -> Protocol { Protocol::Tcp }
    fn get_ip_pair(&self) -> Ipv4AddrPair<Local> { self.ip_pair }
}

impl<S: Endpoint> TcpSegment<S> {
    /// Parses `data` as a TCP header and payload, which could be local to remote or remote to
    /// local. The local to remote direction is for tests only. Only the remote to local direction
    /// should be exposed in production code.
    fn inner_parse(data: &[u8], ip_pair: Ipv4AddrPair<S>) -> Result<Self> {
        let tcp_hdr = data
            .first_chunk::<{ TCP_HDR_MIN_LEN as usize }>()
            .ok_or_else(|| format!("Too short for TCP header ({} bytes)", data.len()))?;

        if pseudo_hdr_cksum(data, ip_pair, Protocol::Tcp)? != 0 {
            return Err("Invalid TCP checksum".into());
        }

        // Convert length in 32-bit words in the upper 4 bits to length in bytes in the full 8 bits
        let offset_bytes = tcp_hdr[12] >> 4 << 2;

        Ok(Self {
            ip_pair,
            ports: PortPair::new(
                u16::from_be_bytes([tcp_hdr[0], tcp_hdr[1]]),
                u16::from_be_bytes([tcp_hdr[2], tcp_hdr[3]]),
            ),
            seq_num: SeqPoint::new(u32::from_be_bytes([
                tcp_hdr[4], tcp_hdr[5], tcp_hdr[6], tcp_hdr[7],
            ])),
            ack_num: SeqPoint::new(u32::from_be_bytes([
                tcp_hdr[8],
                tcp_hdr[9],
                tcp_hdr[10],
                tcp_hdr[11],
            ])),
            offset_bytes,
            flags: tcp_hdr[13].try_into()?,
            window: SeqOffset::new(u16::from_be_bytes([tcp_hdr[14], tcp_hdr[15]])),
            payload: TcpPayload::try_from_iter(
                data.get(offset_bytes.into()..)
                    .into_iter()
                    .flatten()
                    .copied(),
            )?,
        })
    }

    /// Copies data from `self` to write the protocol-specific header and payload into `buf`, which
    /// could be local to remote or remote to local, returning the number of bytes written.
    ///
    /// The remote to local direction is for tests only. Only the local to remote direction
    /// should be exposed in production code.
    fn inner_write_into(&self, buf: &mut [u8]) -> Result<u16> {
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

        let tcp_cksum = pseudo_hdr_cksum(
            buf.try_get(..usize::from(tcp_seg_len))?,
            self.ip_pair,
            Protocol::Tcp,
        )?;

        buf.try_get_mut(16..18)?
            .copy_from_slice(&tcp_cksum.to_be_bytes());

        Ok(tcp_seg_len)
    }
}

impl<S: Endpoint> PrettyProtocol for TcpSegment<S> {
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

impl<S: Endpoint> fmt::Display for TcpSegment<S> {
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
    mod consts;
    mod echo;
    mod establish;
    mod flow_control;
    mod parse;
    mod retransmit;
    mod stray_syn;
    mod terminate;
    mod window;
    mod write;

    pub(super) use consts::*;
    use {
        super::*,
        crate::{
            ETHERNET_MTU,
            protocol::{
                tcp::state::{SynReceived, SyncedState, WindowState},
                test_consts::{LOCAL_TO_REMOTE_IP_PAIR, REMOTE_TO_LOCAL_IP_PAIR},
            },
        },
        std::{assert_matches, collections::VecDeque, thread, time::Duration},
    };

    impl TcpSegment<Remote> {
        /// A SYN requesting a new connection using the regular `CLIENT_PACKET` consts, which should
        /// generate a SYN-ACK reply.
        pub(crate) const CLIENT_SYN: Self = Self { flags: TcpFlags::Syn, ..CLIENT_PKT };

        /// The handshake-completing ACK matching the module's standard test consts, which should be
        /// accepted if in SYN-RECEIVED by transitioning to ESTABLISHED and replying with `None`.
        pub(crate) const CLIENT_ACK_COMPLETING_HANDSHAKE: Self = Self {
            seq_num: CLIENT_ISN.const_add(REMOTE_SYN_BYTE),
            ack_num: SERVER_ISN.const_add(LOCAL_SYN_BYTE),
            ..CLIENT_PKT
        };

        /// The client's FIN-ACK completing active close after our own FIN was sent (FIN-WAIT-1),
        /// which also acknowledges our FIN, so the connection should close immediately.
        pub(crate) const CLIENT_FIN_ACK_COMPLETING_CLOSE: Self = Self {
            seq_num: CLIENT_ISN.const_add(REMOTE_SYN_BYTE),
            ack_num: SERVER_ISN.const_add(LOCAL_SYN_BYTE.const_add(LOCAL_FIN_BYTE)),
            flags: TcpFlags::FinAck,
            ..CLIENT_PKT
        };
    }

    impl Encode<Remote> for TcpSegment<Remote> {
        fn write_into(&self, buf: &mut [u8]) -> Result<u16> { self.inner_write_into(buf) }
        fn proto(&self) -> Protocol { Protocol::Tcp }
        fn get_ip_pair(&self) -> Ipv4AddrPair<Remote> { self.ip_pair }
    }

    impl TcpSegment<Local> {
        /// The server's SYN-ACK reply for the standard SYN-RECEIVED connection using the module's
        /// standard test consts.
        pub(crate) const SERVER_SYN_ACK: Self = Self {
            seq_num: SERVER_ISN,
            ack_num: CLIENT_ISN.const_add(REMOTE_SYN_BYTE),
            flags: TcpFlags::SynAck,
            ..SERVER_REPLY
        };

        /// The server's FIN-ACK reply when actively initiating close right after the handshake for
        /// the standard connection using the module's test consts.
        pub(crate) const SERVER_FIN_ACK_INITIATING_CLOSE: Self = Self {
            seq_num: SERVER_ISN.const_add(LOCAL_SYN_BYTE),
            ack_num: CLIENT_ISN.const_add(REMOTE_SYN_BYTE),
            flags: TcpFlags::FinAck,
            ..SERVER_REPLY
        };

        /// The server's final ACK completing close from FIN-WAIT-1, matching the module's standard
        /// test consts for a connection closing right after the handshake, after its FIN
        /// was both acked and matched by the peer's own FIN in the same segment.
        pub(crate) const SERVER_FINAL_ACK_COMPLETING_CLOSE: Self = Self {
            seq_num: SERVER_ISN.const_add(LOCAL_SYN_BYTE.const_add(LOCAL_FIN_BYTE)),
            ack_num: CLIENT_ISN.const_add(REMOTE_SYN_BYTE.const_add(REMOTE_FIN_BYTE)),
            ..SERVER_REPLY
        };

        /// Parses `data` as a TCP header and payload in the local to remote direction for testing
        /// purposes only.
        ///
        /// This is a test-only version because a segment created locally would never be parsed from
        /// bytes in production.
        pub(crate) fn test_parse_local(data: &[u8], ip_pair: Ipv4AddrPair<Local>) -> Result<Self> {
            Self::inner_parse(data, ip_pair)
        }
    }
}
