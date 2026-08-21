use {
    crate::{
        Result,
        endpoint::{Local, Remote},
        protocol::tcp::{
            LOCAL_SYN_BYTE, SendInfo, SeqOffset, SeqPoint, TcpFlags, TcpHandler, TcpPayload,
            pending_segment::PendingSegment,
        },
    },
    std::{collections::VecDeque, time::Instant},
};

/// The state of a connection in the table, including its TCP state, buffered data, and other
/// locally stored information.
#[cfg_attr(test, derive(Debug, Clone))]
pub(super) struct ConnState {
    pub(super) tcp_state: TcpState,

    /// "SND.NXT = next sequence number to be sent" (RFC 9293, Section 3.4).
    pub(super) snd_nxt: SeqPoint<Local>,

    /// "RCV.NXT = next sequence number expected on an incoming segment" (RFC 9293, Section 3.4).
    pub(super) rcv_nxt: SeqPoint<Remote>,

    /// "SND.UNA = oldest unacknowledged sequence number" (RFC 9293, Section 3.4).
    pub(super) snd_una: SeqPoint<Local>,

    /// Unacked segments sent by the server, kept for retransmission purposes.
    pub(super) pending: Vec<PendingSegment>,

    /// Bytes received from the peer that are queued to be echoed once SND.WND has room for them.
    pub(super) send_buffer: VecDeque<u8>,
}

impl ConnState {
    /// Creates a new `Self` in the state right after receiving a SYN and sending a SYN-ACK.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `send_info.flags` is not SYN-ACK.
    pub(super) fn from_syn_ack(send_info: SendInfo) -> Result<Self, &'static str> {
        (send_info.flags == TcpFlags::SynAck)
            .then(|| Self {
                // State after the initial two-way exchange
                tcp_state: TcpState::SynReceived(SynReceived),
                // SYN-ACK consumes one sequence number
                snd_nxt: send_info.seq_num + LOCAL_SYN_BYTE,
                // Our SYN-ACK's `ack_num` is the client's ISN + 1
                rcv_nxt: send_info.ack_num,
                // Our SYN-ACK is unacknowledged (this is our ISN)
                snd_una: send_info.seq_num,
                pending: vec![PendingSegment::new(send_info, Instant::now())],
                send_buffer: VecDeque::new(),
            })
            .ok_or(
                "Attempted to create a new `ConnState` when sending something other than SYN-ACK",
            )
    }

    /// Removes and returns as many bytes as the peer's currently advertised window allows from the
    /// front of the send buffer, or returns `Ok(None)` if nothing can be sent right now because the
    /// buffer is empty or the window is full. Does not mutate any other state.
    pub(super) fn drain_transmittable(
        &mut self,
        established: &Established,
    ) -> Result<Option<TcpPayload>> {
        let sent_but_not_acked = self
            .snd_nxt
            .offset_past(self.snd_una)
            .ok_or("`drain_transmittable` called with SND.UNA not preceding or equaling SND.NXT")?;

        let space_in_window =
            SeqOffset::<u32, Local>::from(established.0.snd_wnd).saturating_sub(sent_but_not_acked);

        let bytes_to_send = usize::try_from(space_in_window)?.min(self.send_buffer.len());

        TcpPayload::try_from_iter(self.send_buffer.drain(..bytes_to_send)).map_err(Into::into)
    }

    #[cfg(test)]
    pub(super) const fn test_get_snd_wnd(&self) -> Option<SeqOffset<u16, Local>> {
        match self.tcp_state {
            TcpState::SynReceived(_) => None,
            TcpState::Established(established) => Some(established.0.snd_wnd),
            TcpState::FinWait1(fin_wait_1) => Some(fin_wait_1.0.snd_wnd),
            TcpState::FinWait2(fin_wait_2) => Some(fin_wait_2.0.snd_wnd),
            TcpState::Closing(closing) => Some(closing.0.snd_wnd),
            TcpState::LastAck(last_ack) => Some(last_ack.0.snd_wnd),
        }
    }
}

#[cfg(test)]
impl PartialEq for ConnState {
    fn eq(
        &self,
        &Self {
            // Include all fields except `pending` (timing dependent), explicitly destructured to
            // catch any fields added later
            tcp_state,
            snd_nxt,
            rcv_nxt,
            snd_una,
            pending: _,
            ref send_buffer,
        }: &Self,
    ) -> bool {
        self.tcp_state == tcp_state
            && self.snd_nxt == snd_nxt
            && self.rcv_nxt == rcv_nxt
            && self.snd_una == snd_una
            && &self.send_buffer == send_buffer
    }
}

/// The set of states of a TCP connection (non-exhaustive). Variant meanings below from RFC 9293,
/// Section 3.3.2.
#[derive(PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub(super) enum TcpState {
    /// "SYN-RECEIVED - represents waiting for a confirming connection request acknowledgment after
    /// having both received and sent a connection request."
    ///
    /// ISN field: "The Initial Sequence Number. The first sequence number used on a connection"
    /// (RFC 9293, Section 4).
    SynReceived(SynReceived),

    /// "ESTABLISHED - represents an open connection, data received can be delivered to the user.
    /// The normal state for the data transfer phase of the connection."
    Established(Established),

    /// "FIN-WAIT-1 - represents waiting for a connection termination request from the remote TCP
    /// peer, or an acknowledgment of the connection termination request previously sent."
    ///
    /// Entered when this server actively closes the connection.
    FinWait1(FinWait1),

    /// "FIN-WAIT-2 - represents waiting for a connection termination request from the remote TCP
    /// peer."
    ///
    /// Reached from `FinWait1` once our FIN has been acknowledged.
    FinWait2(FinWait2),

    /// "CLOSING - represents waiting for a connection termination request acknowledgment from the
    /// remote TCP peer."
    ///
    /// Reached via simultaneous close, when the remote peer's FIN arrives before our own FIN has
    /// been acknowledged.
    Closing(Closing),

    /// "LAST-ACK - represents waiting for an acknowledgment of the connection termination request
    /// previously sent to the remote TCP peer (this termination request sent to the remote TCP peer
    /// already included an acknowledgment of the termination request sent from the remote TCP
    /// peer)."
    ///
    /// Reached via passive close, after acknowledging the remote peer's FIN with our own.
    LastAck(LastAck),
}

macro_rules! fn_test_new {
    () => {
        #[cfg(test)]
        pub(super) const fn test_new(window_state: WindowState) -> Self { Self(window_state) }
    };
}

macro_rules! fn_incoming_ack_update {
    () => {
        /// Per RFC 9293, Section 3.10.7.4, "Fifth, check the ACK field," "ESTABLISHED STATE,"
        /// processes an incoming segment's acknowledgment against the send-side state, updating
        /// SND.WND, SND.WL1, SND.WL2, SND.UNA, and the retransmission queue as necessary.
        ///
        /// Ignores ACKs that are old (before SND.UNA) or for data not yet sent (past SND.NXT).
        /// For updates to SND.UNA and the retransmission queue, ignores duplicate ACKs
        /// (SND.UNA == SEG.ACK).
        #[must_use = "Returns updated state as a new instance"]
        pub(super) fn incoming_ack_update(
            self,
            conn: &mut ConnState,
            seg: &TcpHandler<Remote>,
        ) -> Self {
            // Exclude duplicate ACKs: SND.UNA < SEG.ACK <= SND.NXT
            if conn.snd_una.precedes(seg.ack_num) && seg.ack_num.precedes_or_eq(conn.snd_nxt) {
                conn.snd_una = seg.ack_num;

                // ACKs are cumulative, so only keep pending segments not fully covered by SEG.ACK
                conn.pending
                    .retain(|pending_seg| !pending_seg.is_covered_by(seg.ack_num));
            }

            // Include duplicate ACKs: SND.UNA <= SEG.ACK <= SND.NXT
            //     and
            // Guard against an old/reordered segment clobbering the window with stale data:
            //     SND.WL1 < SEG.SEQ or (SND.WL1 == SEG.SEQ and SND.WL2 <= SEG.ACK)
            if conn.snd_una.precedes_or_eq(seg.ack_num)
                && seg.ack_num.precedes_or_eq(conn.snd_nxt)
                && self.0.snd_wl1.precedes(seg.seq_num)
                || (self.0.snd_wl1 == seg.seq_num && self.0.snd_wl2.precedes_or_eq(seg.ack_num))
            {
                Self(WindowState {
                    snd_wnd: seg.window,
                    snd_wl1: seg.seq_num,
                    snd_wl2: seg.ack_num,
                })
            } else {
                self
            }
        }
    };
}

#[derive(PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub(super) struct SynReceived;

impl SynReceived {
    #[expect(clippy::unused_self, reason = "Require an instance for state transition")]
    pub(super) const fn establish(self, seg: &TcpHandler<Remote>) -> Established {
        Established(WindowState { snd_wnd: seg.window, snd_wl1: seg.seq_num, snd_wl2: seg.ack_num })
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub(super) struct Established(WindowState);

impl Established {
    pub(super) const fn close(self) -> FinWait1 { FinWait1(self.0) }

    pub(super) const fn skip_close_wait(self) -> LastAck { LastAck(self.0) }

    fn_incoming_ack_update!();
    fn_test_new!();
}

#[derive(PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub(super) struct FinWait1(WindowState);

impl FinWait1 {
    pub(super) const fn rcv_ack_of_fin(self) -> FinWait2 { FinWait2(self.0) }

    pub(super) const fn wait_for_simultaneous_close_ack(self) -> Closing { Closing(self.0) }

    fn_incoming_ack_update!();
    fn_test_new!();
}

#[derive(PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub(super) struct FinWait2(WindowState);

impl FinWait2 {
    fn_incoming_ack_update!();
    fn_test_new!();
}

#[derive(PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub(super) struct Closing(WindowState);

impl Closing {
    fn_test_new!();
}

#[derive(PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub(super) struct LastAck(WindowState);

impl LastAck {
    fn_incoming_ack_update!();
    fn_test_new!();
}

/// The SND.WND, SND.WL1, and SND.WL2 values of a connection.
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
#[expect(clippy::struct_field_names, reason = "Match RFC terminology")]
pub(super) struct WindowState {
    /// SND.WND or send window. "This represents the sequence numbers that the remote (receiving)
    /// TCP endpoint is willing to receive" (RFC 9293, Section 4).
    pub(super) snd_wnd: SeqOffset<u16, Local>,

    /// SND.WL1. "segment sequence number used for last window update" (RFC 9293, Section 3.3.1).
    ///
    /// Purely used for internal bookkeeping alongside `snd_wl2` to determine whether a window
    /// value is fresh or stale/reordered.
    pub(super) snd_wl1: SeqPoint<Remote>,

    /// SND.WL2. "segment acknowledgment number used for last window update" (RFC 9293, Section
    /// 3.3.1).
    ///
    /// Purely used for internal bookkeeping alongside `snd_wl1` to determine whether a window
    /// value is fresh or stale/reordered.
    pub(super) snd_wl2: SeqPoint<Local>,
}
