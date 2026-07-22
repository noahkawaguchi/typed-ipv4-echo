use {
    crate::{
        Result,
        protocol::tcp::{
            SendInfo, TcpFlags, TcpHandler, TcpPayload,
            seq_space::{SeqLe as _, SeqLt as _},
        },
    },
    std::{
        collections::VecDeque,
        time::{Duration, Instant},
    },
};

/// The state of a connection in the table, including its TCP state, buffered data, and other
/// locally stored information.
#[cfg_attr(test, derive(Debug, Clone))]
pub(super) struct ConnState {
    pub(super) tcp_state: TcpState,

    /// "SND.NXT = next sequence number to be sent" (RFC 9293, Section 3.4).
    pub(super) snd_nxt: u32,

    /// "RCV.NXT = next sequence number expected on an incoming segment" (RFC 9293, Section 3.4).
    pub(super) rcv_nxt: u32,

    /// "SND.UNA = oldest unacknowledged sequence number" (RFC 9293, Section 3.4).
    pub(super) snd_una: u32,

    /// SND.WND, SND.WL1, and SND.WL2. Should be `None` until establishment, then always `Some`.
    pub(super) window_state: Option<WindowState>,

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
                tcp_state: TcpState::SynReceived,
                // SYN-ACK consumes one sequence number
                snd_nxt: send_info.seq_num.wrapping_add(1),
                // Our SYN-ACK's `ack_num` is the client's ISN + 1
                rcv_nxt: send_info.ack_num,
                // Our SYN-ACK is unacknowledged (this is our ISN)
                snd_una: send_info.seq_num,
                // Window-related values are set at connection establishment once the peer has
                // provided a defined SEG.ACK
                window_state: None,
                pending: vec![PendingSegment::new(send_info, 1)],
                send_buffer: VecDeque::new(),
            })
            .ok_or(
                "Attempted to create a new `ConnState` when sending something other than SYN-ACK",
            )
    }

    /// Per RFC 9293, Section 3.10.7.4, "Fifth, check the ACK field," "ESTABLISHED STATE," processes
    /// an incoming segment's acknowledgment against the send-side state, updating SND.WND, SND.WL1,
    /// SND.WL2, SND.UNA, and the retransmission queue as necessary.
    ///
    /// Ignores ACKs that are old (before SND.UNA) or for data not yet sent (past SND.NXT). For
    /// updates to SND.UNA and the retransmission queue, ignores duplicate ACKs
    /// (SND.UNA == SEG.ACK).
    pub(super) fn incoming_ack_update(&mut self, seg: &TcpHandler) -> Result<(), &'static str> {
        let Some(window_state) = &self.window_state else {
            return Err("`incoming_ack_update` called with uninitialized window state");
        };

        if self.snd_una.seq_le(seg.ack_num) && seg.ack_num.seq_le(self.snd_nxt) {
            // Include duplicate ACKs: SND.UNA <= SEG.ACK <= SND.NXT
            //     and
            // Guard against an old/reordered segment clobbering the window with stale data:
            //     SND.WL1 < SEG.SEQ or (SND.WL1 == SEG.SEQ and SND.WL2 <= SEG.ACK)
            if window_state.snd_wl1.seq_lt(seg.seq_num)
                || (window_state.snd_wl1 == seg.seq_num && window_state.snd_wl2.seq_le(seg.ack_num))
            {
                self.window_state = Some(WindowState {
                    snd_wnd: seg.window,
                    snd_wl1: seg.seq_num,
                    snd_wl2: seg.ack_num,
                });
            }

            // Exclude duplicate ACKs: SND.UNA < SEG.ACK <= SND.NXT
            if self.snd_una.seq_lt(seg.ack_num) {
                self.snd_una = seg.ack_num;

                // ACKs are cumulative, so only keep pending segments not fully covered by SEG.ACK
                self.pending
                    .retain(|pending_seg| seg.ack_num.seq_lt(pending_seg.end_seq));
            }
        }

        Ok(())
    }

    /// Removes and returns as many bytes as the peer's currently advertised window allows from the
    /// front of the send buffer, or returns `Ok(None)` if nothing can be sent right now because the
    /// buffer is empty or the window is full. Does not mutate any other state.
    pub(super) fn drain_transmittable(&mut self) -> Result<Option<TcpPayload>> {
        let Some(window_state) = &self.window_state else {
            return Err("`drain_transmittable` called with uninitialized window state".into());
        };

        let sent_but_not_acked = self.snd_nxt.wrapping_sub(self.snd_una);
        let space_in_window = u32::from(window_state.snd_wnd).saturating_sub(sent_but_not_acked);
        let bytes_to_send = usize::try_from(space_in_window)?.min(self.send_buffer.len());

        TcpPayload::try_from_iter(self.send_buffer.drain(..bytes_to_send)).map_err(Into::into)
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
            ref window_state,
            pending: _,
            ref send_buffer,
        }: &Self,
    ) -> bool {
        self.tcp_state == tcp_state
            && self.snd_nxt == snd_nxt
            && self.rcv_nxt == rcv_nxt
            && self.snd_una == snd_una
            && &self.window_state == window_state
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
    SynReceived,

    /// "ESTABLISHED - represents an open connection, data received can be delivered to the user.
    /// The normal state for the data transfer phase of the connection."
    Established,

    /// "FIN-WAIT-1 - represents waiting for a connection termination request from the remote TCP
    /// peer, or an acknowledgment of the connection termination request previously sent."
    ///
    /// Entered when this server actively closes the connection.
    FinWait1,

    /// "FIN-WAIT-2 - represents waiting for a connection termination request from the remote TCP
    /// peer."
    ///
    /// Reached from `FinWait1` once our FIN has been acknowledged.
    FinWait2,

    /// "CLOSING - represents waiting for a connection termination request acknowledgment from the
    /// remote TCP peer."
    ///
    /// Reached via simultaneous close, when the remote peer's FIN arrives before our own FIN has
    /// been acknowledged.
    Closing,

    /// "LAST-ACK - represents waiting for an acknowledgment of the connection termination request
    /// previously sent to the remote TCP peer (this termination request sent to the remote TCP peer
    /// already included an acknowledgment of the termination request sent from the remote TCP
    /// peer)."
    ///
    /// Reached via passive close, after acknowledging the remote peer's FIN with our own.
    LastAck,
}

/// The SND.WND, SND.WL1, and SND.WL2 values of a connection.
#[cfg_attr(test, derive(Debug, Copy, Clone, PartialEq, Eq))]
#[expect(clippy::struct_field_names, reason = "Match RFC terminology")]
pub(super) struct WindowState {
    /// SND.WND or send window. "This represents the sequence numbers that the remote (receiving)
    /// TCP endpoint is willing to receive" (RFC 9293, Section 4).
    pub(super) snd_wnd: u16,

    /// SND.WL1. "segment sequence number used for last window update" (RFC 9293, Section 3.3.1).
    ///
    /// Purely used for internal bookkeeping alongside `snd_wl2` to determine whether a window
    /// value is fresh or stale/reordered.
    pub(super) snd_wl1: u32,

    /// SND.WL2. "segment acknowledgment number used for last window update" (RFC 9293, Section
    /// 3.3.1).
    ///
    /// Purely used for internal bookkeeping alongside `snd_wl1` to determine whether a window
    /// value is fresh or stale/reordered.
    pub(super) snd_wl2: u32,
}

/// A sent segment that consumed sequence numbers and hasn't yet been acknowledged.
#[cfg_attr(test, derive(Debug, Clone))]
pub(super) struct PendingSegment {
    /// The values and data the segment was sent with, frozen at send time.
    pub(super) send_info: SendInfo,

    /// The sequence number one past the last byte/flag consumed by the segment (`seq_num +
    /// consumed`, e.g. `seq_num + 1` for a SYN/FIN, `seq_num + payload.len()` for data). Compared
    /// against an incoming `ack_num` to tell whether the segment has been fully acknowledged.
    pub(super) end_seq: u32,

    /// The last time at which the segment was sent.
    pub(super) last_sent_at: Instant,

    /// The number of times the segment has been retransmitted.
    pub(super) retries: u8,
}

impl PendingSegment {
    /// Creates a new unacked segment eligible for retransmission, covering
    /// `send_info.seq_num..send_info.seq_num + consumed`.
    pub(super) fn new(send_info: SendInfo, consumed: u32) -> Self {
        let end_seq = send_info.seq_num.wrapping_add(consumed);
        Self { send_info, end_seq, last_sent_at: Instant::now(), retries: 0 }
    }

    /// Returns the time at which the segment is due for retransmission using exponential backoff,
    /// or `Instant::now()` if `Instant` overflowed.
    pub(super) fn time_due(&self, initial_rto: Duration) -> Instant {
        // Make the RTO saturate at `Duration::MAX`, or "about 584,942,417,355 years" (std library
        // docs), leaving plenty of room for any real RTO.
        let rto = initial_rto.saturating_mul(2u32.saturating_pow(self.retries.into()));

        // In practice, adding `Duration::MAX` should overflow any `Instant`, but this is not
        // guaranteed since `Instant` is opaque. Therefore, check for overflow separately.
        //
        // Return due now on overflow so that a pending segment cannot get stuck never being due.
        self.last_sent_at
            .checked_add(rto)
            .unwrap_or_else(Instant::now)
    }

    /// Returns whether `self` has been sitting unacknowledged long enough to be due for
    /// retransmission as of `now`, i.e. `initial_rto * 2^retries` elapsed since it was last sent.
    pub(super) fn is_due(&self, initial_rto: Duration, now: Instant) -> bool {
        self.time_due(initial_rto) <= now
    }
}
