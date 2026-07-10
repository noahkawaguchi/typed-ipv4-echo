use {
    crate::protocol::tcp::SendInfo,
    std::time::{Duration, Instant},
};

/// The state of a connection in the table, including its TCP state and other locally stored data.
/// Definitions below from RFC 9293, sections annotated inline.
#[cfg_attr(test, derive(Debug, Clone))]
pub(super) struct ConnState {
    pub(super) tcp_state: TcpState,

    /// "SND.NXT = next sequence number to be sent" (3.4).
    pub(super) snd_nxt: u32,

    /// "RCV.NXT = next sequence number expected on an incoming segment" (3.4).
    pub(super) rcv_nxt: u32,

    /// "SND.UNA = oldest unacknowledged sequence number" (3.4).
    pub(super) snd_una: u32,

    /// SND.WND or send window. "This represents the sequence numbers that the remote (receiving)
    /// TCP endpoint is willing to receive" (4).
    pub(super) snd_wnd: u16,

    /// SND.WL1. "segment sequence number used for last window update" (3.3.1).
    ///
    /// Purely used for internal bookkeeping alongside `snd_wl2` to determine whether a window
    /// value is fresh or stale/reordered.
    pub(super) snd_wl1: u32,

    /// SND.WL2. "segment acknowledgment number used for last window update" (3.3.1).
    ///
    /// Purely used for internal bookkeeping alongside `snd_wl1` to determine whether a window
    /// value is fresh or stale/reordered.
    pub(super) snd_wl2: u32,

    /// Unacked segments sent by the server, kept for retransmission purposes.
    pub(super) pending: Vec<PendingSegment>,
}

#[cfg(test)]
impl PartialEq for ConnState {
    fn eq(&self, other: &Self) -> bool {
        // Include all fields except `pending` (timing dependent) and `snd_wl1`/`snd_wl2` (internal
        // freshness bookkeeping for `snd_wnd`)
        self.tcp_state == other.tcp_state
            && self.snd_nxt == other.snd_nxt
            && self.rcv_nxt == other.rcv_nxt
            && self.snd_una == other.snd_una
            && self.snd_wnd == other.snd_wnd
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

    /// Returns whether `self` has been sitting unacknowledged long enough to be due for
    /// retransmission as of `now` (i.e. `rto` elapsed since it was last sent).
    pub(super) fn is_due(&self, rto: Duration, now: Instant) -> bool {
        self.last_sent_at
            .checked_add(rto)
            .is_some_and(|deadline| deadline <= now)
    }
}
