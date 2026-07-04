use {
    crate::{
        addr_pairs::{Ipv4AddrPair, PortPair},
        protocol::tcp::{SendInfo, TcpFlags, TcpHandler},
    },
    std::{
        collections::HashMap,
        net::Ipv4Addr,
        time::{Duration, Instant},
    },
};

/// Key identifying a TCP connection.
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub(super) struct ConnKey {
    pub(super) client_ip: Ipv4Addr,
    pub(super) client_port: u16,
    pub(super) server_ip: Ipv4Addr,
    pub(super) server_port: u16,
}

/// The set of states of a TCP connection (non-exhaustive). Variant meanings below from RFC 9293,
/// Section 3.3.2.
#[derive(PartialEq, Eq, Clone, Copy, Default)]
#[cfg_attr(test, derive(Debug))]
pub(super) enum TcpState {
    /// "SYN-RECEIVED - represents waiting for a confirming connection request acknowledgment after
    /// having both received and sent a connection request."
    ///
    /// ISN field: "The Initial Sequence Number. The first sequence number used on a connection"
    /// (RFC 9293, Section 4).
    SynReceived(u32),

    /// Synchronized states carry `snd_nxt` and `rcv_nxt` with the following meanings:
    /// - "SND.NXT = next sequence number to be sent" (RFC 9293, Section 3.4).
    /// - "RCV.NXT = next sequence number expected on an incoming segment" (RFC 9293, Section 3.4).
    Synced(SyncState, u32, u32),

    /// "CLOSED - represents no connection state at all."
    #[default]
    Closed,
}

/// The set of synchronized states of a TCP connection (non-exhaustive). Variant meanings below from
/// RFC 9293, Section 3.3.2.
#[derive(PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub(super) enum SyncState {
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
struct PendingSegment {
    /// The values and data the segment was sent with, frozen at send time.
    send_info: SendInfo,

    /// The sequence number one past the last byte/flag consumed by the segment (`seq_num +
    /// consumed`, e.g. `seq_num + 1` for a SYN/FIN, `seq_num + payload.len()` for data). Compared
    /// against an incoming `ack_num` to tell whether the segment has been fully acknowledged.
    end_seq: u32,

    /// The last time at which the segment was sent.
    last_sent_at: Instant,

    /// The number of times the segment has been retransmitted.
    retries: u8,
}

impl PendingSegment {
    /// Creates a new `Self` with `seq_num + consumed` as `end_seq`.
    fn new(send_info: SendInfo, consumed: u32) -> Self {
        let end_seq = send_info.seq_num.wrapping_add(consumed);
        Self { send_info, end_seq, last_sent_at: Instant::now(), retries: 0 }
    }

    /// Returns whether `self` has been sitting unacknowledged long enough to be due for
    /// retransmission as of `now` (i.e. `rto` elapsed since it was last sent).
    fn is_due(&self, rto: Duration, now: Instant) -> bool {
        self.last_sent_at
            .checked_add(rto)
            .is_some_and(|deadline| deadline <= now)
    }
}

/// The state of a connection in the table, including its TCP state and other locally stored data.
struct ConnState {
    tcp_state: TcpState,

    /// "SND.UNA = oldest unacknowledged sequence number" (RFC 9293, Section 3.4).
    snd_una: u32,

    /// Unacked segments sent by the server, kept for retransmission purposes.
    pending: Vec<PendingSegment>,
}

/// Tracks per-connection state keyed by the 4-tuple.
#[cfg_attr(test, derive(Default))]
pub struct TcpConnections {
    table: HashMap<ConnKey, ConnState>,
    rto: Duration,
    max_retries: u8,
}

impl TcpConnections {
    pub fn new(rto: Duration, max_retries: u8) -> Self {
        Self { table: HashMap::new(), rto, max_retries }
    }

    pub fn len(&self) -> usize { self.table.len() }

    pub(super) fn tcp_state_of(&self, key: &ConnKey) -> TcpState {
        self.table
            .get(key)
            .map(|conn| conn.tcp_state)
            .unwrap_or_default()
    }

    pub(super) fn store_isn(&mut self, key: ConnKey, isn: u32) {
        self.table.insert(
            key,
            ConnState {
                // State after initial two-way exchange
                tcp_state: TcpState::SynReceived(isn),
                // The SYN-ACK we're sending is unacknowledged
                snd_una: isn,
                pending: Vec::new(),
            },
        );
    }

    pub(super) fn establish(&mut self, key: &ConnKey, rcv_nxt: u32) {
        if let Some(conn) = self.table.get_mut(key)
            && let TcpState::SynReceived(isn) = conn.tcp_state
        {
            // SYN-ACK consumed one sequence number
            conn.tcp_state = TcpState::Synced(SyncState::Established, isn.wrapping_add(1), rcv_nxt);
        }
    }

    #[cfg(test)]
    pub(super) fn get_snd_una(&self, key: &ConnKey) -> Option<u32> {
        self.table.get(key).map(|conn| conn.snd_una)
    }

    /// Advances SND.UNA to `ack_num` if it is a "new" acknowledgment, i.e. `SND.UNA < ack_num <=
    /// SND.NXT` (RFC 9293, Section 3.10.7.4). Old/duplicate ACKs and ACKs for data not yet sent
    /// leave SND.UNA unchanged.
    pub(super) fn update_snd_una(&mut self, key: &ConnKey, ack_num: u32) {
        if let Some(conn) = self.table.get_mut(key)
            && let TcpState::Synced(_, snd_nxt, _) = conn.tcp_state
            && Self::seq_lt(conn.snd_una, ack_num)
            && Self::seq_le(ack_num, snd_nxt)
        {
            conn.snd_una = ack_num;

            // ACKs are cumulative, so only keep pending segments not fully covered by `ack_num`
            conn.pending.retain(|p| Self::seq_lt(ack_num, p.end_seq));
        }
    }

    /// Returns whether `seq_num` falls within the receive window [RCV.NXT, RCV.NXT + RCV.WND).
    /// Uses the advertised window size of `u16::MAX` since that is what outgoing segments carry.
    pub(super) fn seq_in_recv_window(&self, key: &ConnKey, seq_num: u32) -> bool {
        matches!(
            self.table.get(key).map(|conn| conn.tcp_state),
            Some(TcpState::Synced(_, _, rcv_nxt))
                if Self::seq_le(rcv_nxt, seq_num)
                    && Self::seq_lt(seq_num, rcv_nxt.wrapping_add(u32::from(u16::MAX)))
        )
    }

    /// Returns whether `ack_num` acknowledges data the server has not yet sent (`ack_num > SND.NXT`
    /// in sequence-number space).
    pub(super) fn ack_exceeds_snd_nxt(&self, key: &ConnKey, ack_num: u32) -> bool {
        matches!(
            self.table.get(key).map(|conn| conn.tcp_state),
            Some(TcpState::Synced(_, snd_nxt, _)) if Self::seq_lt(snd_nxt, ack_num)
        )
    }

    pub(super) fn advance_snd_nxt(&mut self, key: &ConnKey, n: u32) {
        if let Some(conn) = self.table.get_mut(key)
            && let TcpState::Synced(_, snd_nxt, _) = &mut conn.tcp_state
        {
            *snd_nxt = snd_nxt.wrapping_add(n);
        }
    }

    pub(super) fn advance_rcv_nxt(&mut self, key: &ConnKey, n: u32) {
        if let Some(conn) = self.table.get_mut(key)
            && let TcpState::Synced(_, _, rcv_nxt) = &mut conn.tcp_state
        {
            *rcv_nxt = rcv_nxt.wrapping_add(n);
        }
    }

    /// Records `seq_num..seq_num + consumed` as an unacked segment eligible for retransmission.
    pub(super) fn record_pending(&mut self, key: &ConnKey, send_info: SendInfo, consumed: u32) {
        if let Some(conn) = self.table.get_mut(key) {
            conn.pending.push(PendingSegment::new(send_info, consumed));
        }
    }

    /// Transitions from FIN-WAIT-1 to FIN-WAIT-2 once our FIN has been acknowledged.
    pub(super) fn start_fin_wait_2(&mut self, key: &ConnKey) {
        if let Some(conn) = self.table.get_mut(key)
            && let TcpState::Synced(sync_state @ SyncState::FinWait1, _, _) = &mut conn.tcp_state
        {
            *sync_state = SyncState::FinWait2;
        }
    }

    /// Transitions from FIN-WAIT-1 to CLOSING (simultaneous close). The remote peer's FIN arrived
    /// before our own FIN was acknowledged. Consumes one sequence number in RCV.NXT for the peer's
    /// FIN.
    pub(super) fn start_simultaneous_closing(&mut self, key: &ConnKey) {
        if let Some(conn) = self.table.get_mut(key)
            && let TcpState::Synced(sync_state @ SyncState::FinWait1, _, rcv_nxt) =
                &mut conn.tcp_state
        {
            *sync_state = SyncState::Closing;
            *rcv_nxt = rcv_nxt.wrapping_add(1);
        }
    }

    /// Transitions an ESTABLISHED connection to LAST-ACK (passive close). The remote peer's FIN has
    /// been acknowledged with our own FIN, awaiting their final ACK.
    pub(super) fn start_last_ack(&mut self, key: &ConnKey) {
        if let Some(conn) = self.table.get_mut(key)
            && let TcpState::Synced(sync_state @ SyncState::Established, _, _) = &mut conn.tcp_state
        {
            *sync_state = SyncState::LastAck;
        }
    }

    pub(super) fn remove(&mut self, key: &ConnKey) { self.table.remove(key); }

    /// Returns whether any connection is currently mid-close (FIN-WAIT-1, FIN-WAIT-2, CLOSING, or
    /// LAST-ACK), i.e. has sent or received a FIN but not yet completed teardown.
    pub fn closing_in_progress(&self) -> bool {
        self.table.values().any(|conn| {
            matches!(
                conn.tcp_state,
                TcpState::Synced(
                    SyncState::FinWait1
                        | SyncState::FinWait2
                        | SyncState::Closing
                        | SyncState::LastAck,
                    _,
                    _,
                )
            )
        })
    }

    /// Returns the earliest `Instant` at which a pending segment for any connection becomes due for
    /// retransmission, or `None` if no connection has any pending segments.
    pub fn next_retransmit_deadline(&self) -> Option<Instant> {
        self.table
            .values()
            .flat_map(|conn| &conn.pending)
            .filter_map(|seg| seg.last_sent_at.checked_add(self.rto))
            .min()
    }

    /// Reproduces every pending unacked segment that is due for retransmission. If any connection
    /// has a due segment that has already been retried `max_retries` times, gives up and removes
    /// that connection entirely.
    pub fn make_retransmissions(&mut self) -> Vec<TcpHandler> {
        let now = Instant::now();

        let due_keys = self
            .table
            .iter()
            .filter_map(|(&key, conn)| {
                conn.pending
                    .iter()
                    .any(|seg| seg.is_due(self.rto, now))
                    .then_some(key)
            })
            .collect::<Vec<_>>();

        let mut retransmissions = Vec::new();

        for key in due_keys {
            let Some(conn) = self.table.get_mut(&key) else { continue };

            if conn
                .pending
                .iter()
                .any(|seg| seg.is_due(self.rto, now) && seg.retries >= self.max_retries)
            {
                self.table.remove(&key);
                continue;
            }

            retransmissions.extend(conn.pending.iter_mut().filter_map(|segment| {
                segment.is_due(self.rto, now).then(|| {
                    segment.retries = segment.retries.saturating_add(1);
                    segment.last_sent_at = now;

                    TcpHandler::from_pairs_and_info(
                        Ipv4AddrPair { src: key.server_ip, dst: key.client_ip },
                        PortPair { src: key.server_port, dst: key.client_port },
                        segment.send_info.clone(),
                    )
                })
            }));
        }

        retransmissions
    }

    /// Initiates active close (RFC 9293 "CLOSE" call) for every connection currently ESTABLISHED,
    /// transitioning each to FIN-WAIT-1 and returning a FIN-ACK reply for it.
    pub fn close_established(&mut self) -> Vec<TcpHandler> {
        self.table
            .iter_mut()
            .filter_map(|(key, conn)| {
                let TcpState::Synced(SyncState::Established, snd_nxt, rcv_nxt) = conn.tcp_state
                else {
                    return None;
                };

                // Consume one sequence number in SND.NXT for the FIN about to be sent
                conn.tcp_state =
                    TcpState::Synced(SyncState::FinWait1, snd_nxt.wrapping_add(1), rcv_nxt);

                let send_info = SendInfo {
                    seq_num: snd_nxt,
                    ack_num: rcv_nxt,
                    flags: TcpFlags::FinAck,
                    payload: None,
                };

                conn.pending.push(PendingSegment::new(send_info.clone(), 1));

                Some(TcpHandler::from_pairs_and_info(
                    Ipv4AddrPair { src: key.server_ip, dst: key.client_ip },
                    PortPair { src: key.server_port, dst: key.client_port },
                    send_info,
                ))
            })
            .collect()
    }

    /// Returns whether `a` precedes `b` in TCP sequence-number space, accounting for 32-bit
    /// wraparound (RFC 9293, Section 3.4).
    const fn seq_lt(a: u32, b: u32) -> bool { a.wrapping_sub(b) > u32::MAX / 2 }

    /// Returns whether `a` precedes or equals `b` in TCP sequence-number space, accounting for
    /// 32-bit wraparound (RFC 9293, Section 3.4).
    const fn seq_le(a: u32, b: u32) -> bool { a == b || Self::seq_lt(a, b) }
}
