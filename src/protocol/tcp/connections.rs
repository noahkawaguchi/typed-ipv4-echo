use {
    crate::{
        addr_pairs::{Ipv4AddrPair, PortPair},
        protocol::tcp::{AdvanceBy as _, SendInfo, TcpFlags, TcpHandler},
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
    /// Creates a new unacked segment eligible for retransmission, covering
    /// `send_info.seq_num..send_info.seq_num + consumed`.
    pub(super) fn new(send_info: SendInfo, consumed: u32) -> Self {
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

    /// Returns whether `self` is fully covered by `ack_num`.
    pub(super) const fn is_covered_by(&self, ack_num: u32) -> bool {
        seq_space::le(self.end_seq, ack_num)
    }
}

/// The state of a connection in the table, including its TCP state and other locally stored data.
/// Definitions below from RFC 9293, Section 3.4.
#[cfg_attr(test, derive(Debug, Clone))]
pub(super) struct ConnState {
    pub(super) tcp_state: TcpState,

    /// "SND.NXT = next sequence number to be sent"
    pub(super) snd_nxt: u32,

    /// "RCV.NXT = next sequence number expected on an incoming segment"
    pub(super) rcv_nxt: u32,

    /// "SND.UNA = oldest unacknowledged sequence number"
    pub(super) snd_una: u32,

    /// Unacked segments sent by the server, kept for retransmission purposes.
    pub(super) pending: Vec<PendingSegment>,
}

#[cfg(test)]
impl PartialEq for ConnState {
    fn eq(&self, other: &Self) -> bool {
        // All fields except `pending`
        self.tcp_state == other.tcp_state
            && self.snd_nxt == other.snd_nxt
            && self.rcv_nxt == other.rcv_nxt
            && self.snd_una == other.snd_una
    }
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

    pub(super) fn get_mut(&mut self, key: &ConnKey) -> Option<&mut ConnState> {
        self.table.get_mut(key)
    }

    pub(super) fn store_isn(&mut self, key: ConnKey, send_info: SendInfo) {
        self.table.insert(
            key,
            ConnState {
                // State after initial two-way exchange
                tcp_state: TcpState::SynReceived,
                // SYN-ACK consumes one sequence number
                snd_nxt: send_info.seq_num.wrapping_add(1),
                // Set at connection establishment
                rcv_nxt: 0,
                // The SYN-ACK we're sending is unacknowledged (this is the ISN)
                snd_una: send_info.seq_num,
                pending: vec![PendingSegment::new(send_info, 1)],
            },
        );
    }

    pub(super) fn remove(&mut self, key: &ConnKey) { self.table.remove(key); }

    /// Returns whether any connection is currently mid-close (FIN-WAIT-1, FIN-WAIT-2, CLOSING, or
    /// LAST-ACK), i.e. has sent or received a FIN but not yet completed teardown.
    pub fn closing_in_progress(&self) -> bool {
        self.table.values().any(|conn| {
            matches!(
                conn.tcp_state,
                TcpState::FinWait1 | TcpState::FinWait2 | TcpState::Closing | TcpState::LastAck,
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
                if conn.tcp_state != TcpState::Established {
                    return None;
                }

                let send_info = SendInfo {
                    seq_num: conn.snd_nxt,
                    ack_num: conn.rcv_nxt,
                    flags: TcpFlags::FinAck,
                    payload: None,
                };

                conn.tcp_state = TcpState::FinWait1;

                // Consume one sequence number in SND.NXT for the FIN about to be sent
                conn.snd_nxt.advance_by(1);

                conn.pending.push(PendingSegment::new(send_info.clone(), 1));

                Some(TcpHandler::from_pairs_and_info(
                    Ipv4AddrPair { src: key.server_ip, dst: key.client_ip },
                    PortPair { src: key.server_port, dst: key.client_port },
                    send_info,
                ))
            })
            .collect()
    }

    /// Attempts to retrieve the connection in the table under `KEY`, returning `Err` if not
    /// present.
    #[cfg(test)]
    pub(super) fn try_get(&self) -> Result<&ConnState, String> {
        use crate::protocol::tcp::tests::KEY;

        self.table
            .get(&KEY)
            .ok_or_else(|| String::from("Connection not found"))
    }

    /// Inserts `conn` into the connection table using `KEY`.
    #[cfg(test)]
    pub(super) fn insert(&mut self, conn: ConnState) {
        use crate::protocol::tcp::tests::KEY;

        self.table.insert(KEY, conn);
    }

    /// Inserts a SYN-RECEIVED connection into the table using `KEY`, `CLIENT_ISN`, AND
    /// `SERVER_ISN`.
    #[cfg(test)]
    pub(super) fn insert_syn_recv(&mut self) {
        use crate::protocol::tcp::tests::{CLIENT_ISN, KEY, SERVER_ISN, SYN_BYTE};

        self.store_isn(
            KEY,
            SendInfo {
                seq_num: SERVER_ISN,
                ack_num: CLIENT_ISN + SYN_BYTE,
                flags: TcpFlags::SynAck,
                payload: None,
            },
        );
    }

    /// Inserts an ESTABLISHED connection into the table using `KEY`, `CLIENT_ISN`, AND
    /// `SERVER_ISN`.
    #[cfg(test)]
    pub(super) fn insert_established(&mut self) {
        use crate::protocol::tcp::tests::{CLIENT_ISN, KEY, SERVER_ISN, SYN_BYTE};

        self.table.insert(
            KEY,
            ConnState {
                tcp_state: TcpState::Established,
                snd_nxt: SERVER_ISN + SYN_BYTE,
                rcv_nxt: CLIENT_ISN + SYN_BYTE,
                snd_una: SERVER_ISN + SYN_BYTE,
                pending: Vec::new(),
            },
        );
    }
}

pub(super) mod seq_space {
    /// Returns whether `a` precedes `b` in TCP sequence-number space, accounting for 32-bit
    /// wraparound (RFC 9293, Section 3.4).
    pub const fn lt(a: u32, b: u32) -> bool { a.wrapping_sub(b) > u32::MAX / 2 }

    /// Returns whether `a` precedes or equals `b` in TCP sequence-number space, accounting for
    /// 32-bit wraparound (RFC 9293, Section 3.4).
    pub const fn le(a: u32, b: u32) -> bool { a == b || lt(a, b) }
}
