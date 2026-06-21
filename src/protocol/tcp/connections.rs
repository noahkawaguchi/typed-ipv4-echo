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

    /// "CLOSED - represents no connection state at all."
    #[default]
    Closed,
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

/// The state of a connection in the table, including its TCP state and other locally stored data.
struct ConnState {
    tcp_state: TcpState,

    /// "The Initial Sequence Number. The first sequence number used on a connection" (RFC 9293,
    /// Section 4).
    isn: u32,

    /// "SND.UNA = oldest unacknowledged sequence number" (RFC 9293, Section 3.4).
    snd_una: u32,

    /// "SND.NXT = next sequence number to be sent" (RFC 9293, Section 3.4).
    snd_nxt: u32,

    /// "RCV.NXT = next sequence number expected on an incoming segment" (RFC 9293, Section 3.4).
    rcv_nxt: u32,

    /// The single latest unacked segment sent by the server, if any, for retransmission purposes.
    pending: Option<PendingSegment>,
}

/// Tracks per-connection state keyed by the 4-tuple.
pub struct TcpConnections(HashMap<ConnKey, ConnState>);

impl TcpConnections {
    pub fn new() -> Self { Self(HashMap::new()) }

    pub fn len(&self) -> usize { self.0.len() }

    pub(super) fn tcp_state_of(&self, key: &ConnKey) -> TcpState {
        self.0.get(key).map(|s| s.tcp_state).unwrap_or_default()
    }

    pub(super) fn store_isn(&mut self, key: ConnKey, isn: u32) {
        self.0.insert(
            key,
            ConnState {
                tcp_state: TcpState::SynReceived,
                isn,
                snd_una: isn, // The SYN-ACK we're about to send is unacknowledged
                snd_nxt: isn.wrapping_add(1), // SYN-ACK consumes one sequence number
                rcv_nxt: 0,   // Set at connection establishment
                pending: None,
            },
        );
    }

    /// Returns the ISN only while the connection is still in SYN-RECEIVED state.
    pub(super) fn pending_isn(&self, key: &ConnKey) -> Option<u32> {
        self.0
            .get(key)
            .filter(|s| s.tcp_state == TcpState::SynReceived)
            .map(|s| s.isn)
    }

    pub(super) fn establish(&mut self, key: &ConnKey, rcv_nxt: u32) {
        if let Some(conn) = self.0.get_mut(key) {
            conn.tcp_state = TcpState::Established;
            conn.rcv_nxt = rcv_nxt;
        }
    }

    #[cfg(test)]
    pub(super) fn get_snd_una(&self, key: &ConnKey) -> Option<u32> {
        self.0.get(key).map(|s| s.snd_una)
    }

    /// Advances SND.UNA to `ack_num` if it is a "new" acknowledgment, i.e. `SND.UNA < ack_num <=
    /// SND.NXT` (RFC 9293, Section 3.10.7.4). Old/duplicate ACKs and ACKs for data not yet sent
    /// leave SND.UNA unchanged.
    pub(super) fn update_snd_una(&mut self, key: &ConnKey, ack_num: u32) {
        if let Some(conn) = self.0.get_mut(key)
            && Self::seq_lt(conn.snd_una, ack_num)
            && Self::seq_le(ack_num, conn.snd_nxt)
        {
            conn.snd_una = ack_num;

            // Remove `pending` if fully acknowledged
            if conn
                .pending
                .as_ref()
                .is_some_and(|p| Self::seq_le(p.end_seq, ack_num))
            {
                conn.pending = None;
            }
        }
    }

    /// Returns whether `ack_num` acknowledges data the server has not yet sent (`ack_num > SND.NXT`
    /// in sequence-number space).
    pub(super) fn ack_exceeds_snd_nxt(&self, key: &ConnKey, ack_num: u32) -> bool {
        self.0
            .get(key)
            .is_some_and(|s| Self::seq_lt(s.snd_nxt, ack_num))
    }

    pub(super) fn get_snd_rcv_nxt(&self, key: &ConnKey) -> Option<(u32, u32)> {
        self.0.get(key).map(|s| (s.snd_nxt, s.rcv_nxt))
    }

    pub(super) fn advance_snd_nxt(&mut self, key: &ConnKey, n: u32) {
        if let Some(conn) = self.0.get_mut(key) {
            conn.snd_nxt = conn.snd_nxt.wrapping_add(n);
        }
    }

    pub(super) fn advance_rcv_nxt(&mut self, key: &ConnKey, n: u32) {
        if let Some(conn) = self.0.get_mut(key) {
            conn.rcv_nxt = conn.rcv_nxt.wrapping_add(n);
        }
    }

    /// Records `seq_num..seq_num + consumed` as the latest unacked segment sent for retransmission,
    /// overwriting any previously pending segment.
    pub(super) fn record_pending(&mut self, key: &ConnKey, send_info: SendInfo, consumed: u32) {
        if let Some(conn) = self.0.get_mut(key) {
            let end_seq = send_info.seq_num.wrapping_add(consumed);

            conn.pending = Some(PendingSegment {
                send_info,
                end_seq,
                last_sent_at: Instant::now(),
                retries: 0,
            });
        }
    }

    /// Transitions from FIN-WAIT-1 to FIN-WAIT-2 once our FIN has been acknowledged.
    pub(super) fn start_fin_wait_2(&mut self, key: &ConnKey) {
        if let Some(conn) = self.0.get_mut(key) {
            conn.tcp_state = TcpState::FinWait2;
        }
    }

    /// Transitions from FIN-WAIT-1 to CLOSING (simultaneous close). The remote peer's FIN arrived
    /// before our own FIN was acknowledged. Consumes one sequence number in RCV.NXT for the peer's
    /// FIN.
    pub(super) fn start_simultaneous_closing(&mut self, key: &ConnKey) {
        if let Some(conn) = self.0.get_mut(key) {
            conn.tcp_state = TcpState::Closing;
            conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
        }
    }

    /// Transitions an ESTABLISHED connection to LAST-ACK (passive close). The remote peer's FIN has
    /// been acknowledged with our own FIN, awaiting their final ACK.
    pub(super) fn start_last_ack(&mut self, key: &ConnKey) {
        if let Some(conn) = self.0.get_mut(key) {
            conn.tcp_state = TcpState::LastAck;
        }
    }

    pub(super) fn remove(&mut self, key: &ConnKey) { self.0.remove(key); }

    /// Returns whether any connection is currently mid-close (FIN-WAIT-1, FIN-WAIT-2, CLOSING, or
    /// LAST-ACK), i.e. has sent or received a FIN but not yet completed teardown.
    pub fn closing_in_progress(&self) -> bool {
        self.0.values().any(|s| {
            matches!(
                s.tcp_state,
                TcpState::FinWait1 | TcpState::FinWait2 | TcpState::Closing | TcpState::LastAck
            )
        })
    }

    /// Returns the earliest `Instant` at which any connection's pending segment becomes due for
    /// retransmission (`rto` elapsed since it was last sent), or `None` if no connection has a
    /// pending segment.
    pub fn next_retransmit_deadline(&self, rto: Duration) -> Option<Instant> {
        self.0
            .values()
            .filter_map(|s| {
                s.pending
                    .as_ref()
                    .and_then(|p| p.last_sent_at.checked_add(rto))
            })
            .min()
    }

    /// Reproduces every connection's pending unacked segment that is due for retransmission (`rto`
    /// elapsed since it was last sent), or gives up and removes the connection once it has been
    /// retried `max_retries` times.
    pub fn make_retransmissions(
        &mut self,
        now: Instant,
        rto: Duration,
        max_retries: u8,
    ) -> Vec<(TcpHandler, Ipv4AddrPair)> {
        self.0
            .iter()
            .filter_map(|(&key, s)| {
                (now >= s.pending.as_ref()?.last_sent_at.checked_add(rto)?).then_some(key)
            })
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|key| {
                let pending = self.0.get_mut(&key)?.pending.as_mut()?;

                if pending.retries < max_retries {
                    pending.retries = pending.retries.saturating_add(1);
                    pending.last_sent_at = now;

                    Some((
                        TcpHandler::from_ports_and_info(
                            PortPair { src: key.server_port, dst: key.client_port },
                            pending.send_info.clone(),
                        ),
                        Ipv4AddrPair { src: key.server_ip, dst: key.client_ip },
                    ))
                } else {
                    self.0.remove(&key);
                    None
                }
            })
            .collect()
    }

    /// Initiates active close (RFC 9293 "CLOSE" call) for every connection currently ESTABLISHED,
    /// transitioning each to FIN-WAIT-1 and returning a FIN-ACK reply for it along with the
    /// `Ipv4AddrPair` for its IPv4 header.
    pub fn close_established(&mut self) -> Vec<(TcpHandler, Ipv4AddrPair)> {
        self.0
            .iter()
            .filter_map(|(&key, s)| (s.tcp_state == TcpState::Established).then_some(key))
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|key| {
                let (snd_nxt, rcv_nxt) = self.get_snd_rcv_nxt(&key)?;

                // Transition each ESTABLISHED connection to FIN-WAIT-1, initiating active close.
                // Consume one sequence number in SND.NXT for the FIN about to be sent.
                if let Some(conn) = self.0.get_mut(&key) {
                    conn.tcp_state = TcpState::FinWait1;
                    conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
                }

                let send_info = SendInfo {
                    seq_num: snd_nxt,
                    ack_num: rcv_nxt,
                    flags: TcpFlags::FinAck,
                    payload: Vec::new(),
                };

                self.record_pending(&key, send_info.clone(), 1);

                Some((
                    TcpHandler::from_ports_and_info(
                        PortPair { src: key.server_port, dst: key.client_port },
                        send_info,
                    ),
                    Ipv4AddrPair { src: key.server_ip, dst: key.client_ip },
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
