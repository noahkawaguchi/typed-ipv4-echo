use std::{collections::HashMap, net::Ipv4Addr};

/// Key identifying a TCP connection.
#[derive(PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(Clone, Copy))]
pub(super) struct ConnKey {
    pub(super) client_ip: Ipv4Addr,
    pub(super) client_port: u16,
    pub(super) server_ip: Ipv4Addr,
    pub(super) server_port: u16,
}

/// The set of states of a TCP connection (non-exhaustive). Variant meanings below from RFC 9293,
/// Section 3.3.2.
#[derive(PartialEq, Eq)]
enum TcpState {
    /// "SYN-RECEIVED - represents waiting for a confirming connection request acknowledgment after
    /// having both received and sent a connection request."
    SynReceived,

    /// "ESTABLISHED - represents an open connection, data received can be delivered to the user.
    /// The normal state for the data transfer phase of the connection."
    Established,

    /// "CLOSING - represents waiting for a connection termination request acknowledgment from the
    /// remote TCP peer."
    Closing,
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
}

/// Tracks per-connection state keyed by the 4-tuple.
pub struct TcpConnections(HashMap<ConnKey, ConnState>);

impl TcpConnections {
    pub fn new() -> Self { Self(HashMap::new()) }

    pub(super) fn store_isn(&mut self, key: ConnKey, isn: u32) {
        self.0.insert(
            key,
            ConnState {
                tcp_state: TcpState::SynReceived,
                isn,
                snd_una: isn, // The SYN-ACK we're about to send is unacknowledged
                snd_nxt: isn.wrapping_add(1), // SYN-ACK consumes one sequence number
                rcv_nxt: 0,   // Set at connection establishment
            },
        );
    }

    /// Returns the ISN only while the connection is still in `SynReceived` state.
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

    pub(super) fn is_established(&self, key: &ConnKey) -> bool {
        self.0
            .get(key)
            .is_some_and(|s| s.tcp_state == TcpState::Established)
    }

    pub(super) fn get_snd_nxt(&self, key: &ConnKey) -> Option<u32> {
        self.0.get(key).map(|s| s.snd_nxt)
    }

    pub(super) fn advance_snd_nxt(&mut self, key: &ConnKey, n: u32) {
        if let Some(conn) = self.0.get_mut(key) {
            conn.snd_nxt = conn.snd_nxt.wrapping_add(n);
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
        }
    }

    /// Returns whether `ack_num` acknowledges data the server has not yet sent (`ack_num > SND.NXT`
    /// in sequence-number space).
    pub(super) fn ack_exceeds_snd_nxt(&self, key: &ConnKey, ack_num: u32) -> bool {
        self.0
            .get(key)
            .is_some_and(|s| Self::seq_lt(s.snd_nxt, ack_num))
    }

    pub(super) fn get_rcv_nxt(&self, key: &ConnKey) -> Option<u32> {
        self.0.get(key).map(|s| s.rcv_nxt)
    }

    pub(super) fn advance_rcv_nxt(&mut self, key: &ConnKey, n: u32) {
        if let Some(conn) = self.0.get_mut(key) {
            conn.rcv_nxt = conn.rcv_nxt.wrapping_add(n);
        }
    }

    pub(super) fn start_closing(&mut self, key: &ConnKey) {
        if let Some(conn) = self.0.get_mut(key) {
            conn.tcp_state = TcpState::Closing;
        }
    }

    pub(super) fn is_closing(&self, key: &ConnKey) -> bool {
        self.0
            .get(key)
            .is_some_and(|s| s.tcp_state == TcpState::Closing)
    }

    pub(super) fn remove(&mut self, key: &ConnKey) { self.0.remove(key); }

    /// Returns whether `a` precedes `b` in TCP sequence-number space, accounting for 32-bit
    /// wraparound (RFC 9293, Section 3.4).
    const fn seq_lt(a: u32, b: u32) -> bool { a.wrapping_sub(b) > u32::MAX / 2 }

    /// Returns whether `a` precedes or equals `b` in TCP sequence-number space, accounting for
    /// 32-bit wraparound (RFC 9293, Section 3.4).
    const fn seq_le(a: u32, b: u32) -> bool { a == b || Self::seq_lt(a, b) }
}
