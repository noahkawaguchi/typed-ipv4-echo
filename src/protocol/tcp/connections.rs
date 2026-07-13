use {
    crate::{
        addr_pairs::{Ipv4AddrPair, PortPair},
        protocol::tcp::{
            SendInfo, TcpFlags, TcpHandler,
            seq_space::AdvanceBy as _,
            state::{ConnState, PendingSegment, TcpState},
        },
    },
    std::{
        collections::{HashMap, VecDeque},
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
                // Window-related values are set at connection establishment once the peer's window
                // is actually known
                snd_wnd: 0,
                snd_wl1: 0,
                snd_wl2: 0,
                pending: vec![PendingSegment::new(send_info, 1)],
                send_buffer: VecDeque::new(),
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

    /// Inserts a SYN-RECEIVED connection into the table using `KEY`, `CLIENT_ISN`, and
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

    /// Creates a default-initialized `Self` and inserts a default-initialized ESTABLISHED
    /// connection using `KEY` as if the initial three-way handshake had just completed.
    #[cfg(test)]
    pub(super) fn after_handshake() -> Self {
        use crate::protocol::tcp::tests::KEY;

        let mut connections = Self::default();
        connections.table.insert(KEY, ConnState::default());
        connections
    }
}
