use {
    crate::{
        Result,
        addr_pairs::{Ipv4AddrPair, PortPair},
        protocol::tcp::{
            PendingSegment, SendInfo, TcpFlags, TcpHandler,
            seq_space::AdvanceBy as _,
            state::{ConnState, TcpState},
        },
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

/// Tracks per-connection state keyed by the 4-tuple.
#[cfg_attr(test, derive(Default))]
pub struct TcpConnections {
    table: HashMap<ConnKey, ConnState>,

    /// The initial retransmission timeout, i.e. how long to wait before retransmitting an unacked
    /// segment the first time before exponential backoff.
    initial_rto: Duration,

    /// The number of times to retransmit an unacked segment before giving up and dropping the
    /// connection.
    max_retries: u8,
}

impl TcpConnections {
    pub fn new(initial_rto: Duration, max_retries: u8) -> Self {
        Self { table: HashMap::new(), initial_rto, max_retries }
    }

    pub fn len(&self) -> usize { self.table.len() }

    pub(super) fn get_mut(&mut self, key: &ConnKey) -> Option<&mut ConnState> {
        self.table.get_mut(key)
    }

    /// Adds a new SYN-RECEIVED connection to the table.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the connection's TCP state is not SYN-RECEIVED.
    pub(super) fn insert_syn_rcv(
        &mut self,
        key: ConnKey,
        state: ConnState,
    ) -> Result<(), &'static str> {
        (state.tcp_state == TcpState::SynReceived)
            .then(|| {
                self.table.insert(key, state);
            })
            .ok_or("Attempted to insert a connection with a state other than SYN-RECEIVED")
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
            .map(|seg| seg.time_due(self.initial_rto))
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
                    .any(|seg| seg.time_due(self.initial_rto) <= now)
                    .then_some(key)
            })
            .collect::<Vec<_>>();

        let mut retransmissions = Vec::new();

        for key in due_keys {
            let Some(conn) = self.table.get_mut(&key) else { continue };

            if conn.pending.iter().any(|seg| {
                seg.time_due(self.initial_rto) <= now && seg.exhausted_retries(self.max_retries)
            }) {
                self.table.remove(&key);
                continue;
            }

            retransmissions.extend(conn.pending.iter_mut().filter_map(|seg| {
                (seg.time_due(self.initial_rto) <= now).then(|| {
                    TcpHandler::from_pairs_and_info(
                        Ipv4AddrPair { src: key.server_ip, dst: key.client_ip },
                        PortPair { src: key.server_port, dst: key.client_port },
                        seg.retransmit_info(now),
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

                conn.pending.push(PendingSegment::new(send_info.clone()));

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
    pub(super) fn try_get(&self) -> Result<&ConnState, &'static str> {
        use crate::protocol::tcp::tests::KEY;

        self.table.get(&KEY).ok_or("Connection not found")
    }

    /// Inserts `conn` into the connection table using `KEY`.
    #[cfg(test)]
    pub(super) fn insert(&mut self, conn: ConnState) {
        use crate::protocol::tcp::tests::KEY;

        self.table.insert(KEY, conn);
    }

    /// Creates a default-initialized `Self` and inserts a new SYN-RECEIVED connection using `KEY`,
    /// `CLIENT_ISN`, and `SERVER_ISN` as if we had just responded to the peer's SYN with SYN-ACK.
    #[cfg(test)]
    pub(super) fn with_syn_rcv() -> Self {
        use {
            crate::protocol::tcp::tests::{CLIENT_ISN, KEY, SERVER_ISN, SYN_BYTE},
            std::collections::VecDeque,
        };

        let mut connections = Self::default();

        connections.table.insert(
            KEY,
            ConnState {
                tcp_state: TcpState::SynReceived,
                snd_nxt: SERVER_ISN + SYN_BYTE,
                rcv_nxt: CLIENT_ISN + SYN_BYTE,
                snd_una: SERVER_ISN,
                window_state: None,
                pending: vec![PendingSegment::new(SendInfo {
                    seq_num: SERVER_ISN,
                    ack_num: CLIENT_ISN + SYN_BYTE,
                    flags: TcpFlags::SynAck,
                    payload: None,
                })],
                send_buffer: VecDeque::new(),
            },
        );

        connections
    }

    /// Creates a default-initialized `Self` and inserts a default-initialized ESTABLISHED
    /// connection using `KEY` as if the initial three-way handshake had just completed.
    #[cfg(test)]
    pub(super) fn after_handshake() -> Self {
        use crate::protocol::tcp::tests::{AFTER_HANDSHAKE, KEY};

        let mut connections = Self::default();
        connections.table.insert(KEY, AFTER_HANDSHAKE);
        connections
    }
}
