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

#[derive(PartialEq, Eq)]
enum TcpState {
    SynReceived,
    Established,
    Closing,
}

struct ConnState {
    tcp_state: TcpState,
    isn: u32,
}

/// Tracks per-connection state keyed by the 4-tuple.
pub struct TcpConnections(HashMap<ConnKey, ConnState>);

impl TcpConnections {
    pub fn new() -> Self { Self(HashMap::new()) }

    pub(super) fn store_isn(&mut self, key: ConnKey, isn: u32) {
        self.0
            .insert(key, ConnState { tcp_state: TcpState::SynReceived, isn });
    }

    /// Returns the ISN only while the connection is still in `SynReceived` state.
    pub(super) fn pending_isn(&self, key: &ConnKey) -> Option<u32> {
        self.0
            .get(key)
            .filter(|s| s.tcp_state == TcpState::SynReceived)
            .map(|s| s.isn)
    }

    pub(super) fn establish(&mut self, key: &ConnKey) {
        if let Some(conn) = self.0.get_mut(key) {
            conn.tcp_state = TcpState::Established;
        }
    }

    pub(super) fn is_established(&self, key: &ConnKey) -> bool {
        self.0
            .get(key)
            .is_some_and(|s| s.tcp_state == TcpState::Established)
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
}
