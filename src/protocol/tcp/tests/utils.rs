use super::*;

/// Fixed value to use as the ISN randomly chosen by the client.
pub const CLIENT_ISN: u32 = 100;

/// Fixed value to use as the ISN randomly chosen by the server.
pub const SERVER_ISN: u32 = 400;

/// Checks at compile time that `CLIENT_ISN` and `SERVER_ISN` are sufficiently far from each
/// other so they cannot be mixed up in tests.
const _: () = assert!(CLIENT_ISN.abs_diff(SERVER_ISN) >= 100);

/// The single phantom byte consumed by SYN.
pub const SYN_BYTE: u32 = 1;

/// The single phantom byte consumed by FIN.
pub const FIN_BYTE: u32 = 1;

/// The number of bytes in the payload `"Hello"`.
pub const HELLO_LEN: u32 = 5;

/// The number of bytes in the payload `"Hi"`.
pub const HI_LEN: u32 = 2;

/// The number of bytes in the payload `"Hey"`.
pub const HEY_LEN: u32 = 3;

/// Connection key shared by test modules.
pub const KEY: ConnKey =
    ConnKey { client_ip: SRC_IP, client_port: 1234, server_ip: DST_IP, server_port: 80 };

/// An ESTABLISHED connection as if the initial three-way handshake had just completed. Uses the
/// test constants `CLIENT_ISN` and `SERVER_ISN`. Has the maximum SND.WND and empty
/// `pending`/`send_buffer`.
pub const AFTER_HANDSHAKE: ConnState = ConnState {
    tcp_state: TcpState::Established,
    snd_nxt: SERVER_ISN + SYN_BYTE,
    rcv_nxt: CLIENT_ISN + SYN_BYTE,
    snd_una: SERVER_ISN + SYN_BYTE,
    window_state: Some(WindowState {
        snd_wnd: u16::MAX,
        snd_wl1: CLIENT_ISN + SYN_BYTE,
        snd_wl2: SERVER_ISN + SYN_BYTE,
    }),
    pending: Vec::new(),
    send_buffer: VecDeque::new(),
};

/// An incoming pure ACK packet from the client (port 1234) to the server (port 80).
/// `seq_num` and `ack_num` will be 0 if not overridden.
pub const CLIENT_PACKET: TcpHandler = TcpHandler {
    ip_pair: Ipv4AddrPair { src: KEY.client_ip, dst: KEY.server_ip },
    ports: PortPair { src: KEY.client_port, dst: KEY.server_port },
    seq_num: 0,
    ack_num: 0,
    offset_bytes: 20,
    flags: TcpFlags::Ack,
    window: u16::MAX,
    payload: None,
};

/// An outgoing pure ACK packet from the server (port 80) to the client (port 1234).
/// `seq_num` and `ack_num` will be 0 if not overridden.
pub const SERVER_REPLY: TcpHandler = TcpHandler {
    ip_pair: Ipv4AddrPair { src: KEY.server_ip, dst: KEY.client_ip },
    ports: PortPair { src: KEY.server_port, dst: KEY.client_port },
    seq_num: 0,
    ack_num: 0,
    offset_bytes: 20,
    flags: TcpFlags::Ack,
    window: u16::MAX,
    payload: None,
};

/// Attempts to convert a `&str` into an `Option<TcpPayload>`, with an empty string mapping to
/// `Ok(None)`.
pub fn payload_from(s: &str) -> Result<Option<TcpPayload>, &'static str> {
    TcpPayload::try_from_iter(s.as_bytes().iter().copied())
}
