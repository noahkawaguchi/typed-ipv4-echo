use {
    super::*,
    crate::protocol::test_utils::{DST_IP, IP_PAIR, SRC_IP},
    std::error::Error,
};

/// Connection key shared by tests in this module.
const KEY: ConnKey =
    ConnKey { client_ip: SRC_IP, client_port: 1234, server_ip: DST_IP, server_port: 80 };

/// Builds an incoming packet from the client (port 1234) to the server (port 80).
fn client_packet(seq_num: u32, ack_num: u32, flags: TcpFlags, payload: &[u8]) -> TcpHandler {
    TcpHandler {
        src_port: KEY.client_port,
        dst_port: KEY.server_port,
        seq_num,
        ack_num,
        offset_bytes: 20,
        flags,
        payload: payload.to_vec(),
    }
}

/// Builds an expected reply from the server (port 80) to the client (port 1234).
fn server_reply(seq_num: u32, ack_num: u32, flags: TcpFlags, payload: &[u8]) -> TcpHandler {
    TcpHandler {
        src_port: KEY.server_port,
        dst_port: KEY.client_port,
        seq_num,
        ack_num,
        offset_bytes: 20,
        flags,
        payload: payload.to_vec(),
    }
}

#[test]
fn syn_ack_is_resent_while_due() -> Result<(), Box<dyn Error>> {
    let mut connections = TcpConnections::new();

    client_packet(4096, 0, TcpFlags::Syn, &[]).into_reply(&mut connections, IP_PAIR)?;
    let isn = connections.pending_isn(&KEY).ok_or("ISN not stored")?;

    let mut resent =
        TcpHandler::retransmit_expired(&mut connections, Instant::now(), Duration::ZERO, 5);
    let (reply, ip_pair) = resent.pop().ok_or("Expected one retransmitted segment")?;

    assert!(resent.is_empty(), "Expected exactly one retransmitted segment");
    assert_eq!(reply, server_reply(isn, 4097, TcpFlags::SynAck, &[]));
    assert_eq!(ip_pair.src, DST_IP);
    assert_eq!(ip_pair.dst, SRC_IP);

    Ok(())
}

#[test]
fn pending_segment_is_cleared_once_acked() -> Result<(), Box<dyn Error>> {
    let mut connections = TcpConnections::new();

    client_packet(4096, 0, TcpFlags::Syn, &[]).into_reply(&mut connections, IP_PAIR)?;
    let isn = connections.pending_isn(&KEY).ok_or("ISN not stored")?;

    // Handshake ACK completes the connection and should clear the pending SYN-ACK
    client_packet(4097, isn.wrapping_add(1), TcpFlags::Ack, &[])
        .into_reply(&mut connections, IP_PAIR)?;

    let resent =
        TcpHandler::retransmit_expired(&mut connections, Instant::now(), Duration::ZERO, 5);

    assert!(resent.is_empty(), "Acked segment should not be retransmitted");

    Ok(())
}

#[test]
fn data_echo_is_resent_unchanged() -> Result<(), Box<dyn Error>> {
    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, 0);
    connections.establish(&KEY, 4097);

    client_packet(4097, 1, TcpFlags::Ack, b"Hello").into_reply(&mut connections, IP_PAIR)?;

    let mut resent =
        TcpHandler::retransmit_expired(&mut connections, Instant::now(), Duration::ZERO, 5);
    let (reply, _) = resent.pop().ok_or("Expected one retransmitted segment")?;

    assert!(resent.is_empty(), "Expected exactly one retransmitted segment");
    assert_eq!(reply, server_reply(1, 4102, TcpFlags::Ack, b"Hello"));

    Ok(())
}

#[test]
fn fin_ack_is_resent_unchanged() -> Result<(), Box<dyn Error>> {
    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, 0);
    connections.establish(&KEY, 4097);

    TcpHandler::close_established(&mut connections);

    let mut resent =
        TcpHandler::retransmit_expired(&mut connections, Instant::now(), Duration::ZERO, 5);
    let (reply, _) = resent.pop().ok_or("Expected one retransmitted segment")?;

    assert!(resent.is_empty(), "Expected exactly one retransmitted segment");
    assert_eq!(reply, server_reply(1, 4097, TcpFlags::FinAck, &[]));

    Ok(())
}

#[test]
fn gives_up_after_max_retransmits() -> Result<(), Box<dyn Error>> {
    const MAX_RETRIES: u8 = 3;

    let mut connections = TcpConnections::new();
    client_packet(4096, 0, TcpFlags::Syn, &[]).into_reply(&mut connections, IP_PAIR)?;

    for _ in 0..MAX_RETRIES {
        let resent = TcpHandler::retransmit_expired(
            &mut connections,
            Instant::now(),
            Duration::ZERO,
            MAX_RETRIES,
        );

        assert_eq!(resent.len(), 1, "Should still be retried");
        assert_eq!(connections.tcp_state_of(&KEY), TcpState::SynReceived);
    }

    // Exceeds MAX_RETRIES -> give up
    let resent = TcpHandler::retransmit_expired(
        &mut connections,
        Instant::now(),
        Duration::ZERO,
        MAX_RETRIES,
    );

    assert!(resent.is_empty(), "Should give up instead of retransmitting again");
    assert_eq!(connections.tcp_state_of(&KEY), TcpState::Closed, "Connection should be removed");

    Ok(())
}
