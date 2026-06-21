use {
    super::*,
    crate::protocol::test_utils::IP_PAIR,
    std::{
        error::Error,
        time::{Duration, Instant},
    },
};

#[test]
fn syn_ack_is_resent_while_due() -> Result<(), Box<dyn Error>> {
    let mut connections = TcpConnections::new();

    client_packet(4096, 0, TcpFlags::Syn, &[]).into_reply(&mut connections, IP_PAIR)?;
    let isn = connections.pending_isn(&KEY).ok_or("ISN not stored")?;

    let mut resent = connections.make_retransmissions(Instant::now(), Duration::ZERO, 5);
    let (reply, ip_pair) = resent.pop().ok_or("Expected one retransmitted segment")?;

    assert!(resent.is_empty(), "Expected exactly one retransmitted segment");
    assert_eq!(reply, server_reply(isn, 4097, TcpFlags::SynAck, &[]));
    assert_eq!(ip_pair, IP_PAIR.swapped());

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

    let resent = connections.make_retransmissions(Instant::now(), Duration::ZERO, 5);

    assert!(resent.is_empty(), "Acked segment should not be retransmitted");

    Ok(())
}

#[test]
fn data_echo_is_resent_unchanged() -> Result<(), Box<dyn Error>> {
    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, 0);
    connections.establish(&KEY, 4097);

    client_packet(4097, 1, TcpFlags::Ack, b"Hello").into_reply(&mut connections, IP_PAIR)?;

    let mut resent = connections.make_retransmissions(Instant::now(), Duration::ZERO, 5);
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

    connections.close_established();

    let mut resent = connections.make_retransmissions(Instant::now(), Duration::ZERO, 5);
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
        let resent = connections.make_retransmissions(Instant::now(), Duration::ZERO, MAX_RETRIES);

        assert_eq!(resent.len(), 1, "Should still be retried");
        assert_eq!(connections.tcp_state_of(&KEY), TcpState::SynReceived);
    }

    // Exceeds MAX_RETRIES -> give up
    let resent = connections.make_retransmissions(Instant::now(), Duration::ZERO, MAX_RETRIES);

    assert!(resent.is_empty(), "Should give up instead of retransmitting again");
    assert_eq!(connections.tcp_state_of(&KEY), TcpState::Closed, "Connection should be removed");

    Ok(())
}
