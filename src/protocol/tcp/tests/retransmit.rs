use {
    super::*,
    crate::protocol::test_utils::IP_PAIR,
    std::{error::Error, time::Duration},
};

#[test]
fn syn_ack_is_resent_while_due() -> Result<(), Box<dyn Error>> {
    let mut connections = TcpConnections::new(Duration::ZERO, 5);

    client_packet(4096, 0, TcpFlags::Syn, &[]).into_reply(&mut connections, IP_PAIR)?;
    let isn = connections.pending_isn(&KEY).ok_or("ISN not stored")?;

    let mut resent = connections.make_retransmissions();
    let (reply, ip_pair) = resent.pop().ok_or("Expected one retransmitted segment")?;

    assert!(resent.is_empty(), "Expected exactly one retransmitted segment");
    assert_eq!(reply, server_reply(isn, 4097, TcpFlags::SynAck, &[]));
    assert_eq!(ip_pair, IP_PAIR.swapped());

    Ok(())
}

#[test]
fn pending_segment_is_cleared_once_acked() -> Result<(), Box<dyn Error>> {
    let mut connections = TcpConnections::new(Duration::ZERO, 5);

    client_packet(4096, 0, TcpFlags::Syn, &[]).into_reply(&mut connections, IP_PAIR)?;
    let isn = connections.pending_isn(&KEY).ok_or("ISN not stored")?;

    // Handshake ACK completes the connection and should clear the pending SYN-ACK
    client_packet(4097, isn.wrapping_add(1), TcpFlags::Ack, &[])
        .into_reply(&mut connections, IP_PAIR)?;

    let resent = connections.make_retransmissions();

    assert!(resent.is_empty(), "Acked segment should not be retransmitted");

    Ok(())
}

#[test]
fn data_echo_is_resent_unchanged() -> Result<(), Box<dyn Error>> {
    let mut connections = TcpConnections::new(Duration::ZERO, 5);
    connections.store_isn(KEY, 0);
    connections.establish(&KEY, 4097);

    client_packet(4097, 1, TcpFlags::Ack, b"Hello").into_reply(&mut connections, IP_PAIR)?;

    let mut resent = connections.make_retransmissions();
    let (reply, _) = resent.pop().ok_or("Expected one retransmitted segment")?;

    assert!(resent.is_empty(), "Expected exactly one retransmitted segment");
    assert_eq!(reply, server_reply(1, 4102, TcpFlags::Ack, b"Hello"));

    Ok(())
}

#[test]
fn fin_ack_is_resent_unchanged() -> Result<(), Box<dyn Error>> {
    let mut connections = TcpConnections::new(Duration::ZERO, 5);
    connections.store_isn(KEY, 0);
    connections.establish(&KEY, 4097);

    connections.close_established();

    let mut resent = connections.make_retransmissions();
    let (reply, _) = resent.pop().ok_or("Expected one retransmitted segment")?;

    assert!(resent.is_empty(), "Expected exactly one retransmitted segment");
    assert_eq!(reply, server_reply(1, 4097, TcpFlags::FinAck, &[]));

    Ok(())
}

#[test]
fn multiple_unacked_segments_are_all_retransmitted() -> Result<(), Box<dyn Error>> {
    // If the client pipelines multiple segments before acking the first, the server must keep
    // retransmitting every unacked segment, not just the most recently sent one.

    let mut connections = TcpConnections::new(Duration::ZERO, 5);
    connections.store_isn(KEY, 0);
    connections.establish(&KEY, 4097);

    // First data packet: "Hello" (5 bytes), ack=1 -> echoed, pending segment seq=1..6
    client_packet(4097, 1, TcpFlags::Ack, b"Hello").into_reply(&mut connections, IP_PAIR)?;

    // Second data packet: "Hi" (2 bytes), still ack=1 (hasn't acked the first echo yet) -> echoed,
    // pending segment seq=6..8
    client_packet(4102, 1, TcpFlags::Ack, b"Hi").into_reply(&mut connections, IP_PAIR)?;

    let [(hello, _), (hi, _)] = <[_; 2]>::try_from(connections.make_retransmissions())
        .map_err(|_| "Expected exactly two retransmitted segments")?;

    assert_eq!(hello, server_reply(1, 4102, TcpFlags::Ack, b"Hello"));
    assert_eq!(hi, server_reply(6, 4104, TcpFlags::Ack, b"Hi"));

    Ok(())
}

#[test]
fn gives_up_after_max_retransmits() -> Result<(), Box<dyn Error>> {
    const MAX_RETRIES: u8 = 3;

    let mut connections = TcpConnections::new(Duration::ZERO, MAX_RETRIES);
    client_packet(4096, 0, TcpFlags::Syn, &[]).into_reply(&mut connections, IP_PAIR)?;

    for _ in 0..MAX_RETRIES {
        let resent = connections.make_retransmissions();

        assert_eq!(resent.len(), 1, "Should still be retried");
        assert_eq!(connections.tcp_state_of(&KEY), TcpState::SynReceived);
    }

    // Exceeds MAX_RETRIES -> give up
    let resent = connections.make_retransmissions();

    assert!(resent.is_empty(), "Should give up instead of retransmitting again");
    assert_eq!(connections.tcp_state_of(&KEY), TcpState::Closed, "Connection should be removed");

    Ok(())
}
