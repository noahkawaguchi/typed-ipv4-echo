use {super::*, std::time::Duration};

#[test]
fn syn_ack_is_resent_while_due() -> Result<()> {
    let mut connections = TcpConnections::new(Duration::ZERO, 5);

    client_packet(CLIENT_ISN, 0, TcpFlags::Syn, &[]).create_reply(&mut connections)?;

    let isn = connections.try_get()?.snd_una;

    let mut resent = connections.make_retransmissions();
    let reply = resent.pop().ok_or("Expected one retransmitted segment")?;

    assert!(resent.is_empty(), "Expected exactly one retransmitted segment");
    assert_eq!(reply, server_reply(isn, CLIENT_ISN + SYN_BYTE, TcpFlags::SynAck, &[]));
    assert_eq!(reply.get_ip_pair(), IP_PAIR.swapped());

    Ok(())
}

#[test]
fn pending_segment_is_cleared_once_acked() -> Result<()> {
    let mut connections = TcpConnections::new(Duration::ZERO, 5);

    client_packet(CLIENT_ISN, 0, TcpFlags::Syn, &[]).create_reply(&mut connections)?;

    let isn = connections.try_get()?.snd_una;

    // Handshake ACK completes the connection and should clear the pending SYN-ACK
    client_packet(CLIENT_ISN + SYN_BYTE, isn.wrapping_add(SYN_BYTE), TcpFlags::Ack, &[])
        .create_reply(&mut connections)?;

    assert!(
        connections.make_retransmissions().is_empty(),
        "Acked segment should not be retransmitted"
    );

    Ok(())
}

#[test]
fn data_echo_is_resent_unchanged() -> Result<()> {
    let mut connections = TcpConnections::new(Duration::ZERO, 5);
    connections.insert(ConnState::default());

    client_packet(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE, TcpFlags::Ack, b"Hello")
        .create_reply(&mut connections)?;

    let mut resent = connections.make_retransmissions();
    let reply = resent.pop().ok_or("Expected one retransmitted segment")?;

    assert!(resent.is_empty(), "Expected exactly one retransmitted segment");
    assert_eq!(
        reply,
        server_reply(
            SERVER_ISN + SYN_BYTE,
            CLIENT_ISN + SYN_BYTE + HELLO_LEN,
            TcpFlags::Ack,
            b"Hello"
        )
    );

    Ok(())
}

#[test]
fn fin_ack_is_resent_unchanged() -> Result<()> {
    let mut connections = TcpConnections::new(Duration::ZERO, 5);
    connections.insert(ConnState::default());
    connections.close_established();

    let mut resent = connections.make_retransmissions();
    let reply = resent.pop().ok_or("Expected one retransmitted segment")?;

    assert!(resent.is_empty(), "Expected exactly one retransmitted segment");
    assert_eq!(
        reply,
        server_reply(SERVER_ISN + SYN_BYTE, CLIENT_ISN + SYN_BYTE, TcpFlags::FinAck, &[])
    );

    Ok(())
}

#[test]
fn multiple_unacked_segments_are_all_retransmitted() -> Result<()> {
    // If the client pipelines multiple segments before acking the first, the server must keep
    // retransmitting every unacked segment, not just the most recently sent one.

    let mut connections = TcpConnections::new(Duration::ZERO, 5);
    connections.insert(ConnState::default());

    // First data packet: "Hello" (5 bytes), ack=SERVER_ISN+1 -> echoed, pending segment
    // seq=SERVER_ISN+1..SERVER_ISN+6
    client_packet(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE, TcpFlags::Ack, b"Hello")
        .create_reply(&mut connections)?;

    // Second data packet: "Hi" (2 bytes), still ack=SERVER_ISN+1 (hasn't acked the first echo yet)
    // -> echoed, pending segment seq=SERVER_ISN+6..SERVER_ISN+8
    client_packet(CLIENT_ISN + SYN_BYTE + HELLO_LEN, SERVER_ISN + SYN_BYTE, TcpFlags::Ack, b"Hi")
        .create_reply(&mut connections)?;

    let [hello, hi] = connections
        .make_retransmissions()
        .try_into()
        .map_err(|_| "Expected exactly two retransmitted segments")?;

    assert_eq!(
        hello,
        server_reply(
            SERVER_ISN + SYN_BYTE,
            CLIENT_ISN + SYN_BYTE + HELLO_LEN,
            TcpFlags::Ack,
            b"Hello"
        )
    );

    assert_eq!(
        hi,
        server_reply(
            SERVER_ISN + SYN_BYTE + HELLO_LEN,
            CLIENT_ISN + SYN_BYTE + HELLO_LEN + HI_LEN,
            TcpFlags::Ack,
            b"Hi"
        )
    );

    Ok(())
}

#[test]
fn gives_up_after_max_retransmits() -> Result<()> {
    const MAX_RETRIES: u8 = 3;

    let mut connections = TcpConnections::new(Duration::ZERO, MAX_RETRIES);

    client_packet(CLIENT_ISN, 0, TcpFlags::Syn, &[]).create_reply(&mut connections)?;

    for _ in 0..MAX_RETRIES {
        let resent = connections.make_retransmissions();

        assert_eq!(resent.len(), 1, "Should still be retried");
        assert_eq!(connections.try_get()?.tcp_state, TcpState::SynReceived);
    }

    // Exceeds MAX_RETRIES -> give up
    let resent = connections.make_retransmissions();

    assert!(resent.is_empty(), "Should give up instead of retransmitting again");
    assert_matches!(connections.try_get(), Err(_), "Connection should be removed");

    Ok(())
}
