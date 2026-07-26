use super::*;

#[test]
fn no_deadline_no_closing() {
    let server = decision_test_server();
    assert!(server.shutdown_deadline.is_none());
    assert!(!server.tcp_connections.closing_in_progress());
    assert!(!server.shutting_down_and_no_connections_closing());
}

#[test]
fn no_deadline_some_closing() {
    let mut tcp_connections = TcpConnections::default().after_handshake();
    tcp_connections.close_established();
    let server = Server { tcp_connections, ..decision_test_server() };

    assert!(server.shutdown_deadline.is_none());
    assert!(server.tcp_connections.closing_in_progress());
    assert!(!server.shutting_down_and_no_connections_closing());
}

#[test]
fn some_deadline_some_closing() {
    let mut tcp_connections = TcpConnections::default().after_handshake();
    tcp_connections.close_established();

    let server = Server {
        tcp_connections,
        shutdown_deadline: Some(Instant::now()),
        ..decision_test_server()
    };

    assert!(server.shutdown_deadline.is_some());
    assert!(server.tcp_connections.closing_in_progress());
    assert!(!server.shutting_down_and_no_connections_closing());
}

#[test]
fn some_deadline_no_closing() {
    let server = Server {
        tcp_connections: TcpConnections::default(),
        shutdown_deadline: Some(Instant::now()),
        ..decision_test_server()
    };

    assert!(server.shutdown_deadline.is_some());
    assert!(!server.tcp_connections.closing_in_progress());
    assert!(server.shutting_down_and_no_connections_closing());
}

#[test]
fn exits_once_connections_finish_closing() -> Result {
    // The first poll is a shutdown signal that begins active close (FIN-ACK sent -> FIN-WAIT-1).
    // The second poll delivers the client's real closing FIN-ACK, which the connection accepts as
    // completing the close. The post-packet check should then end the loop immediately, without
    // needing the (very long) grace period to elapse.

    let poll_calls = Cell::new(0u8);
    let poll = MockPoll::new([Err(io::ErrorKind::Interrupted.into()), Ok(true)]);
    let mut device =
        MockDevice::new([Ok(encode_mock_packet(&TcpHandler::test_fin_ack_completing_close())?)])?;

    run_test_server(
        TcpConnections::default().after_handshake(),
        &mut device,
        |_, _| {
            poll_calls.set(poll_calls.get() + 1);
            poll.next()
        },
        || true,
        ONE_YEAR_GRACE_PERIOD,
    )?;

    assert_eq!(poll_calls.get(), 2, "Both poll calls should have been needed to exit");
    assert_eq!(
        device.writes().len(),
        2,
        "The initial FIN-ACK and the final ACK completing the close should be written"
    );

    Ok(())
}
