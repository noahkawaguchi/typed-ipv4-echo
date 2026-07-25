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
    // A grace period too long to elapse means the second poll's `Ok(false)` must fall through to
    // the retransmit branch instead of the "grace period elapsed" branch. The default
    // `TcpConnections` has a max retries of 0, so the retransmission attempt actually drops the
    // connection, which then lets the third poll call (processing an otherwise irrelevant packet)
    // prove that the post-packet closing in progress check ends the loop early, even though the
    // grace period is nowhere close to elapsing.

    let poll_calls = Cell::new(0u8);
    let poll = MockPoll::new([Err(io::ErrorKind::Interrupted.into()), Ok(false), Ok(true)]);
    let mut device = MockDevice::new([Ok(vec![0u8; 5])])?;

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

    assert_eq!(poll_calls.get(), 3, "All three poll calls should have been needed to exit");
    assert_eq!(device.writes().len(), 1, "Only the original FIN-ACK, no resend, should be written");

    Ok(())
}
