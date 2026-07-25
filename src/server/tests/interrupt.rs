use super::*;

#[test]
fn already_draining_reports_time_left() -> Result {
    let mut device = MockDevice::new([])?;
    let now = Instant::now();
    let deadline = now.checked_add(Duration::from_secs(10)).ok_or("overflow")?;

    let mut server =
        Server { shutdown_deadline: Some(deadline), ..decision_test_server(&mut device) };

    assert_eq!(
        server.decide_shutdown(now)?,
        ShutdownDecision::AlreadyDraining { time_left: Duration::from_secs(10) }
    );

    Ok(())
}

#[test]
fn established_connection_begins_draining_with_fin_ack_and_deadline() -> Result {
    let mut device = MockDevice::new([])?;
    let now = Instant::now();
    let expected_deadline = now.checked_add(Duration::from_secs(10)).ok_or("overflow")?;

    let mut server = Server {
        tcp_connections: TcpConnections::after_handshake(),
        shutdown_grace_period: Duration::from_secs(10),
        ..decision_test_server(&mut device)
    };

    assert_matches!(
        server.decide_shutdown(now)?,
        ShutdownDecision::BeganDraining { to_send, deadline }
            if to_send.len() == 1 && deadline == expected_deadline
    );

    Ok(())
}

#[test]
fn no_established_connections_reports_no_connections() -> Result {
    let mut device = MockDevice::new([])?;

    let mut server =
        Server { tcp_connections: TcpConnections::default(), ..decision_test_server(&mut device) };

    assert_eq!(server.decide_shutdown(Instant::now())?, ShutdownDecision::NoConnections);

    Ok(())
}

#[test]
fn overflowing_deadline_errors_instead_of_panicking() -> Result {
    let mut device = MockDevice::new([])?;

    let mut server = Server {
        tcp_connections: TcpConnections::after_handshake(),
        shutdown_grace_period: Duration::MAX,
        ..decision_test_server(&mut device)
    };

    assert_matches!(
        server.decide_shutdown(Instant::now()),
        Err(e) if e.contains("Overflowed")
    );

    Ok(())
}

#[test]
fn first_interrupt_with_established_connection_sends_fin_ack_and_continues() -> Result {
    // The first poll call simulates the shutdown signal, then the second lets the (already-elapsed)
    // grace period end the loop instead of running forever. Proves that the loop sends the packets
    // as real I/O when draining begins.

    let poll = MockPoll::new([Err(io::ErrorKind::Interrupted.into()), Ok(false)]);
    let mut device = MockDevice::new([])?;

    run_test_server(
        TcpConnections::after_handshake(),
        &mut device,
        |_, _| poll.next(),
        || true,
        IMMEDIATE_GRACE_PERIOD,
    )?;

    assert_eq!(device.writes().len(), 1, "Exactly one FIN-ACK should be written");

    Ok(())
}

#[test]
fn interrupt_with_no_established_connections_exits_immediately() -> Result {
    // The server should exit after the initial interrupted error, avoiding the second error, which
    // would be propagated

    let poll =
        MockPoll::new([Err(io::ErrorKind::Interrupted.into()), Err(io::ErrorKind::Other.into())]);

    let mut device = MockDevice::new([])?;

    assert_matches!(
        run_test_server(
            TcpConnections::default(),
            &mut device,
            |_, _| poll.next(),
            || true,
            IMMEDIATE_GRACE_PERIOD,
        ),
        Ok(()),
        "Server should exit before hitting the error that would be propagated"
    );

    assert!(device.writes().is_empty(), "No connections to close, nothing should be written");

    Ok(())
}

#[test]
fn interrupt_unrelated_to_shutdown_is_ignored() -> Result {
    // The shutdown check only starts returning `true` on the second poll call, so the first
    // interruption must be treated as an unrelated signal (just continue) rather than the start of
    // a shutdown. Connections start empty so that, if the first interrupt were wrongly treated as
    // real, the server would exit immediately (after only one poll call) instead of needing the
    // second, real shutdown interrupt to do so.

    let poll_calls = Cell::new(0u8);

    let poll = MockPoll::new([
        Err(io::ErrorKind::Interrupted.into()),
        Err(io::ErrorKind::Interrupted.into()),
    ]);

    let mut device = MockDevice::new([])?;

    run_test_server(
        TcpConnections::default(),
        &mut device,
        |_, _| {
            poll_calls.set(poll_calls.get() + 1);
            poll.next()
        },
        || poll_calls.get() >= 2,
        IMMEDIATE_GRACE_PERIOD,
    )?;

    assert_eq!(poll_calls.get(), 2, "The first interrupt should not have ended the loop early");

    Ok(())
}

#[test]
fn read_interrupt_reaches_the_same_shutdown_handling_as_poll_interrupt() -> Result {
    // Mirrors the test for poll, but the `EINTR` arrives from the `read()` call instead of the
    // `poll()`, confirming that both entry points reach the same shutdown decision handling

    let poll = MockPoll::new([Ok(true)]);
    let mut device = MockDevice::new([Err(io::ErrorKind::Interrupted.into())])?;

    run_test_server(
        TcpConnections::default(),
        &mut device,
        |_, _| poll.next(),
        || true,
        IMMEDIATE_GRACE_PERIOD,
    )?;

    assert!(device.writes().is_empty(), "No connections to close, nothing should be written");

    Ok(())
}
