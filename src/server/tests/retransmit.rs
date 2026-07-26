use super::*;

#[test]
fn due_retransmission_is_sent_as_real_io() -> Result {
    // Zero RTO means the pending SYN-ACK is due the instant it's seeded, so the very first
    // `Ok(false)` (a poll timeout) should trigger a real resend. The second poll call is a shutdown
    // signal, and since a SYN-RECEIVED connection isn't mid-close, it exits immediately without
    // writing anything more.

    let poll = MockPoll::new([Ok(false), Err(io::ErrorKind::Interrupted.into())]);
    let mut device = MockDevice::new([])?;

    run_test_server(
        TcpConnections::new(Duration::ZERO, 5).with_syn_rcv(),
        &mut device,
        |_, _| poll.next(),
        || true,
        ONE_YEAR_GRACE_PERIOD,
    )?;

    let [write] = device.writes() else { return Err("Expected exactly one write".into()) };

    let ProtocolHandler::Tcp(handler) = decode_mock_packet(write)? else {
        return Err("Expected a TCP packet".into());
    };

    assert_eq!(handler, TcpHandler::test_server_syn_ack_for_syn_received());

    Ok(())
}

#[test]
fn retransmission_does_not_drop_the_connection() -> Result {
    // Max retries of 5 comfortably covers two retransmissions, so if the connection survives the
    // first retransmit, the second due poll should trigger another one instead of finding the
    // connection already gone.

    let poll = MockPoll::new([Ok(false), Ok(false), Err(io::ErrorKind::Interrupted.into())]);
    let mut device = MockDevice::new([])?;

    run_test_server(
        TcpConnections::new(Duration::ZERO, 5).with_syn_rcv(),
        &mut device,
        |_, _| poll.next(),
        || true,
        ONE_YEAR_GRACE_PERIOD,
    )?;

    let [first, second] = device.writes() else {
        return Err(
            "The connection should survive the first retransmit and produce a second".into()
        );
    };

    for write in [first, second] {
        let ProtocolHandler::Tcp(handler) = decode_mock_packet(write)? else {
            return Err("Expected a TCP packet".into());
        };

        assert_eq!(
            handler,
            TcpHandler::test_server_syn_ack_for_syn_received(),
            "Every retransmission should resend the same unacked SYN-ACK unchanged"
        );
    }

    Ok(())
}

#[test]
fn gives_up_and_drops_connection_after_max_retries() -> Result {
    // With max retries of 2, the first two due polls retransmit, and the third finds the retries
    // exhausted and drops the connection instead of sending again. The final poll is a shutdown
    // signal, and with the connection already gone, it should exit immediately without another
    // write.

    let poll =
        MockPoll::new([Ok(false), Ok(false), Ok(false), Err(io::ErrorKind::Interrupted.into())]);
    let mut device = MockDevice::new([])?;

    run_test_server(
        TcpConnections::new(Duration::ZERO, 2).with_syn_rcv(),
        &mut device,
        |_, _| poll.next(),
        || true,
        ONE_YEAR_GRACE_PERIOD,
    )?;

    let [first, second] = device.writes() else {
        return Err("Only 2 retransmissions should be written before giving up, not 3".into());
    };

    for write in [first, second] {
        let ProtocolHandler::Tcp(handler) = decode_mock_packet(write)? else {
            return Err("Expected a TCP packet".into());
        };

        assert_eq!(
            handler,
            TcpHandler::test_server_syn_ack_for_syn_received(),
            "Every retransmission should resend the same unacked SYN-ACK unchanged"
        );
    }

    Ok(())
}
