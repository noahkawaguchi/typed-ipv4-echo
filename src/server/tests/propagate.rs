use super::*;

#[test]
fn poll_error_unrelated_to_interruption_propagates() -> Result {
    let poll = PollScript::new([Err(io::ErrorKind::Other.into())]);
    let mut device = MockDevice::new([])?;

    assert_matches!(
        run_test_server(
            TcpConnections::default(),
            &mut device,
            |_, _| poll.next(),
            || false,
            Duration::MAX,
        ),
        Err(_),
        "A non-interrupt poll error should propagate"
    );

    Ok(())
}

#[test]
fn read_error_unrelated_to_interruption_propagates() -> Result {
    let poll = PollScript::new([Ok(true)]);
    let mut device = MockDevice::new([Err(io::ErrorKind::Other.into())])?;

    assert_matches!(
        run_test_server(
            TcpConnections::default(),
            &mut device,
            |_, _| poll.next(),
            || false,
            Duration::MAX,
        ),
        Err(_),
        "A non-interrupt read error should propagate"
    );

    Ok(())
}

#[test]
fn write_failure_while_sending_fin_ack_propagates() -> Result {
    let poll = PollScript::new([Err(io::ErrorKind::Interrupted.into())]);
    let mut device = MockDevice::new([])?.fail_writes(io::ErrorKind::Other);

    assert_matches!(
        run_test_server(
            TcpConnections::after_handshake(),
            &mut device,
            |_, _| poll.next(),
            || true,
            Duration::MAX,
        ),
        Err(_),
        "A device write failure while closing connections should propagate"
    );

    Ok(())
}
