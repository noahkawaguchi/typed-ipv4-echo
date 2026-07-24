use super::*;

#[test]
fn poll_error_unrelated_to_interruption_propagates() -> Result {
    const MESSAGE: &str = "boom from poll";

    let poll = PollScript::new([Err(io::Error::other(MESSAGE))]);
    let mut device = MockDevice::new([])?;

    assert_matches!(
        run_test_server(
            TcpConnections::default(),
            &mut device,
            |_, _| poll.next(),
            || false,
            ONE_YEAR_GRACE_PERIOD,
        ),
        Err(e) if e.to_string().contains(MESSAGE),
        "A non-interrupt poll error should propagate"
    );

    Ok(())
}

#[test]
fn read_error_unrelated_to_interruption_propagates() -> Result {
    const MESSAGE: &str = "boom from read";

    let poll = PollScript::new([Ok(true)]);
    let mut device = MockDevice::new([Err(io::Error::other(MESSAGE))])?;

    assert_matches!(
        run_test_server(
            TcpConnections::default(),
            &mut device,
            |_, _| poll.next(),
            || false,
            ONE_YEAR_GRACE_PERIOD,
        ),
        Err(e) if e.to_string().contains(MESSAGE),
        "A non-interrupt read error should propagate"
    );

    Ok(())
}

#[test]
fn write_failure_while_sending_fin_ack_propagates() -> Result {
    const MESSAGE: &str = "boom from write";

    let poll = PollScript::new([Err(io::ErrorKind::Interrupted.into())]);
    let mut device = MockDevice::new([])?.fail_writes(MESSAGE);

    assert_matches!(
        run_test_server(
            TcpConnections::after_handshake(),
            &mut device,
            |_, _| poll.next(),
            || true,
            ONE_YEAR_GRACE_PERIOD,
        ),
        Err(e) if e.to_string().contains(MESSAGE),
        "A device write failure while closing connections should propagate"
    );

    Ok(())
}
