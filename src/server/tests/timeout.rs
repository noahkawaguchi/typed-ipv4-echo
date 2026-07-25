use super::*;

#[test]
fn poll_timeout_reflects_shutdown_deadline() -> Result {
    // Not asserting exact `Duration` values since they come from `Instant::now()`, just that the
    // timeout is unbounded before any shutdown signal and becomes bounded once draining starts

    let observed_timeouts = RefCell::new(Vec::new());
    let poll = PollScript::new([Err(io::ErrorKind::Interrupted.into()), Ok(false)]);
    let mut device = MockDevice::new([])?;

    run_test_server(
        TcpConnections::after_handshake(),
        &mut device,
        |_, timeout| {
            observed_timeouts
                .try_borrow_mut()
                .map_err(io::Error::other)?
                .push(timeout);

            poll.next()
        },
        || true,
        IMMEDIATE_GRACE_PERIOD,
    )?;

    assert_matches!(
        observed_timeouts.into_inner().as_slice(),
        [None, Some(_)],
        "No timeout before the interrupt, then some timeout once draining begins"
    );

    Ok(())
}
