use super::*;

#[test]
fn poll_timeout_reflects_shutdown_deadline() -> Result {
    // Not asserting exact `Duration` values since they come from `Instant::now()`, just that the
    // timeout is unbounded before any shutdown signal and becomes bounded once draining starts

    let observed_timeouts = RefCell::new(Vec::new());
    let poll = MockPoll::new([Err(io::ErrorKind::Interrupted.into()), Ok(false)]);
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

#[test]
fn poll_timeout_reflects_pending_retransmission() -> Result {
    // `with_syn_rcv` has a pending SYN-ACK segment from construction, with no interrupt or shutdown
    // deadline happening first, so a bounded timeout on the very first poll call must come from
    // that segment. Because the connection is in SYN-RECEIVED, there are no connections considered
    // to be mid-close, so the interrupt on the first poll call causes an immediate exit instead of
    // draining.

    let observed_timeouts = RefCell::new(Vec::new());
    let poll = MockPoll::new([Err(io::ErrorKind::Interrupted.into())]);
    let mut device = MockDevice::new([])?;

    run_test_server(
        TcpConnections::with_syn_rcv(),
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
        [Some(_)],
        "There should be a single bounded timeout from the pending SYN-ACK's retransmit deadline"
    );

    Ok(())
}
