use super::*;

#[test]
fn neither_deadline_gives_no_timeout() {
    assert_eq!(decision_test_server().poll_timeout(Instant::now()), None);
}

#[test]
fn shutdown_deadline_alone_gives_its_duration() -> Result {
    let now = Instant::now();
    let duration = Duration::from_secs(10);
    let deadline = now.checked_add(duration).ok_or("overflow")?;

    assert_eq!(
        Server { shutdown_deadline: Some(deadline), ..decision_test_server() }.poll_timeout(now),
        Some(duration)
    );

    Ok(())
}

#[test]
fn pending_retransmission_alone_gives_some_timeout() {
    // `Instant::now()` is currently called internally for the retransmissions, so assert an
    // approximate range

    assert_matches!(
        Server {
            tcp_connections: TcpConnections::new(Duration::from_millis(500), 5).with_syn_rcv(),
            ..decision_test_server()
        }
        .poll_timeout(Instant::now()),
        Some(d) if d > Duration::from_millis(400) && d < Duration::from_millis(600)
    );
}

#[test]
fn earlier_retransmit_deadline_taken_over_later_shutdown_deadline() -> Result {
    let now = Instant::now();
    let in_30s = now.checked_add(Duration::from_secs(30)).ok_or("overflow")?;

    assert_matches!(
        Server {
            tcp_connections: TcpConnections::new(Duration::from_millis(250), 5).with_syn_rcv(),
            shutdown_deadline: Some(in_30s),
            ..decision_test_server()
        }
        .poll_timeout(now),
        Some(d) if d < Duration::from_secs(1),
        "The near-term retransmit deadline should win the `min`, not the far future shutdown \
        deadline"
    );

    Ok(())
}

#[test]
fn earlier_shutdown_deadline_taken_over_later_retransmit_deadline() -> Result {
    const GRACE_PERIOD: Duration = Duration::from_millis(250);

    let now = Instant::now();
    let in_250ms = now.checked_add(GRACE_PERIOD).ok_or("overflow")?;

    assert_eq!(
        Server {
            tcp_connections: TcpConnections::new(Duration::from_secs(30), 5).with_syn_rcv(),
            shutdown_deadline: Some(in_250ms),
            ..decision_test_server()
        }
        .poll_timeout(now),
        Some(GRACE_PERIOD),
        "The near-term shutdown deadline should win the `min`, not the far future retransmit \
         deadline"
    );

    Ok(())
}

#[test]
fn passed_deadline_saturates_to_zero() -> Result {
    let now = Instant::now();
    let past = now.checked_sub(Duration::from_secs(5)).ok_or("underflow")?;

    assert_eq!(
        Server { shutdown_deadline: Some(past), ..decision_test_server() }.poll_timeout(now),
        Some(Duration::ZERO)
    );

    Ok(())
}

#[test]
fn poll_timeout_reflects_shutdown_deadline_across_a_real_run() -> Result {
    // Showing here that the loop actually uses the computed timeout when polling, and that the
    // grace period being elapsed actually ends the loop.
    //
    // Not asserting exact `Duration` values since they come from `Instant::now()`, just that the
    // timeout is unbounded before any shutdown signal and becomes bounded (and, with an immediate
    // grace period, causes exit) once draining starts.

    let observed_timeouts = RefCell::new(Vec::new());
    let poll = MockPoll::new([Err(io::ErrorKind::Interrupted.into()), Ok(false)]);
    let mut device = MockDevice::new([])?;

    run_test_server(
        TcpConnections::default().after_handshake(),
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
