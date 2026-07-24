use super::*;

#[test]
fn malformed_packet_is_skipped_without_propagating_or_writing() -> Result {
    // 5 bytes is too short for even a minimal (20-byte) IPv4 header, so parsing fails and the
    // packet should just be logged and skipped. The second poll call is a shutdown signal, and
    // since there are no established connections, it ends the loop cleanly.

    let poll = PollScript::new([Ok(true), Err(io::ErrorKind::Interrupted.into())]);
    let mut device = MockDevice::new([Ok(vec![0u8; 5])])?;

    assert_matches!(
        run_test_server(
            TcpConnections::default(),
            &mut device,
            |_, _| poll.next(),
            || true,
            IMMEDIATE_GRACE_PERIOD,
        ),
        Ok(()),
        "A malformed packet error should not propagate"
    );

    assert!(device.writes().is_empty(), "A malformed packet should not produce a reply");

    Ok(())
}
