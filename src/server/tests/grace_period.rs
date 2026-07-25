use super::*;

#[test]
fn grace_period_not_elapsed_with_no_deadline() -> Result {
    let mut device = MockDevice::new([])?;
    let server = decision_test_server(&mut device);
    assert!(!server.grace_period_elapsed(Instant::now()));
    Ok(())
}

#[test]
fn grace_period_not_elapsed_before_deadline() -> Result {
    let mut device = MockDevice::new([])?;
    let now = Instant::now();
    let deadline = now.checked_add(Duration::from_secs(10)).ok_or("overflow")?;

    assert!(
        !Server { shutdown_deadline: Some(deadline), ..decision_test_server(&mut device) }
            .grace_period_elapsed(now)
    );

    Ok(())
}

#[test]
fn grace_period_elapsed_past_deadline() -> Result {
    let mut device = MockDevice::new([])?;
    let now = Instant::now();
    let deadline = now
        .checked_sub(Duration::from_secs(10))
        .ok_or("underflow")?;

    assert!(
        Server { shutdown_deadline: Some(deadline), ..decision_test_server(&mut device) }
            .grace_period_elapsed(now)
    );

    Ok(())
}

#[test]
fn grace_period_elapsed_at_deadline() -> Result {
    let mut device = MockDevice::new([])?;
    let now = Instant::now();

    assert!(
        Server { shutdown_deadline: Some(now), ..decision_test_server(&mut device) }
            .grace_period_elapsed(now)
    );

    Ok(())
}
