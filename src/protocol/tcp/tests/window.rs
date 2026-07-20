use super::*;

#[test]
fn new_ack_adopts_window_from_segment() -> Result {
    // A "new" ack (SND.UNA < SEG.ACK <= SND.NXT) should also update SND.WND to the incoming
    // segment's advertised window (RFC 9293, Section 3.10.7.4), not just leave it at whatever it
    // was seeded with at handshake time.

    const NEW_WND: u16 = 12_345;

    let mut connections = TcpConnections::after_handshake();
    let mut cloned_state = connections.try_get()?.clone();

    assert_ne!(
        cloned_state.window_state.map(|win| win.snd_wnd),
        Some(NEW_WND),
        "The initial send window must differ from the updated one for the test to be meaningful"
    );

    // "Hello" data, ack=SERVER_ISN+1 == current SND.UNA, so not yet a "new" ack -> SND.NXT advances
    // to SERVER_ISN+6, but SND.WND stays untouched
    TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE,
        payload: payload_from("Hello"),
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    cloned_state.snd_nxt.advance_by(HELLO_LEN);
    cloned_state.rcv_nxt.advance_by(HELLO_LEN);

    assert_eq!(connections.try_get()?, &cloned_state, "State confirmation before window update");

    // Pure ACK of that echo, ack=SERVER_ISN+6 (now "new"), advertising a new window
    let window_update = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE + HELLO_LEN,
        ack_num: SERVER_ISN + SYN_BYTE + HELLO_LEN,
        window: NEW_WND,
        ..CLIENT_PACKET
    };

    assert_eq!(window_update.create_reply(&mut connections)?, None);

    cloned_state.snd_una.advance_by(HELLO_LEN);
    cloned_state.window_state = Some(WindowState {
        snd_wnd: NEW_WND,
        snd_wl1: window_update.seq_num,
        snd_wl2: window_update.ack_num,
    });

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "SND.WND should adopt the new segment's advertised window"
    );

    Ok(())
}

#[test]
fn stale_segment_does_not_clobber_send_window() -> Result {
    // A retransmitted/out-of-order segment can still carry a "new" ack_num (SND.UNA < SEG.ACK <=
    // SND.NXT is about cumulative acknowledgment, not about the segment being in order), but per
    // RFC 9293, Section 3.10.7.4, SND.WND must only adopt a segment's window when SND.WL1 < SEG.SEQ
    // or (SND.WL1 == SEG.SEQ and SND.WL2 <= SEG.ACK), preventing this kind of old segment from
    // clobbering it with stale data.

    let mut connections = TcpConnections::after_handshake();
    let mut cloned_state = connections.try_get()?.clone();

    // "Hello" data, ack=SERVER_ISN+1 == current SND.UNA -> RCV.NXT advances to CLIENT_ISN+6,
    // SND.NXT advances to SERVER_ISN+6, leaving room below for a "new" ACK
    TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE,
        payload: payload_from("Hello"),
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    cloned_state.snd_nxt.advance_by(HELLO_LEN);
    cloned_state.rcv_nxt.advance_by(HELLO_LEN);

    assert_eq!(connections.try_get()?, &cloned_state, "State confirmation before window update");

    // Pure ACK with seq=CLIENT_ISN+6, fresher than the handshake's SND.WL1=CLIENT_ISN+1, so this
    // legitimately updates SND.WND/SND.WL1/SND.WL2 as if it were the last segment to do so before
    // the stale duplicate below arrives
    let fresh_window_update = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE + HELLO_LEN,
        ack_num: SERVER_ISN + SYN_BYTE,
        window: 1000,
        ..CLIENT_PACKET
    };

    assert_eq!(fresh_window_update.create_reply(&mut connections)?, None);

    cloned_state.window_state = Some(WindowState {
        snd_wnd: 1000,
        snd_wl1: fresh_window_update.seq_num,
        snd_wl2: fresh_window_update.ack_num,
    });

    assert_eq!(connections.try_get()?, &cloned_state, "First window update should be adopted");

    // Stale SEG.SEQ duplicates that of the original "Hello" segment, but SEG.ACK is exactly
    // SND.NXT, satisfying the "new ACK" check on its own, and it has a different window
    assert_eq!(
        TcpHandler {
            seq_num: CLIENT_ISN + SYN_BYTE,
            ack_num: SERVER_ISN + SYN_BYTE + HELLO_LEN,
            window: 65_000,
            ..CLIENT_PACKET
        }
        .create_reply(&mut connections)?,
        None
    );

    cloned_state.snd_una.advance_by(HELLO_LEN);

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "SND.WND must not adopt the stale segment's window despite SEG.ACK being new"
    );

    Ok(())
}

#[test]
fn same_seq_but_fresher_ack_updates_window() -> Result {
    // The window update condition is "SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =<
    // SEG.ACK)" (RFC 9293, Section 3.10.7.4). The equal-SEQ branch matters for pure ACKs, which
    // don't consume sequence numbers. Two of them in a row can carry the exact same SEG.SEQ while
    // still acknowledging more data than the last (e.g. a keep-alive style followup ack), and the
    // second one must still be allowed to update SND.WND.

    let mut connections = TcpConnections::after_handshake();
    let mut cloned_state = connections.try_get()?.clone();

    // Two data packets build up room for cumulative ACKs without ever giving the client's own
    // seq_num a chance to move past CLIENT_ISN+8 again
    TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE,
        payload: payload_from("Hello"),
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    cloned_state.snd_nxt.advance_by(HELLO_LEN);
    cloned_state.rcv_nxt.advance_by(HELLO_LEN);
    assert_eq!(connections.try_get()?, &cloned_state);

    let hi_packet = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE + HELLO_LEN,
        ack_num: SERVER_ISN + SYN_BYTE,
        payload: payload_from("Hi"),
        ..CLIENT_PACKET
    };

    hi_packet.create_reply(&mut connections)?;

    cloned_state.snd_nxt.advance_by(HI_LEN);
    cloned_state.rcv_nxt.advance_by(HI_LEN);
    cloned_state.window_state = Some(WindowState {
        snd_wnd: CLIENT_PACKET.window,
        snd_wl1: hi_packet.seq_num,
        snd_wl2: hi_packet.ack_num,
    });

    assert_eq!(connections.try_get()?, &cloned_state);

    // First pure ACK with seq=CLIENT_ISN+8 is fresher than the handshake's SND.WL1=CLIENT_ISN+1, so
    // this legitimately sets SND.WL1=CLIENT_ISN+8, SND.WL2=SERVER_ISN+6
    let window_update_1 = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE + HELLO_LEN + HI_LEN,
        ack_num: SERVER_ISN + SYN_BYTE + HELLO_LEN,
        window: 1000,
        ..CLIENT_PACKET
    };

    assert_eq!(window_update_1.create_reply(&mut connections)?, None);

    cloned_state.snd_una.advance_by(HELLO_LEN);
    cloned_state.window_state = Some(WindowState {
        snd_wnd: 1000,
        snd_wl1: window_update_1.seq_num,
        snd_wl2: window_update_1.ack_num,
    });

    assert_eq!(connections.try_get()?, &cloned_state, "First window update should be adopted");

    // Second pure ACK with identical seq_num (no new data sent), but a strictly higher ack_num and
    // a different window
    let window_update_2 = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE + HELLO_LEN + HI_LEN,
        ack_num: SERVER_ISN + SYN_BYTE + HELLO_LEN + HI_LEN,
        window: 2000,
        ..CLIENT_PACKET
    };

    assert_eq!(window_update_2.create_reply(&mut connections)?, None);

    cloned_state.snd_una.advance_by(HI_LEN);
    cloned_state.window_state = Some(WindowState {
        snd_wnd: 2000,
        snd_wl1: window_update_2.seq_num,
        snd_wl2: window_update_2.ack_num,
    });

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "SND.WND should still update when SEQ repeats but ACK is fresher"
    );

    Ok(())
}

#[test]
fn duplicate_ack_updates_window() -> Result {
    // RFC 9293, Section 3.10.7.4 gives two different conditions: SND.UNA only advances on a
    // "new" ACK (SND.UNA < SEG.ACK <= SND.NXT), but the send window update uses the non-strict
    // SND.UNA <= SEG.ACK <= SND.NXT. A duplicate ACK (SEG.ACK == SND.UNA) must still be allowed
    // to update SND.WND, such as a window-opening segment that doesn't acknowledge any new data.

    const NEW_WND: u16 = 777;

    // SND.UNA=SND.NXT=SERVER_ISN+1, RCV.NXT=CLIENT_ISN+1
    let mut connections = TcpConnections::after_handshake();
    let mut cloned_state = connections.try_get()?.clone();

    assert_ne!(
        cloned_state.window_state.map(|win| win.snd_wnd),
        Some(NEW_WND),
        "The initial send window must differ from the updated one for the test to be meaningful"
    );

    // "Hello" data, ack=SERVER_ISN+1 == current SND.UNA (not a "new" ACK) -> RCV.NXT advances to
    // CLIENT_ISN+6, SND.NXT advances to SERVER_ISN+6, SND.UNA stays at SERVER_ISN+1
    TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE,
        payload: payload_from("Hello"),
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    cloned_state.snd_nxt.advance_by(HELLO_LEN);
    cloned_state.rcv_nxt.advance_by(HELLO_LEN);

    assert_eq!(connections.try_get()?, &cloned_state, "State confirmation before window update");

    // Duplicate ACK where ack_num=SERVER_ISN+1 still equals SND.UNA (nothing new acknowledged), but
    // seq_num=CLIENT_ISN+6 is fresher than the stored SND.WL1=CLIENT_ISN+1, so this must still
    // update SND.WND to the new window
    let dup_ack_fresh_seq = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE + HELLO_LEN,
        ack_num: SERVER_ISN + SYN_BYTE,
        window: NEW_WND,
        ..CLIENT_PACKET
    };

    assert_eq!(dup_ack_fresh_seq.create_reply(&mut connections)?, None);

    cloned_state.window_state = Some(WindowState {
        snd_wnd: NEW_WND,
        snd_wl1: dup_ack_fresh_seq.seq_num,
        snd_wl2: dup_ack_fresh_seq.ack_num,
    });

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "SND.WND should update on a duplicate ack (SEG.ACK == SND.UNA) as long as SND.WL1 and \
         SND.WL2 allow it"
    );

    Ok(())
}
