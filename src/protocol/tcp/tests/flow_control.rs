use super::*;

/// Creates a `ConnState` that is the same as `AFTER_HANDSHAKE` except for a custom `snd_wnd`.
fn after_handshake_with_snd_wnd(snd_wnd: SeqOffset<u16, Local>) -> ConnState {
    ConnState {
        tcp_state: TcpState::Established(SyncedState::test_new(WindowState::test_new(
            snd_wnd,
            CLIENT_ISN + REMOTE_SYN_BYTE,
            SERVER_ISN + LOCAL_SYN_BYTE,
        ))),
        ..AFTER_HANDSHAKE
    }
}

#[test]
fn small_window_truncates_echoed_payload_and_buffers_the_rest() -> Result {
    const WINDOW: SeqOffset<u16, Local> = SeqOffset::new(3);

    let mut connections = TcpConnections::default();
    let mut expected_state = after_handshake_with_snd_wnd(WINDOW);
    connections.insert(expected_state.clone());

    let reply = TcpHandler {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        window: WINDOW,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpHandler {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
            payload: TcpPayload::from_test_str("Hel")?,
            ..SERVER_REPLY
        }),
        "Only the first 3 bytes fit in the advertised window of 3"
    );

    expected_state.snd_nxt += WINDOW.into();
    expected_state.rcv_nxt += REMOTE_HELLO_LEN;
    expected_state.send_buffer.extend(b"lo");

    assert_eq!(
        connections.try_get()?,
        &expected_state,
        "SND.NXT should advance only by what was sent, and the rest should be buffered"
    );

    Ok(())
}

#[test]
fn unacked_bytes_count_toward_room_left_in_send_window() -> Result {
    // The room left in the send window must account for bytes already sent but not yet
    // acknowledged, not just use the advertised window size as is. (In other tests where there are
    // zero unacked bytes, using the window directly without considering SND.NXT and SND.UNA would
    // pass.)

    const WINDOW: SeqOffset<u16, Local> = SeqOffset::new(3);

    let mut connections = TcpConnections::default();
    let mut expected_state = after_handshake_with_snd_wnd(WINDOW);
    connections.insert(expected_state.clone());

    // "Hello" (5 bytes), window only allows 3 -> "Hel" sent (SND.NXT advances by 3, SND.UNA stays
    // put), "lo" buffered. 3 bytes are now sent but unacked.
    TcpHandler {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        window: WINDOW,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    expected_state.snd_nxt += WINDOW.into();
    expected_state.rcv_nxt += REMOTE_HELLO_LEN;
    expected_state.send_buffer.extend(b"lo");

    {
        let state = connections.try_get()?;
        assert_eq!(state, &expected_state, "State confirmation before the dup ACK");
        assert!(
            state.snd_una.precedes(state.snd_nxt),
            "Bytes must be sent but unacked for this test to be meaningful"
        );
    }

    // A duplicate ACK (SEG.ACK == SND.UNA, so nothing new is acknowledged) that only refreshes
    // SND.WND, still at 3. With 3 bytes already sent but unacked and a window of 3, there is no
    // room left, so the buffered "lo" must stay buffered.
    let dup_ack_same_window = TcpHandler {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        window: WINDOW,
        ..CLIENT_PACKET
    };

    assert_eq!(
        dup_ack_same_window.create_reply(&mut connections)?,
        None,
        "No room left in the window while the first 3 bytes remain unacked"
    );

    expected_state.tcp_state = TcpState::Established(SyncedState::test_new(WindowState::test_new(
        dup_ack_same_window.window,
        dup_ack_same_window.seq_num,
        dup_ack_same_window.ack_num,
    )));

    assert_eq!(
        connections.try_get()?,
        &expected_state,
        "SND.UNA and the send buffer should be unchanged with only SND.WL1/SND.WL2 refreshed"
    );

    Ok(())
}

#[test]
fn window_opening_via_ack_drains_buffered_remainder() -> Result {
    const HEL_LEN: SeqOffset<u32, Local> = SeqOffset::new(3);
    const LO_LEN: SeqOffset<u32, Local> = SeqOffset::new(2);

    const INITIAL_WINDOW: SeqOffset<u16, Local> = SeqOffset::new(3);
    const LARGER_WINDOW: SeqOffset<u16, Local> = SeqOffset::new(10);

    let mut connections = TcpConnections::default();
    let mut expected_state = after_handshake_with_snd_wnd(INITIAL_WINDOW);
    connections.insert(expected_state.clone());

    // "Hello" (5 bytes), window only allows 3 -> "Hel" sent, "lo" buffered
    TcpHandler {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        window: INITIAL_WINDOW,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    expected_state.snd_nxt += HEL_LEN;
    expected_state.rcv_nxt += REMOTE_HELLO_LEN;
    expected_state.send_buffer.extend(b"lo");

    assert_eq!(connections.try_get()?, &expected_state, "State confirmation before window update");

    // Client acks the 3 sent bytes and advertises a bigger window -> should drain "lo"
    let window_update = TcpHandler {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE + HEL_LEN,
        window: LARGER_WINDOW,
        ..CLIENT_PACKET
    };

    let reply = window_update.create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpHandler {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE + HEL_LEN,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
            payload: TcpPayload::from_test_str("lo")?,
            ..SERVER_REPLY
        }),
        "The buffered remainder should drain once the window opens, piggybacked on the next ACK"
    );

    expected_state.snd_una += HEL_LEN;
    expected_state.snd_nxt += LO_LEN;
    expected_state.tcp_state = TcpState::Established(SyncedState::test_new(WindowState::test_new(
        LARGER_WINDOW,
        window_update.seq_num,
        window_update.ack_num,
    )));
    expected_state.send_buffer.clear();

    assert_eq!(
        connections.try_get()?,
        &expected_state,
        "All bytes should have fully drained from the buffer"
    );

    Ok(())
}

#[test]
fn zero_window_buffers_entire_payload_and_gets_bare_ack() -> Result {
    const ZERO_WINDOW: SeqOffset<u16, Local> = SeqOffset::new(0);

    let mut connections = TcpConnections::default();
    let mut expected_state = after_handshake_with_snd_wnd(ZERO_WINDOW);
    connections.insert(expected_state.clone());

    let reply = TcpHandler {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        window: ZERO_WINDOW,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpHandler {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
            ..SERVER_REPLY
        }),
        "A closed window still gets a bare ACK for the receipt, just no echoed payload"
    );

    expected_state.rcv_nxt += REMOTE_HELLO_LEN;
    expected_state.send_buffer.extend(b"Hello");

    assert_eq!(
        connections.try_get()?,
        &expected_state,
        "Since nothing was sent, SND.NXT shouldn't advance, and the whole payload should be \
         buffered"
    );

    Ok(())
}
