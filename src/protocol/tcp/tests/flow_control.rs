use super::*;

/// Creates a `ConnState` that is the same as `AFTER_HANDSHAKE` except for a custom `snd_wnd`.
fn after_handshake_with_snd_wnd(snd_wnd: SeqDist<u16>) -> ConnState {
    ConnState {
        window_state: Some(WindowState {
            snd_wnd,
            snd_wl1: CLIENT_ISN + SYN_BYTE,
            snd_wl2: SERVER_ISN + SYN_BYTE,
        }),
        ..AFTER_HANDSHAKE
    }
}

#[test]
fn small_window_truncates_echoed_payload_and_buffers_the_rest() -> Result {
    const WINDOW: SeqDist<u16> = SeqDist::new(3);

    let mut connections = TcpConnections::default();
    let mut expected_state = after_handshake_with_snd_wnd(WINDOW);
    connections.insert(expected_state.clone());

    let reply = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE,
        window: WINDOW,
        payload: payload_from("Hello")?,
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpHandler {
            seq_num: SERVER_ISN + SYN_BYTE,
            ack_num: CLIENT_ISN + SYN_BYTE + HELLO_LEN,
            payload: payload_from("Hel")?,
            ..SERVER_REPLY
        }),
        "Only the first 3 bytes fit in the advertised window of 3"
    );

    expected_state.snd_nxt += WINDOW.into();
    expected_state.rcv_nxt += HELLO_LEN;
    expected_state.send_buffer.extend(b"lo");

    assert_eq!(
        connections.try_get()?,
        &expected_state,
        "SND.NXT should advance only by what was sent, and the rest should be buffered"
    );

    Ok(())
}

#[test]
fn window_opening_via_ack_drains_buffered_remainder() -> Result {
    const HEL_LEN: SeqDist<u32> = SeqDist::new(3);
    const INITIAL_WINDOW: SeqDist<u16> = SeqDist::new(3);
    const LARGER_WINDOW: SeqDist<u16> = SeqDist::new(10);

    let mut connections = TcpConnections::default();
    let mut expected_state = after_handshake_with_snd_wnd(INITIAL_WINDOW);
    connections.insert(expected_state.clone());

    // "Hello" (5 bytes), window only allows 3 -> "Hel" sent, "lo" buffered
    TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE,
        window: INITIAL_WINDOW,
        payload: payload_from("Hello")?,
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    expected_state.snd_nxt += HEL_LEN;
    expected_state.rcv_nxt += HELLO_LEN;
    expected_state.send_buffer.extend(b"lo");

    assert_eq!(connections.try_get()?, &expected_state, "State confirmation before window update");

    // Client acks the 3 sent bytes and advertises a bigger window -> should drain "lo"
    let window_update = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE + HELLO_LEN,
        ack_num: SERVER_ISN + SYN_BYTE + HEL_LEN,
        window: LARGER_WINDOW,
        ..CLIENT_PACKET
    };

    let reply = window_update.create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpHandler {
            seq_num: SERVER_ISN + SYN_BYTE + HEL_LEN,
            ack_num: CLIENT_ISN + SYN_BYTE + HELLO_LEN,
            payload: payload_from("lo")?,
            ..SERVER_REPLY
        }),
        "The buffered remainder should drain once the window opens, piggybacked on the next ACK"
    );

    expected_state.snd_una += HEL_LEN;
    expected_state.snd_nxt += HELLO_LEN - HEL_LEN;
    expected_state.window_state = Some(WindowState {
        snd_wnd: LARGER_WINDOW,
        snd_wl1: window_update.seq_num,
        snd_wl2: window_update.ack_num,
    });
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
    const ZERO_WINDOW: SeqDist<u16> = SeqDist::new(0);

    let mut connections = TcpConnections::default();
    let mut expected_state = after_handshake_with_snd_wnd(ZERO_WINDOW);
    connections.insert(expected_state.clone());

    let reply = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE,
        window: ZERO_WINDOW,
        payload: payload_from("Hello")?,
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpHandler {
            seq_num: SERVER_ISN + SYN_BYTE,
            ack_num: CLIENT_ISN + SYN_BYTE + HELLO_LEN,
            ..SERVER_REPLY
        }),
        "A closed window still gets a bare ACK for the receipt, just no echoed payload"
    );

    expected_state.rcv_nxt += HELLO_LEN;
    expected_state.send_buffer.extend(b"Hello");

    assert_eq!(
        connections.try_get()?,
        &expected_state,
        "Since nothing was sent, SND.NXT shouldn't advance, and the whole payload should be \
         buffered"
    );

    Ok(())
}
