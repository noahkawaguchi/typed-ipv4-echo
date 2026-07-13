use super::*;

#[test]
fn small_window_truncates_echoed_payload_and_buffers_the_rest() -> Result<()> {
    let mut connections = TcpConnections::default();
    let mut expected_state = ConnState { snd_wnd: 3, ..AFTER_HANDSHAKE };
    connections.insert(expected_state.clone());

    let reply = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE,
        window: 3,
        payload: payload_from("Hello"),
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(server_reply(
            SERVER_ISN + SYN_BYTE,
            CLIENT_ISN + SYN_BYTE + HELLO_LEN,
            TcpFlags::Ack,
            b"Hel",
        )),
        "Only the first 3 bytes fit in the advertised window of 3"
    );

    expected_state.snd_nxt.advance_by(3);
    expected_state.rcv_nxt.advance_by(HELLO_LEN);
    expected_state.send_buffer.extend(b"lo");

    assert_eq!(
        connections.try_get()?,
        &expected_state,
        "SND.NXT should advance only by what was sent, and the rest should be buffered"
    );

    Ok(())
}

#[test]
fn window_opening_via_ack_drains_buffered_remainder() -> Result<()> {
    let mut connections = TcpConnections::default();
    let mut expected_state = ConnState { snd_wnd: 3, ..AFTER_HANDSHAKE };
    connections.insert(expected_state.clone());

    // "Hello" (5 bytes), window only allows 3 -> "Hel" sent, "lo" buffered
    TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE,
        window: 3,
        payload: payload_from("Hello"),
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    expected_state.snd_nxt.advance_by(3);
    expected_state.rcv_nxt.advance_by(HELLO_LEN);
    expected_state.send_buffer.extend(b"lo");

    assert_eq!(connections.try_get()?, &expected_state, "State confirmation before window update");

    // Client acks the 3 sent bytes and advertises a bigger window -> should drain "lo"
    let reply = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE + HELLO_LEN,
        ack_num: SERVER_ISN + SYN_BYTE + 3,
        window: 10,
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(server_reply(
            SERVER_ISN + SYN_BYTE + 3,
            CLIENT_ISN + SYN_BYTE + HELLO_LEN,
            TcpFlags::Ack,
            b"lo",
        )),
        "The buffered remainder should drain once the window opens, piggybacked on the next ACK"
    );

    expected_state.snd_una.advance_by(3);
    expected_state.snd_wnd = 10;
    expected_state.snd_nxt.advance_by(2);
    expected_state.send_buffer.clear();

    assert_eq!(
        connections.try_get()?,
        &expected_state,
        "All bytes should have fully drained from the buffer"
    );

    Ok(())
}

#[test]
fn zero_window_buffers_entire_payload_and_gets_bare_ack() -> Result<()> {
    let mut connections = TcpConnections::default();
    let mut expected_state = ConnState { snd_wnd: 0, ..AFTER_HANDSHAKE };
    connections.insert(expected_state.clone());

    let reply = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE,
        window: 0,
        payload: payload_from("Hello"),
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(server_reply(
            SERVER_ISN + SYN_BYTE,
            CLIENT_ISN + SYN_BYTE + HELLO_LEN,
            TcpFlags::Ack,
            &[],
        )),
        "A closed window still gets a bare ACK for the receipt, just no echoed payload"
    );

    expected_state.rcv_nxt.advance_by(HELLO_LEN);
    expected_state.send_buffer.extend(b"Hello");

    assert_eq!(
        connections.try_get()?,
        &expected_state,
        "Since nothing was sent, SND.NXT shouldn't advance, and the whole payload should be \
         buffered"
    );

    Ok(())
}
