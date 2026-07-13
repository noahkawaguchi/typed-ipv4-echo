use super::*;

/// Builds a data packet from the client with a custom advertised window (`client_packet` always
/// hardcodes `TcpHandler::RCV_WND`, which would clobber the small windows these tests rely on).
fn client_data_packet_with_window(
    seq_num: u32,
    ack_num: u32,
    window: u16,
    payload: &[u8],
) -> TcpHandler {
    TcpHandler {
        ip_pair: Ipv4AddrPair { src: KEY.client_ip, dst: KEY.server_ip },
        ports: PortPair { src: KEY.client_port, dst: KEY.server_port },
        seq_num,
        ack_num,
        offset_bytes: 20,
        flags: TcpFlags::Ack,
        window,
        payload: (!payload.is_empty()).then(|| Rc::from(payload)),
    }
}

#[test]
fn small_window_truncates_echoed_payload_and_buffers_the_rest() -> Result<()> {
    let mut connections = TcpConnections::default();
    let mut expected_state = ConnState { snd_wnd: 3, ..Default::default() };
    connections.insert(expected_state.clone());

    let reply =
        client_data_packet_with_window(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE, 3, b"Hello")
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
    let mut expected_state = ConnState { snd_wnd: 3, ..Default::default() };
    connections.insert(expected_state.clone());

    // "Hello" (5 bytes), window only allows 3 -> "Hel" sent, "lo" buffered
    client_data_packet_with_window(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE, 3, b"Hello")
        .create_reply(&mut connections)?;

    expected_state.snd_nxt.advance_by(3);
    expected_state.rcv_nxt.advance_by(HELLO_LEN);
    expected_state.send_buffer.extend(b"lo");

    assert_eq!(connections.try_get()?, &expected_state, "State confirmation before window update");

    // Client acks the 3 sent bytes and advertises a bigger window -> should drain "lo"
    let reply = custom_window_client_packet(
        CLIENT_ISN + SYN_BYTE + HELLO_LEN,
        SERVER_ISN + SYN_BYTE + 3,
        10,
    )
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
    let mut expected_state = ConnState { snd_wnd: 0, ..Default::default() };
    connections.insert(expected_state.clone());

    let reply =
        client_data_packet_with_window(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE, 0, b"Hello")
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
