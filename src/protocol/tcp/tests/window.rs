use super::*;

/// Creates a pure ACK packet from the client with a custom window size.
fn custom_window_client_packet(seq_num: u32, ack_num: u32, window: u16) -> TcpHandler {
    TcpHandler {
        ip_pair: Ipv4AddrPair { src: KEY.client_ip, dst: KEY.server_ip },
        ports: PortPair { src: KEY.client_port, dst: KEY.server_port },
        seq_num,
        ack_num,
        offset_bytes: 20,
        flags: TcpFlags::Ack,
        window,
        payload: None,
    }
}

#[test]
fn new_ack_adopts_window_from_segment() -> Result<()> {
    // A "new" ack (SND.UNA < SEG.ACK <= SND.NXT) should also update SND.WND to the incoming
    // segment's advertised window (RFC 9293, Section 3.10.7.4), not just leave it at whatever it
    // was seeded with at handshake time.

    const NEW_WND: u16 = 12_345;

    let mut connections = TcpConnections::default();
    connections.insert_established();
    assert_ne!(
        connections.try_get()?.snd_wnd,
        NEW_WND,
        "The initial send window must differ from the updated one for the test to be valid"
    );

    // "Hello" data, ack=SERVER_ISN+1 == current SND.UNA, so not yet a "new" ack -> SND.NXT advances
    // to SERVER_ISN+6, but SND.WND stays untouched
    client_packet(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE, TcpFlags::Ack, b"Hello")
        .create_reply(&mut connections)?;

    // Pure ACK of that echo, ack=SERVER_ISN+6 (now "new"), advertising a new window
    assert_eq!(
        custom_window_client_packet(
            CLIENT_ISN + SYN_BYTE + HELLO_LEN,
            SERVER_ISN + SYN_BYTE + HELLO_LEN,
            NEW_WND,
        )
        .create_reply(&mut connections)?,
        None
    );

    assert_eq!(
        connections.try_get()?.snd_wnd,
        NEW_WND,
        "SND.WND should adopt the new segment's advertised window"
    );

    Ok(())
}

#[test]
fn stale_segment_does_not_clobber_send_window() -> Result<()> {
    // A retransmitted/out-of-order segment can still carry a "new" ack_num (SND.UNA < SEG.ACK <=
    // SND.NXT is about cumulative acknowledgment, not about the segment being in order), but per
    // RFC 9293, Section 3.10.7.4, SND.WND must only adopt a segment's window when SND.WL1 < SEG.SEQ
    // or (SND.WL1 == SEG.SEQ and SND.WL2 <= SEG.ACK), preventing this kind of old segment from
    // clobbering it with stale data.

    let mut connections = TcpConnections::default();
    connections.insert_established();

    // "Hello" data, ack=SERVER_ISN+1 == current SND.UNA -> RCV.NXT advances to CLIENT_ISN+6,
    // SND.NXT advances to SERVER_ISN+6, leaving room below for a "new" ACK
    client_packet(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE, TcpFlags::Ack, b"Hello")
        .create_reply(&mut connections)?;

    // Pure ACK with seq=CLIENT_ISN+6, fresher than the handshake's SND.WL1=CLIENT_ISN+1, so this
    // legitimately updates SND.WND/SND.WL1/SND.WL2 as if it were the last segment to do so before
    // the stale duplicate below arrives
    assert_eq!(
        custom_window_client_packet(CLIENT_ISN + SYN_BYTE + HELLO_LEN, SERVER_ISN + SYN_BYTE, 1000)
            .create_reply(&mut connections)?,
        None
    );

    assert_eq!(connections.try_get()?.snd_wnd, 1000, "Sanity check on the setup");

    // Stale SEG.SEQ duplicates that of the original "Hello" segment, but SEG.ACK is exactly
    // SND.NXT, satisfying the "new ACK" check on its own, and it has a different window
    assert_eq!(
        custom_window_client_packet(
            CLIENT_ISN + SYN_BYTE,
            SERVER_ISN + SYN_BYTE + HELLO_LEN,
            65_000
        )
        .create_reply(&mut connections)?,
        None
    );

    assert_eq!(
        connections.try_get()?.snd_wnd,
        1000,
        "SND.WND must not adopt the stale segment's window despite SEG.ACK being new"
    );

    Ok(())
}

#[test]
fn same_seq_but_fresher_ack_updates_window() -> Result<()> {
    // The window update condition is "SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =<
    // SEG.ACK)" (RFC 9293, Section 3.10.7.4). The equal-SEQ branch matters for pure ACKs, which
    // don't consume sequence numbers. Two of them in a row can carry the exact same SEG.SEQ while
    // still acknowledging more data than the last (e.g. a keep-alive style followup ack), and the
    // second one must still be allowed to update SND.WND.

    let mut connections = TcpConnections::default();
    connections.insert_established();

    // Two data packets build up room for cumulative ACKs without ever giving the client's own
    // seq_num a chance to move past CLIENT_ISN+8 again
    client_packet(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE, TcpFlags::Ack, b"Hello")
        .create_reply(&mut connections)?;
    client_packet(CLIENT_ISN + SYN_BYTE + HELLO_LEN, SERVER_ISN + SYN_BYTE, TcpFlags::Ack, b"Hi")
        .create_reply(&mut connections)?;

    // First pure ACK with seq=CLIENT_ISN+8 is fresher than the handshake's SND.WL1=CLIENT_ISN+1, so
    // this legitimately sets SND.WL1=CLIENT_ISN+8, SND.WL2=SERVER_ISN+6
    assert_eq!(
        custom_window_client_packet(
            CLIENT_ISN + SYN_BYTE + HELLO_LEN + HI_LEN,
            SERVER_ISN + SYN_BYTE + HELLO_LEN,
            1000,
        )
        .create_reply(&mut connections)?,
        None
    );

    assert_eq!(connections.try_get()?.snd_wnd, 1000, "Sanity check on the first update");

    // Second pure ACK with identical seq_num (no new data sent), but a strictly higher ack_num and
    // a different window
    assert_eq!(
        custom_window_client_packet(
            CLIENT_ISN + SYN_BYTE + HELLO_LEN + HI_LEN,
            SERVER_ISN + SYN_BYTE + HELLO_LEN + HI_LEN,
            2000,
        )
        .create_reply(&mut connections)?,
        None
    );

    assert_eq!(
        connections.try_get()?.snd_wnd,
        2000,
        "SND.WND should still update when SEQ repeats but ACK is fresher"
    );

    Ok(())
}

#[test]
fn duplicate_ack_updates_window() -> Result<()> {
    // RFC 9293, Section 3.10.7.4 gives two different conditions: SND.UNA only advances on a
    // "new" ACK (SND.UNA < SEG.ACK <= SND.NXT), but the send window update uses the non-strict
    // SND.UNA <= SEG.ACK <= SND.NXT. A duplicate ACK (SEG.ACK == SND.UNA) must still be allowed
    // to update SND.WND, such as a window-opening segment that doesn't acknowledge any new data.

    const NEW_WND: u16 = 777;

    let mut connections = TcpConnections::default();
    connections.insert_established(); // SND.UNA=SND.NXT=SERVER_ISN+1, RCV.NXT=CLIENT_ISN+1
    assert_ne!(
        connections.try_get()?.snd_wnd,
        NEW_WND,
        "The initial send window must differ from the updated one for the test to be valid"
    );

    // "Hello" data, ack=SERVER_ISN+1 == current SND.UNA (not a "new" ACK) -> RCV.NXT advances to
    // CLIENT_ISN+6, SND.NXT advances to SERVER_ISN+6, SND.UNA stays at SERVER_ISN+1
    client_packet(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE, TcpFlags::Ack, b"Hello")
        .create_reply(&mut connections)?;

    // Duplicate ACK where ack_num=SERVER_ISN+1 still equals SND.UNA (nothing new acknowledged), but
    // seq_num=CLIENT_ISN+6 is fresher than the stored SND.WL1=CLIENT_ISN+1, so this must still
    // update SND.WND to the new window
    assert_eq!(
        custom_window_client_packet(
            CLIENT_ISN + SYN_BYTE + HELLO_LEN,
            SERVER_ISN + SYN_BYTE,
            NEW_WND
        )
        .create_reply(&mut connections)?,
        None
    );

    assert_eq!(
        connections.try_get()?.snd_wnd,
        NEW_WND,
        "SND.WND should update on a duplicate ack (SEG.ACK == SND.UNA) as long as SND.WL1 and \
         SND.WL2 allow it"
    );

    Ok(())
}
