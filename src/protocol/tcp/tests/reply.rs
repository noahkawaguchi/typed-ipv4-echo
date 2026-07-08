use super::*;

#[test]
fn reply_creates_valid_syn_ack() -> Result<()> {
    let mut connections = TcpConnections::default();

    let reply = client_packet(CLIENT_ISN, 0, TcpFlags::Syn, &[]).create_reply(&mut connections)?;

    // seq_num is the random ISN that was stored in the connection table
    let stored_isn = connections.try_get()?.snd_una;

    assert_eq!(reply, Some(server_reply(stored_isn, CLIENT_ISN + SYN_BYTE, TcpFlags::SynAck, &[])));

    Ok(())
}

#[test]
fn duplicate_syn_during_syn_received_resends_same_syn_ack() -> Result<()> {
    // If our SYN-ACK is lost, the client's retransmission timer will resend its SYN. We must resend
    // the same SYN-ACK (same ISN), not RST the retry, and not generate a new ISN.

    let mut connections = TcpConnections::default();
    connections.insert_syn_recv(); // Simulate having already sent a SYN-ACK with ISN=SERVER_ISN
    let initial_state = connections.try_get()?.clone();

    let reply = client_packet(CLIENT_ISN, 0, TcpFlags::Syn, &[]).create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(server_reply(SERVER_ISN, CLIENT_ISN + SYN_BYTE, TcpFlags::SynAck, &[])),
        "Retransmitted SYN should get the same SYN-ACK resent, not a RST"
    );

    assert_eq!(
        connections.try_get()?,
        &initial_state,
        "State should remain SYN-RECEIVED, not reset or advance"
    );

    Ok(())
}

#[test]
fn stray_syn_out_of_window_on_established_gets_challenge_ack() -> Result<()> {
    // RFC 9293, Section 3.10.7.4, "First, check sequence number": a segment outside the receive
    // window gets a challenge ACK (<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>) and is dropped. "Fourth,
    // check the SYN bit" is not reached.

    let mut connections = TcpConnections::default();
    connections.insert_established(); // snd_nxt=SERVER_ISN+1, rcv_nxt=CLIENT_ISN+1
    let initial_state = connections.try_get()?.clone();

    // seq=CLIENT_ISN-20 < rcv_nxt=CLIENT_ISN+1, outside the receive window, caught at "First, check
    // sequence number"
    let reply =
        client_packet(CLIENT_ISN - 20, 0, TcpFlags::Syn, &[]).create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(server_reply(SERVER_ISN + SYN_BYTE, CLIENT_ISN + SYN_BYTE, TcpFlags::Ack, &[])),
        "Out-of-window stray SYN must produce a challenge ACK, not a RST"
    );

    assert_eq!(
        connections.try_get()?,
        &initial_state,
        "Out-of-window stray SYN must not destroy the connection"
    );

    Ok(())
}

#[test]
fn stray_syn_in_window_on_established_gets_challenge_ack() -> Result<()> {
    // RFC 9293, Section 3.10.7.4, "Fourth, check the SYN bit": for synchronized states, RFC 5961
    // (incorporated into RFC 9293) recommends a challenge ACK irrespective of the sequence number,
    // and the connection must not be reset.

    let mut connections = TcpConnections::default();
    connections.insert_established(); // snd_nxt=SERVER_ISN+1, rcv_nxt=CLIENT_ISN+1
    let initial_state = connections.try_get()?.clone();

    // seq=CLIENT_ISN+1 == rcv_nxt, inside the receive window, reaches "Fourth, check the SYN bit"
    let reply = client_packet(CLIENT_ISN + SYN_BYTE, 0, TcpFlags::Syn, &[])
        .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(server_reply(SERVER_ISN + SYN_BYTE, CLIENT_ISN + SYN_BYTE, TcpFlags::Ack, &[])),
        "In-window stray SYN must produce a challenge ACK, not a RST"
    );

    assert_eq!(
        connections.try_get()?,
        &initial_state,
        "In-window stray SYN must not destroy the connection"
    );

    Ok(())
}

#[test]
fn stray_syn_in_window_on_fin_wait_1_gets_challenge_ack() -> Result<()> {
    // The same RFC 9293, Section 3.10.7.4 SYN rule as above applies to all synchronized states
    // listed there, not just ESTABLISHED.

    let mut connections = TcpConnections::default();
    connections.insert_established(); // rcv_nxt=CLIENT_ISN+1
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2

    let initial_state = connections.try_get()?.clone();
    assert_eq!(initial_state.tcp_state, TcpState::FinWait1);

    let reply = client_packet(CLIENT_ISN + SYN_BYTE, 0, TcpFlags::Syn, &[])
        .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(server_reply(
            SERVER_ISN + SYN_BYTE + FIN_BYTE,
            CLIENT_ISN + SYN_BYTE,
            TcpFlags::Ack,
            &[]
        )),
        "Stray SYN in FIN-WAIT-1 must produce a challenge ACK using snd_nxt=SERVER_ISN+2"
    );

    assert_eq!(
        connections.try_get()?,
        &initial_state,
        "In-window stray SYN must not destroy the connection"
    );

    Ok(())
}

#[test]
fn data_packet_before_complete_handshake_gets_rst() -> Result<()> {
    let mut connections = TcpConnections::default();
    connections.insert_syn_recv(); // SYN-ACK sent, but handshake not yet completed

    let reply =
        client_packet(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE, TcpFlags::Ack, b"Hello")
            .create_reply(&mut connections)?;

    assert_eq!(reply, Some(server_reply(SERVER_ISN + SYN_BYTE, 0, TcpFlags::Rst, &[])));

    Ok(())
}

#[test]
fn handshake_ack_establishes_connection_and_returns_none() -> Result<()> {
    let mut connections = TcpConnections::default();
    // Simulate having sent a SYN-ACK with ISN=SERVER_ISN so ack_num=SERVER_ISN+1 is the correct
    // completion
    connections.insert_syn_recv();
    let mut cloned_state = connections.try_get()?.clone();

    assert_eq!(
        client_packet(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE, TcpFlags::Ack, &[])
            .create_reply(&mut connections)?,
        None
    );

    // Reproduce the state changes that should happen at connection establishment
    cloned_state.tcp_state = TcpState::Established;
    cloned_state.rcv_nxt = CLIENT_ISN + SYN_BYTE;
    cloned_state.snd_una.advance_by(SYN_BYTE);

    assert_eq!(connections.try_get()?, &cloned_state);

    Ok(())
}

#[test]
fn reply_creates_valid_data_echo() -> Result<()> {
    let mut connections = TcpConnections::default();
    connections.insert_established(); // rcv_nxt = client's seq at handshake ACK time

    let reply =
        client_packet(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE, TcpFlags::Ack, b"Hello")
            .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(server_reply(
            SERVER_ISN + SYN_BYTE,
            CLIENT_ISN + SYN_BYTE + HELLO_LEN,
            TcpFlags::Ack,
            b"Hello"
        ))
    );

    Ok(())
}

#[test]
fn reply_creates_valid_fin_ack() -> Result<()> {
    // Simulate an established connection
    let mut connections = TcpConnections::default();
    connections.insert_established(); // FIN-ACK arrives at seq=CLIENT_ISN+1
    let mut cloned_state = connections.try_get()?.clone();

    let reply = client_packet(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE, TcpFlags::FinAck, &[])
        .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(server_reply(
            SERVER_ISN + SYN_BYTE,
            CLIENT_ISN + SYN_BYTE + FIN_BYTE,
            TcpFlags::FinAck,
            &[]
        ))
    );

    // Connection is now in LAST-ACK state (waiting for client's final ACK), not yet removed
    cloned_state.tcp_state = TcpState::LastAck;
    cloned_state.snd_nxt.advance_by(FIN_BYTE);
    cloned_state.rcv_nxt.advance_by(FIN_BYTE);

    assert_eq!(connections.try_get()?, &cloned_state);

    Ok(())
}

#[test]
fn final_ack_after_fin_ack_removes_connection_and_returns_none() -> Result<()> {
    // Simulates the client's final ACK completing the 4-step close. Should get no reply (not RST)
    // so the client can close cleanly from TIME-WAIT.

    let mut connections = TcpConnections::default();
    connections.insert(ConnState {
        tcp_state: TcpState::LastAck,
        snd_nxt: SERVER_ISN + SYN_BYTE,
        rcv_nxt: CLIENT_ISN + SYN_BYTE,
        snd_una: SERVER_ISN + SYN_BYTE,
        pending: Vec::new(),
    });

    // ack=SERVER_ISN+2 (our FIN-ACK seq + 1)
    assert_eq!(
        client_packet(
            CLIENT_ISN + SYN_BYTE + FIN_BYTE,
            SERVER_ISN + SYN_BYTE + FIN_BYTE,
            TcpFlags::Ack,
            &[]
        )
        .create_reply(&mut connections)?,
        None
    );

    assert_matches!(connections.try_get(), Err(_), "Connection should be removed after final ACK");

    Ok(())
}

#[test]
fn pure_ack_on_established_connection_returns_none() -> Result<()> {
    // Simulates the client ACKing the server's echo reply. This should get no reply (not RST) so
    // the connection stays open for more data.

    let mut connections = TcpConnections::default();
    // State after receiving and echoing "Hello"
    connections.insert(ConnState {
        tcp_state: TcpState::Established,
        snd_nxt: SERVER_ISN + SYN_BYTE + HELLO_LEN,
        rcv_nxt: CLIENT_ISN + SYN_BYTE + HELLO_LEN,
        snd_una: SERVER_ISN + SYN_BYTE,
        pending: Vec::new(),
    });

    let mut cloned_state = connections.try_get()?.clone();

    // ack=SERVER_ISN + 5 bytes echoed + 1
    assert_eq!(
        client_packet(
            CLIENT_ISN + SYN_BYTE + HELLO_LEN,
            SERVER_ISN + SYN_BYTE + HELLO_LEN,
            TcpFlags::Ack,
            &[]
        )
        .create_reply(&mut connections)?,
        None
    );

    cloned_state.snd_una.advance_by(HELLO_LEN);

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "Connection should remain open after pure ACK"
    );

    Ok(())
}

#[test]
fn consecutive_replies_use_snd_nxt_for_seq_num() -> Result<()> {
    // Verifies that the server updates and uses its own snd_nxt for seq_num rather than simply
    // mirroring the client's ack_num. After sending a 5-byte echo, snd_nxt=SERVER_ISN+6, then the
    // next reply's seq_num must be SERVER_ISN+6 even when the client sends a stale
    // ack_num=SERVER_ISN+1.

    let mut connections = TcpConnections::default();
    connections.insert_established();
    let mut cloned_state = connections.try_get()?.clone();

    // First data packet: "Hello" (5 bytes), ack=SERVER_ISN+1 (acknowledges our ISN+1)
    let reply1 =
        client_packet(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE, TcpFlags::Ack, b"Hello")
            .create_reply(&mut connections)?;

    assert_eq!(
        reply1,
        Some(server_reply(
            SERVER_ISN + SYN_BYTE,
            CLIENT_ISN + SYN_BYTE + HELLO_LEN,
            TcpFlags::Ack,
            b"Hello"
        )),
        "Standard reply to the first data packet"
    );

    cloned_state.snd_nxt.advance_by(HELLO_LEN);
    cloned_state.rcv_nxt.advance_by(HELLO_LEN);
    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "Stored snd_nxt should be SERVER_ISN + 1 + 5 bytes echoed between replies"
    );

    // Second data packet: "Hi" (2 bytes), but with stale ack=SERVER_ISN+1 (hasn't ACKed our "Hello"
    // echo)
    let reply2 = client_packet(
        CLIENT_ISN + SYN_BYTE + HELLO_LEN,
        SERVER_ISN + SYN_BYTE,
        TcpFlags::Ack,
        b"Hi",
    )
    .create_reply(&mut connections)?;

    assert_eq!(
        reply2,
        Some(server_reply(
            SERVER_ISN + SYN_BYTE + HELLO_LEN,
            CLIENT_ISN + SYN_BYTE + HELLO_LEN + HI_LEN,
            TcpFlags::Ack,
            b"Hi"
        )),
        "Server's seq_num should be snd_nxt=SERVER_ISN+6, not client's stale ack_num=SERVER_ISN+1"
    );

    Ok(())
}

#[test]
fn old_ack_num_does_not_regress_snd_una() -> Result<()> {
    // SND.UNA should only ever advance on a "new" ack (RFC 9293, Section 3.10.7.4). After two
    // exchanges bring SND.UNA up to SERVER_ISN+6, a third packet with a stale ack_num=SERVER_ISN+1
    // (now older than SND.UNA) must not move SND.UNA backward, even though the segment is
    // otherwise processed normally (seq_num still matches RCV.NXT).

    let mut connections = TcpConnections::default();
    connections.insert_established(); // SND.UNA=SND.NXT=SERVER_ISN+1, RCV.NXT=CLIENT_ISN+1
    let mut cloned_state = connections.try_get()?.clone();
    assert_eq!(cloned_state.snd_una, SERVER_ISN + SYN_BYTE);

    // First packet: "Hello" (5 bytes), ack=SERVER_ISN+1 -> SND.UNA is SERVER_ISN+1, SND.NXT becomes
    // SERVER_ISN+6
    let reply1 =
        client_packet(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE, TcpFlags::Ack, b"Hello")
            .create_reply(&mut connections)?;

    assert_eq!(
        reply1,
        Some(server_reply(
            SERVER_ISN + SYN_BYTE,
            CLIENT_ISN + SYN_BYTE + HELLO_LEN,
            TcpFlags::Ack,
            b"Hello"
        )),
        "Standard reply to the first data packet"
    );

    cloned_state.snd_nxt.advance_by(HELLO_LEN);
    cloned_state.rcv_nxt.advance_by(HELLO_LEN);
    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "SND.UNA should still be SERVER_ISN+1 after the first data packet"
    );

    // Second packet: "Hi" (2 bytes), ack=SERVER_ISN+6 -> SND.UNA advances to SERVER_ISN+6, SND.NXT
    // becomes SERVER_ISN+8
    let reply2 = client_packet(
        CLIENT_ISN + SYN_BYTE + HELLO_LEN,
        SERVER_ISN + SYN_BYTE + HELLO_LEN,
        TcpFlags::Ack,
        b"Hi",
    )
    .create_reply(&mut connections)?;

    assert_eq!(
        reply2,
        Some(server_reply(
            SERVER_ISN + SYN_BYTE + HELLO_LEN,
            CLIENT_ISN + SYN_BYTE + HELLO_LEN + HI_LEN,
            TcpFlags::Ack,
            b"Hi"
        )),
        "Standard reply to the second data packet"
    );

    cloned_state.snd_nxt.advance_by(HI_LEN);
    cloned_state.rcv_nxt.advance_by(HI_LEN);
    cloned_state.snd_una.advance_by(HELLO_LEN);
    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "SND.UNA should be SERVER_ISN+6 after the second data packet"
    );

    // Third packet: "Hey" (3 bytes), ack=SERVER_ISN+1 (now stale, older than SND.UNA=SERVER_ISN+6)
    let reply3 = client_packet(
        CLIENT_ISN + SYN_BYTE + HELLO_LEN + HI_LEN,
        SERVER_ISN + SYN_BYTE,
        TcpFlags::Ack,
        b"Hey",
    )
    .create_reply(&mut connections)?;

    // The stale ack_num doesn't make the segment unacceptable (SERVER_ISN+1 <=
    // SND.NXT=SERVER_ISN+8), so it's still processed normally and "Hey" is echoed
    assert_eq!(
        reply3,
        Some(server_reply(
            SERVER_ISN + SYN_BYTE + HELLO_LEN + HI_LEN,
            CLIENT_ISN + SYN_BYTE + HELLO_LEN + HI_LEN + HEY_LEN,
            TcpFlags::Ack,
            b"Hey"
        )),
        "Stale ack_num shouldn't prevent normal processing"
    );

    cloned_state.snd_nxt.advance_by(HEY_LEN);
    cloned_state.rcv_nxt.advance_by(HEY_LEN);
    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "Stale ack_num=SERVER_ISN+1 must not move SND.UNA backward from SERVER_ISN+6"
    );

    Ok(())
}

#[test]
fn rst_exactly_at_rcv_nxt_cleans_up_connection_and_returns_none() -> Result<()> {
    // RFC 9293, Section 3.10.7.4, RST bit set, SEG.SEQ == RCV.NXT -> reset connection

    let mut connections = TcpConnections::default();
    connections.insert_established();

    assert_eq!(
        client_packet(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE, TcpFlags::Rst, &[])
            .create_reply(&mut connections)?,
        None
    );

    assert_matches!(connections.try_get(), Err(_), "Connection should be removed after RST");

    Ok(())
}

#[test]
fn rst_within_window_but_not_at_rcv_nxt_gets_challenge_ack() -> Result<()> {
    // RFC 9293, Section 3.10.7.4, RST bit set, SEG.SEQ in receive window but SEG.SEQ != RCV.NXT ->
    // send challenge ACK, don't reset connection

    let mut connections = TcpConnections::default();
    connections.insert_established(); // rcv_nxt=CLIENT_ISN+1, snd_nxt=SERVER_ISN+1
    let initial_state = connections.try_get()?.clone();

    // seq_num=CLIENT_ISN+4 is inside the receive window [CLIENT_ISN+1, CLIENT_ISN+1+RCV.WND), but
    // seq_num=CLIENT_ISN+4 != rcv_nxt=CLIENT_ISN+1
    let reply = client_packet(CLIENT_ISN + 4, SERVER_ISN + SYN_BYTE, TcpFlags::Rst, &[])
        .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(server_reply(SERVER_ISN + SYN_BYTE, CLIENT_ISN + SYN_BYTE, TcpFlags::Ack, &[])),
        "In-window non-exact RST should get a challenge ACK, not a silent drop or reset"
    );

    assert_eq!(
        connections.try_get()?,
        &initial_state,
        "Connection must not be torn down by a non-exact in-window RST"
    );

    Ok(())
}

#[test]
fn rst_with_out_of_window_seq_is_silently_dropped() -> Result<()> {
    // RFC 9293, Section 3.10.7.4, RST bit set, SEG.SEQ outside the current receive window -> must
    // be silently ignored. (This is protection against blind RST-spoofing where an attacker knows
    // the 4-tuple but not the current sequence numbers.)

    let mut connections = TcpConnections::default();
    connections.insert_established(); // rcv_nxt=CLIENT_ISN+1
    let initial_state = connections.try_get()?.clone();

    // seq_num=CLIENT_ISN-10 is just below rcv_nxt=CLIENT_ISN+1, so this RST is outside the receive
    // window
    let reply = client_packet(CLIENT_ISN - 10, SERVER_ISN + SYN_BYTE, TcpFlags::Rst, &[])
        .create_reply(&mut connections)?;
    assert_eq!(reply, None, "Out-of-window RST should be silently dropped");

    assert_eq!(
        connections.try_get()?,
        &initial_state,
        "Connection must not be torn down by an out-of-window RST"
    );

    Ok(())
}

#[test]
fn duplicate_data_packet_gets_duplicate_ack_without_echo() -> Result<()> {
    // A retransmitted segment should get a duplicate ACK pointing at the current rcv_nxt, not
    // another echo. Processing a second distinct packet first makes the seq_num check meaningful
    // because the retransmitted packet's seq+len points back to CLIENT_ISN+6, but rcv_nxt is
    // CLIENT_ISN+8 after both deliveries.

    let mut connections = TcpConnections::default();
    connections.insert_established();

    let hello =
        client_packet(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE, TcpFlags::Ack, b"Hello");
    let hi = client_packet(
        CLIENT_ISN + SYN_BYTE + HELLO_LEN,
        SERVER_ISN + SYN_BYTE + HELLO_LEN,
        TcpFlags::Ack,
        b"Hi",
    );

    // First packet: "Hello" (seq=CLIENT_ISN+1) -> rcv_nxt advances to CLIENT_ISN+6, snd_nxt
    // advances to SERVER_ISN+6
    let reply1 = hello.clone().create_reply(&mut connections)?;
    assert_eq!(
        reply1,
        Some(server_reply(
            SERVER_ISN + SYN_BYTE,
            CLIENT_ISN + SYN_BYTE + HELLO_LEN,
            TcpFlags::Ack,
            b"Hello"
        )),
        "Standard reply to the first data packet"
    );

    // Second packet: "Hi" (seq=CLIENT_ISN+6) -> rcv_nxt advances to CLIENT_ISN+8, snd_nxt advances
    // to SERVER_ISN+8
    let reply2 = hi.create_reply(&mut connections)?;
    assert_eq!(
        reply2,
        Some(server_reply(
            SERVER_ISN + SYN_BYTE + HELLO_LEN,
            CLIENT_ISN + SYN_BYTE + HELLO_LEN + HI_LEN,
            TcpFlags::Ack,
            b"Hi"
        )),
        "Standard reply to the second data packet"
    );

    // Retransmit of "Hello": seq=CLIENT_ISN+1, but rcv_nxt is now CLIENT_ISN+8
    let reply3 = hello.create_reply(&mut connections)?;

    assert_eq!(
        reply3,
        Some(server_reply(
            SERVER_ISN + SYN_BYTE + HELLO_LEN + HI_LEN,
            CLIENT_ISN + SYN_BYTE + HELLO_LEN + HI_LEN,
            TcpFlags::Ack,
            &[]
        )),
        "Duplicate ACK should ack rcv_nxt=CLIENT_ISN+8 with no payload, not echo \
         seq+len=CLIENT_ISN+6"
    );

    Ok(())
}

#[test]
fn out_of_order_fin_ack_gets_duplicate_ack_without_closing() -> Result<()> {
    // A FIN-ACK arriving before data preceding it (seq_num != rcv_nxt, e.g. an earlier data segment
    // was lost) must not be processed yet. Doing so would signal "no more data" before the missing
    // data has been delivered. Until the gap is filled, treat it like out-of-order data by sending
    // a duplicate ACK reflecting the current rcv_nxt with no change to local state.

    let mut connections = TcpConnections::default();
    connections.insert_established(); // rcv_nxt = CLIENT_ISN+1
    let initial_state = connections.try_get()?.clone();

    // FIN-ACK arrives at seq=CLIENT_ISN+6, but rcv_nxt is still CLIENT_ISN+1 (a 5-byte gap)
    let reply = client_packet(
        CLIENT_ISN + SYN_BYTE + HELLO_LEN,
        SERVER_ISN + SYN_BYTE,
        TcpFlags::FinAck,
        &[],
    )
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(server_reply(SERVER_ISN + SYN_BYTE, CLIENT_ISN + SYN_BYTE, TcpFlags::Ack, &[])),
        "Out-of-order FIN-ACK should get a duplicate ACK reflecting rcv_nxt=CLIENT_ISN+1, not a \
         FIN-ACK in response"
    );

    assert_eq!(
        connections.try_get()?,
        &initial_state,
        "Connection must remain established, out-of-order FIN-ACK must not start closing"
    );

    Ok(())
}

#[test]
fn unrecognized_packet_for_unknown_connection_gets_rst() -> Result<()> {
    // ACK with payload for a connection the server has no record of (e.g. after restart)

    let mut connections = TcpConnections::default(); // Empty, no known connections

    let reply =
        client_packet(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE, TcpFlags::Ack, b"Hello")
            .create_reply(&mut connections)?;

    assert_eq!(reply, Some(server_reply(SERVER_ISN + SYN_BYTE, 0, TcpFlags::Rst, &[])));

    Ok(())
}

#[test]
fn ack_for_unsent_data_is_dropped_and_gets_current_state_reply() -> Result<()> {
    // Per RFC 9293 Section 3.10.7.4, an ACK acknowledging data the server hasn't sent yet (ack_num
    // past SND.NXT) must be dropped, and the reply should be a bare ACK reflecting the current
    // SND.NXT/RCV.NXT, with no payload echoed and no state change. seq_num matches RCV.NXT, so this
    // would otherwise be treated as valid in-order data.

    let mut connections = TcpConnections::default();
    connections.insert_established(); // SND.NXT=SERVER_ISN+1, RCV.NXT=CLIENT_ISN+1
    let initial_state = connections.try_get()?.clone();

    // seq_num == RCV.NXT, but ack_num=SERVER_ISN+20 is past SND.NXT=SERVER_ISN+1
    let reply = client_packet(CLIENT_ISN + SYN_BYTE, SERVER_ISN + 20, TcpFlags::Ack, b"Hello")
        .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(server_reply(SERVER_ISN + SYN_BYTE, CLIENT_ISN + SYN_BYTE, TcpFlags::Ack, &[]))
    );

    assert_eq!(connections.try_get()?, &initial_state, "State must be untouched");

    Ok(())
}

#[test]
fn wraparound_ack_for_unsent_data_is_still_rejected() -> Result<()> {
    // ISNs are random (RFC 9293, Section 3.4.1) and can land near `u32::MAX`, wrapping SND.NXT to a
    // small value. An ack_num that wraps one past SND.NXT must still be recognized as acknowledging
    // unsent data, even though a naive numeric comparison (ack_num > snd_nxt) would say 0 >
    // `u32::MAX` is false and let it through.

    let mut connections = TcpConnections::default();
    let initial_state = ConnState {
        tcp_state: TcpState::Established,
        snd_nxt: u32::MAX,
        rcv_nxt: CLIENT_ISN + SYN_BYTE,
        snd_una: u32::MAX,
        pending: Vec::new(),
    };
    connections.insert(initial_state.clone());

    // ack=0 wraps 1 past SND.NXT=`u32::MAX`
    let reply = client_packet(CLIENT_ISN + SYN_BYTE, 0, TcpFlags::Ack, &[])
        .create_reply(&mut connections)?;

    assert_eq!(reply, Some(server_reply(u32::MAX, CLIENT_ISN + SYN_BYTE, TcpFlags::Ack, &[])));

    assert_eq!(connections.try_get()?, &initial_state, "State must be untouched");

    Ok(())
}

#[test]
fn close_established_sends_fin_ack_and_transitions_to_fin_wait_1() -> Result<()> {
    let mut connections = TcpConnections::default();
    connections.insert_established(); // snd_nxt=SERVER_ISN+1, rcv_nxt=CLIENT_ISN+1
    let mut cloned_state = connections.try_get()?.clone();

    let mut replies = connections.close_established();
    let reply = replies.pop().ok_or("Expected one reply")?;

    assert!(replies.is_empty(), "Expected exactly one reply");
    assert_eq!(
        reply,
        server_reply(SERVER_ISN + SYN_BYTE, CLIENT_ISN + SYN_BYTE, TcpFlags::FinAck, &[])
    );

    // IP addresses are swapped: server -> client
    assert_eq!(reply.get_ip_pair(), IP_PAIR.swapped());

    cloned_state.tcp_state = TcpState::FinWait1;
    cloned_state.snd_nxt.advance_by(FIN_BYTE);
    assert_eq!(connections.try_get()?, &cloned_state, "FIN consumes one sequence number");

    Ok(())
}

#[test]
fn fin_wait_1_to_fin_wait_2_on_ack_of_our_fin() -> Result<()> {
    let mut connections = TcpConnections::default();
    connections.insert_established();
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2
    let mut cloned_state = connections.try_get()?.clone();

    // Client acknowledges our FIN (ack=SERVER_ISN+2), no FIN of its own yet
    assert_eq!(
        client_packet(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE + FIN_BYTE, TcpFlags::Ack, &[])
            .create_reply(&mut connections)?,
        None
    );

    cloned_state.tcp_state = TcpState::FinWait2;
    cloned_state.snd_una.advance_by(FIN_BYTE);
    assert_eq!(connections.try_get()?, &cloned_state);

    Ok(())
}

#[test]
fn fin_wait_2_closes_on_fin_ack_from_peer() -> Result<()> {
    let mut connections = TcpConnections::default();
    connections.insert_established();
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2
    let mut cloned_state = connections.try_get()?.clone();

    // Our FIN is acknowledged -> FIN-WAIT-2
    let ack_reply =
        client_packet(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE + FIN_BYTE, TcpFlags::Ack, &[])
            .create_reply(&mut connections)?;
    assert_eq!(ack_reply, None);

    cloned_state.tcp_state = TcpState::FinWait2;
    cloned_state.snd_una.advance_by(FIN_BYTE);
    assert_eq!(connections.try_get()?, &cloned_state);

    // Client's FIN arrives in order
    let fin_reply = client_packet(
        CLIENT_ISN + SYN_BYTE,
        SERVER_ISN + SYN_BYTE + FIN_BYTE,
        TcpFlags::FinAck,
        &[],
    )
    .create_reply(&mut connections)?;

    assert_eq!(
        fin_reply,
        Some(server_reply(
            SERVER_ISN + SYN_BYTE + FIN_BYTE,
            CLIENT_ISN + SYN_BYTE + FIN_BYTE,
            TcpFlags::Ack,
            &[]
        ))
    );

    assert_matches!(connections.try_get(), Err(_), "Connection should be removed");

    Ok(())
}

#[test]
fn fin_wait_1_closes_immediately_if_peers_fin_also_acks_ours() -> Result<()> {
    // Simultaneous close where the peer's FIN, arriving while we're still in FIN-WAIT-1, also
    // acknowledges our FIN -> fully closed immediately, skipping FIN-WAIT-2/CLOSING.

    let mut connections = TcpConnections::default();
    connections.insert_established();
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2

    // Client's FIN arrives in order and also acknowledges our FIN (ack=SERVER_ISN+2)
    let reply = client_packet(
        CLIENT_ISN + SYN_BYTE,
        SERVER_ISN + SYN_BYTE + FIN_BYTE,
        TcpFlags::FinAck,
        &[],
    )
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(server_reply(
            SERVER_ISN + SYN_BYTE + FIN_BYTE,
            CLIENT_ISN + SYN_BYTE + FIN_BYTE,
            TcpFlags::Ack,
            &[]
        ))
    );

    assert_matches!(connections.try_get(), Err(_), "Connection should be removed");

    Ok(())
}

#[test]
fn data_after_our_fin_in_fin_wait_1_is_acked_without_echo() -> Result<()> {
    // After we've sent our FIN (FIN-WAIT-1), the connection isn't fully closed until the peer's
    // FIN also arrives, so data already in flight from the peer must still be accepted and ACKed,
    // even though we have no send side left to echo it with.

    let mut connections = TcpConnections::default();
    connections.insert_established(); // rcv_nxt=CLIENT_ISN+1
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2
    let mut cloned_state = connections.try_get()?.clone();

    let reply =
        client_packet(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE, TcpFlags::Ack, b"Hello")
            .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(server_reply(
            SERVER_ISN + SYN_BYTE + FIN_BYTE,
            CLIENT_ISN + SYN_BYTE + HELLO_LEN,
            TcpFlags::Ack,
            &[]
        )),
        "Data arriving after our FIN should be ACKed without being echoed, not RST"
    );

    cloned_state.rcv_nxt.advance_by(HELLO_LEN);
    assert_eq!(connections.try_get()?, &cloned_state, "State should remain FIN-WAIT-1");

    Ok(())
}

#[test]
fn data_after_our_fin_in_fin_wait_2_is_acked_without_echo() -> Result<()> {
    let mut connections = TcpConnections::default();
    connections.insert_established();
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2
    let mut cloned_state = connections.try_get()?.clone();

    // Our FIN is acknowledged -> FIN-WAIT-2
    client_packet(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE + FIN_BYTE, TcpFlags::Ack, &[])
        .create_reply(&mut connections)?;

    cloned_state.tcp_state = TcpState::FinWait2;
    cloned_state.snd_una.advance_by(FIN_BYTE);
    assert_eq!(connections.try_get()?, &cloned_state);

    let reply = client_packet(
        CLIENT_ISN + SYN_BYTE,
        SERVER_ISN + SYN_BYTE + FIN_BYTE,
        TcpFlags::Ack,
        b"Hello",
    )
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(server_reply(
            SERVER_ISN + SYN_BYTE + FIN_BYTE,
            CLIENT_ISN + SYN_BYTE + HELLO_LEN,
            TcpFlags::Ack,
            &[]
        )),
        "Data arriving after our FIN should be ACKed without being echoed, not RST"
    );

    cloned_state.rcv_nxt.advance_by(HELLO_LEN);
    assert_eq!(connections.try_get()?, &cloned_state, "State should remain FIN-WAIT-2");

    Ok(())
}

#[test]
fn simultaneous_close_transitions_through_closing_to_closed() -> Result<()> {
    let mut connections = TcpConnections::default();
    connections.insert_established();
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2
    let mut cloned_state = connections.try_get()?.clone();

    // Client's FIN arrives in order, but doesn't yet acknowledge our FIN (ack=SERVER_ISN+1,
    // simultaneous close) -> CLOSING
    let reply = client_packet(CLIENT_ISN + SYN_BYTE, SERVER_ISN + SYN_BYTE, TcpFlags::FinAck, &[])
        .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(server_reply(
            SERVER_ISN + SYN_BYTE + FIN_BYTE,
            CLIENT_ISN + SYN_BYTE + FIN_BYTE,
            TcpFlags::Ack,
            &[]
        ))
    );

    cloned_state.tcp_state = TcpState::Closing;
    cloned_state.rcv_nxt.advance_by(FIN_BYTE);
    assert_eq!(connections.try_get()?, &cloned_state);

    // Client's ACK of our FIN finally arrives -> fully closed
    assert_eq!(
        client_packet(
            CLIENT_ISN + SYN_BYTE + FIN_BYTE,
            SERVER_ISN + SYN_BYTE + FIN_BYTE,
            TcpFlags::Ack,
            &[]
        )
        .create_reply(&mut connections)?,
        None
    );

    assert_matches!(connections.try_get(), Err(_), "Connection should be removed");

    Ok(())
}
