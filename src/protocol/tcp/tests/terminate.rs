use super::*;

#[test]
fn creates_valid_fin_ack() -> Result {
    // Simulate an established connection
    let mut connections = TcpConnections::default().after_handshake(); // FIN-ACK arrives at seq=CLIENT_ISN+1
    let mut cloned_state = connections.try_get()?.clone();

    let reply = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE,
        flags: TcpFlags::FinAck,
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpHandler {
            seq_num: SERVER_ISN + SYN_BYTE,
            ack_num: CLIENT_ISN + SYN_BYTE + FIN_BYTE,
            flags: TcpFlags::FinAck,
            ..SERVER_REPLY
        })
    );

    // Connection is now in LAST-ACK state (waiting for client's final ACK), not yet removed
    cloned_state.tcp_state = TcpState::LastAck;
    cloned_state.snd_nxt.advance_by(FIN_BYTE);
    cloned_state.rcv_nxt.advance_by(FIN_BYTE);

    assert_eq!(connections.try_get()?, &cloned_state);

    Ok(())
}

#[test]
fn fin_ack_acks_prior_data_and_advances_snd_una() -> Result {
    // FIN-ACK also includes "check the ACK field" processing just like a plain ACK (RFC 9293,
    // Section 3.10.7.4). Its SEG.ACK can acknowledge data sent earlier in the connection, and that
    // must still advance SND.UNA and prune `pending`.

    // snd_nxt=snd_una=SERVER_ISN+1, rcv_nxt=CLIENT_ISN+1
    let mut connections = TcpConnections::default().after_handshake();
    let mut cloned_state = connections.try_get()?.clone();

    // Client sends data, server echoes "Hello" back
    TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE,
        payload: payload_from("Hello")?,
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    cloned_state.snd_nxt.advance_by(HELLO_LEN);
    cloned_state.rcv_nxt.advance_by(HELLO_LEN);
    // snd_una left unchanged at this point because the "Hello" echo is unacked

    assert_eq!(
        {
            let pending = &connections.try_get()?.pending;
            (
                pending.len(),
                pending
                    .first()
                    .and_then(|seg| seg.peek_info().payload.as_ref().map(TcpPayload::as_bytes)),
            )
        },
        (1, Some("Hello".as_ref())),
        "Intermediate `pending` should consist of the unacked \"Hello\" echo"
    );

    // Client's FIN-ACK arrives in order (seq=CLIENT_ISN+6) and acks the echoed "Hello"
    // (ack=SERVER_ISN+6)
    let client_fin_ack = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE + HELLO_LEN,
        ack_num: SERVER_ISN + SYN_BYTE + HELLO_LEN,
        flags: TcpFlags::FinAck,
        ..CLIENT_PACKET
    };

    client_fin_ack.create_reply(&mut connections)?;

    cloned_state.tcp_state = TcpState::LastAck;
    cloned_state.snd_nxt.advance_by(FIN_BYTE);
    cloned_state.rcv_nxt.advance_by(FIN_BYTE);
    cloned_state.snd_una.advance_by(HELLO_LEN);
    cloned_state.window_state = Some(WindowState {
        snd_wnd: CLIENT_PACKET.window,
        snd_wl1: client_fin_ack.seq_num,
        snd_wl2: client_fin_ack.ack_num,
    });

    let final_state = connections.try_get()?;

    assert_eq!(
        final_state, &cloned_state,
        "SEG.ACK from FIN-ACK should advance SND.UNA just like a plain ACK"
    );

    assert_eq!(
        (final_state.pending.len(), final_state.pending.first().map(|seg| seg.peek_info().flags)),
        (1, Some(TcpFlags::FinAck)),
        "The fully acked \"Hello\" echo should be pruned from `pending`, leaving only the FIN-ACK"
    );

    Ok(())
}

#[test]
fn out_of_order_fin_ack_gets_duplicate_ack_without_closing() -> Result {
    // A FIN-ACK arriving before data preceding it (seq_num != rcv_nxt, e.g. an earlier data segment
    // was lost) must not be processed yet. Doing so would signal "no more data" before the missing
    // data has been delivered. Until the gap is filled, treat it like out-of-order data by sending
    // a duplicate ACK reflecting the current rcv_nxt with no change to local state.

    let mut connections = TcpConnections::default().after_handshake(); // rcv_nxt = CLIENT_ISN+1
    let mut cloned_state = connections.try_get()?.clone();

    // FIN-ACK arrives at seq=CLIENT_ISN+6, but rcv_nxt is still CLIENT_ISN+1 (a 5-byte gap)
    let client_fin_ack = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE + HELLO_LEN,
        ack_num: SERVER_ISN + SYN_BYTE,
        flags: TcpFlags::FinAck,
        ..CLIENT_PACKET
    };

    assert_eq!(
        client_fin_ack.create_reply(&mut connections)?,
        Some(TcpHandler {
            seq_num: SERVER_ISN + SYN_BYTE,
            ack_num: CLIENT_ISN + SYN_BYTE,
            ..SERVER_REPLY
        }),
        "Out-of-order FIN-ACK should get a duplicate ACK reflecting rcv_nxt=CLIENT_ISN+1, not a \
         FIN-ACK in response"
    );

    cloned_state.window_state = Some(WindowState {
        snd_wnd: CLIENT_PACKET.window,
        snd_wl1: client_fin_ack.seq_num,
        snd_wl2: client_fin_ack.ack_num,
    });

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "Connection must remain established, out-of-order FIN-ACK must not start closing"
    );

    Ok(())
}

#[test]
fn final_ack_after_fin_ack_removes_connection_and_returns_none() -> Result {
    // Simulates the client's final ACK completing the 4-step close. Should get no reply (not RST)
    // so the client can close cleanly from TIME-WAIT.

    let mut connections = TcpConnections::default().after_handshake();
    let mut cloned_state = connections.try_get()?.clone();

    TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE,
        flags: TcpFlags::FinAck,
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    cloned_state.tcp_state = TcpState::LastAck;
    cloned_state.snd_nxt.advance_by(1);
    cloned_state.rcv_nxt.advance_by(1);

    assert_eq!(connections.try_get()?, &cloned_state);

    // ack=SERVER_ISN+2 (our FIN-ACK seq + 1)
    assert_eq!(
        TcpHandler {
            seq_num: CLIENT_ISN + SYN_BYTE + FIN_BYTE,
            ack_num: SERVER_ISN + SYN_BYTE + FIN_BYTE,
            ..CLIENT_PACKET
        }
        .create_reply(&mut connections)?,
        None
    );

    assert_matches!(connections.try_get(), Err(_), "Connection should be removed after final ACK");

    Ok(())
}

#[test]
fn close_established_sends_fin_ack_and_transitions_to_fin_wait_1() -> Result {
    // snd_nxt=SERVER_ISN+1, rcv_nxt=CLIENT_ISN+1
    let mut connections = TcpConnections::default().after_handshake();
    let mut cloned_state = connections.try_get()?.clone();

    let mut replies = connections.close_established();
    let reply = replies.pop().ok_or("Expected one reply")?;

    assert!(replies.is_empty(), "Expected exactly one reply");
    assert_eq!(
        reply,
        TcpHandler {
            seq_num: SERVER_ISN + SYN_BYTE,
            ack_num: CLIENT_ISN + SYN_BYTE,
            flags: TcpFlags::FinAck,
            ..SERVER_REPLY
        }
    );

    // IP addresses are swapped: server -> client
    assert_eq!(reply.get_ip_pair(), IP_PAIR.swapped());

    cloned_state.tcp_state = TcpState::FinWait1;
    cloned_state.snd_nxt.advance_by(FIN_BYTE);
    assert_eq!(connections.try_get()?, &cloned_state, "FIN consumes one sequence number");

    Ok(())
}

#[test]
fn fin_wait_1_to_fin_wait_2_on_ack_of_our_fin() -> Result {
    let mut connections = TcpConnections::default().after_handshake();
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2
    let mut cloned_state = connections.try_get()?.clone();

    // Client acknowledges our FIN (ack=SERVER_ISN+2), no FIN of its own yet
    let ack_of_fin = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE + FIN_BYTE,
        ..CLIENT_PACKET
    };

    assert_eq!(ack_of_fin.create_reply(&mut connections)?, None);

    cloned_state.tcp_state = TcpState::FinWait2;
    cloned_state.snd_una.advance_by(FIN_BYTE);
    cloned_state.window_state = Some(WindowState {
        snd_wnd: CLIENT_PACKET.window,
        snd_wl1: ack_of_fin.seq_num,
        snd_wl2: ack_of_fin.ack_num,
    });

    assert_eq!(connections.try_get()?, &cloned_state);

    Ok(())
}

#[test]
fn fin_wait_2_closes_on_fin_ack_from_peer() -> Result {
    let mut connections = TcpConnections::default().after_handshake();
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2
    let mut cloned_state = connections.try_get()?.clone();

    // Our FIN is acknowledged -> FIN-WAIT-2
    let ack_of_fin = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE + FIN_BYTE,
        ..CLIENT_PACKET
    };

    assert_eq!(ack_of_fin.create_reply(&mut connections)?, None);

    cloned_state.tcp_state = TcpState::FinWait2;
    cloned_state.snd_una.advance_by(FIN_BYTE);
    cloned_state.window_state = Some(WindowState {
        snd_wnd: CLIENT_PACKET.window,
        snd_wl1: ack_of_fin.seq_num,
        snd_wl2: ack_of_fin.ack_num,
    });

    assert_eq!(connections.try_get()?, &cloned_state);

    // Client's FIN arrives in order
    let fin_reply = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE + FIN_BYTE,
        flags: TcpFlags::FinAck,
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        fin_reply,
        Some(TcpHandler {
            seq_num: SERVER_ISN + SYN_BYTE + FIN_BYTE,
            ack_num: CLIENT_ISN + SYN_BYTE + FIN_BYTE,
            ..SERVER_REPLY
        })
    );

    assert_matches!(connections.try_get(), Err(_), "Connection should be removed");

    Ok(())
}

#[test]
fn fin_wait_1_closes_immediately_if_peers_fin_also_acks_ours() -> Result {
    // Simultaneous close where the peer's FIN, arriving while we're still in FIN-WAIT-1, also
    // acknowledges our FIN -> fully closed immediately, skipping FIN-WAIT-2/CLOSING.

    let mut connections = TcpConnections::default().after_handshake();
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2

    // Client's FIN arrives in order and also acknowledges our FIN (ack=SERVER_ISN+2)
    let reply = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE + FIN_BYTE,
        flags: TcpFlags::FinAck,
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpHandler {
            seq_num: SERVER_ISN + SYN_BYTE + FIN_BYTE,
            ack_num: CLIENT_ISN + SYN_BYTE + FIN_BYTE,
            ..SERVER_REPLY
        })
    );

    assert_matches!(connections.try_get(), Err(_), "Connection should be removed");

    Ok(())
}

#[test]
fn data_after_our_fin_in_fin_wait_1_is_acked_without_echo() -> Result {
    // After we've sent our FIN (FIN-WAIT-1), the connection isn't fully closed until the peer's
    // FIN also arrives, so data already in flight from the peer must still be accepted and ACKed,
    // even though we have no send side left to echo it with.

    let mut connections = TcpConnections::default().after_handshake(); // rcv_nxt=CLIENT_ISN+1
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2
    let mut cloned_state = connections.try_get()?.clone();

    let reply = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE,
        payload: payload_from("Hello")?,
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpHandler {
            seq_num: SERVER_ISN + SYN_BYTE + FIN_BYTE,
            ack_num: CLIENT_ISN + SYN_BYTE + HELLO_LEN,
            ..SERVER_REPLY
        }),
        "Data arriving after our FIN should be ACKed without being echoed, not RST"
    );

    cloned_state.rcv_nxt.advance_by(HELLO_LEN);
    assert_eq!(connections.try_get()?, &cloned_state, "State should remain FIN-WAIT-1");

    Ok(())
}

#[test]
fn data_after_our_fin_in_fin_wait_2_is_acked_without_echo() -> Result {
    let mut connections = TcpConnections::default().after_handshake();
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2
    let mut cloned_state = connections.try_get()?.clone();

    // Our FIN is acknowledged -> FIN-WAIT-2
    let ack_of_fin = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE + FIN_BYTE,
        ..CLIENT_PACKET
    };

    assert_eq!(ack_of_fin.create_reply(&mut connections)?, None);

    cloned_state.tcp_state = TcpState::FinWait2;
    cloned_state.snd_una.advance_by(FIN_BYTE);
    cloned_state.window_state = Some(WindowState {
        snd_wnd: CLIENT_PACKET.window,
        snd_wl1: ack_of_fin.seq_num,
        snd_wl2: ack_of_fin.ack_num,
    });

    assert_eq!(connections.try_get()?, &cloned_state);

    let reply = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE + FIN_BYTE,
        payload: payload_from("Hello")?,
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpHandler {
            seq_num: SERVER_ISN + SYN_BYTE + FIN_BYTE,
            ack_num: CLIENT_ISN + SYN_BYTE + HELLO_LEN,
            ..SERVER_REPLY
        }),
        "Data arriving after our FIN should be ACKed without being echoed, not RST"
    );

    cloned_state.rcv_nxt.advance_by(HELLO_LEN);
    assert_eq!(connections.try_get()?, &cloned_state, "State should remain FIN-WAIT-2");

    Ok(())
}

#[test]
fn simultaneous_close_transitions_through_closing_to_closed() -> Result {
    let mut connections = TcpConnections::default().after_handshake();
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2
    let mut cloned_state = connections.try_get()?.clone();

    // Client's FIN arrives in order, but doesn't yet acknowledge our FIN (ack=SERVER_ISN+1,
    // simultaneous close) -> CLOSING
    let reply = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE,
        flags: TcpFlags::FinAck,
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpHandler {
            seq_num: SERVER_ISN + SYN_BYTE + FIN_BYTE,
            ack_num: CLIENT_ISN + SYN_BYTE + FIN_BYTE,
            ..SERVER_REPLY
        })
    );

    cloned_state.tcp_state = TcpState::Closing;
    cloned_state.rcv_nxt.advance_by(FIN_BYTE);
    assert_eq!(connections.try_get()?, &cloned_state);

    // Client's ACK of our FIN finally arrives -> fully closed
    assert_eq!(
        TcpHandler {
            seq_num: CLIENT_ISN + SYN_BYTE + FIN_BYTE,
            ack_num: SERVER_ISN + SYN_BYTE + FIN_BYTE,
            ..CLIENT_PACKET
        }
        .create_reply(&mut connections)?,
        None
    );

    assert_matches!(connections.try_get(), Err(_), "Connection should be removed");

    Ok(())
}
