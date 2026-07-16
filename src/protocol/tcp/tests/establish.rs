use super::*;

#[test]
fn creates_valid_syn_ack() -> Result {
    let mut connections = TcpConnections::default();

    let reply = TcpHandler { seq_num: CLIENT_ISN, flags: TcpFlags::Syn, ..CLIENT_PACKET }
        .create_reply(&mut connections)?;

    // seq_num is the random ISN that was stored in the connection table
    let stored_isn = connections.try_get()?.snd_una;

    assert_eq!(
        reply,
        Some(TcpHandler {
            seq_num: stored_isn,
            ack_num: CLIENT_ISN + SYN_BYTE,
            flags: TcpFlags::SynAck,
            ..SERVER_REPLY
        })
    );

    Ok(())
}

#[test]
fn duplicate_syn_during_syn_received_resends_same_syn_ack() -> Result {
    // If our SYN-ACK is lost, the client's retransmission timer will resend its SYN. We must resend
    // the same SYN-ACK (same ISN), not RST the retry, and not generate a new ISN.

    let mut connections = TcpConnections::default();
    connections.insert_syn_recv(); // Simulate having already sent a SYN-ACK with ISN=SERVER_ISN
    let initial_state = connections.try_get()?.clone();

    let reply = TcpHandler { seq_num: CLIENT_ISN, flags: TcpFlags::Syn, ..CLIENT_PACKET }
        .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpHandler {
            seq_num: SERVER_ISN,
            ack_num: CLIENT_ISN + SYN_BYTE,
            flags: TcpFlags::SynAck,
            ..SERVER_REPLY
        }),
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
fn data_packet_before_complete_handshake_gets_rst() -> Result {
    let mut connections = TcpConnections::default();
    connections.insert_syn_recv(); // SYN-ACK sent, but handshake not yet completed

    let reply = TcpHandler {
        seq_num: CLIENT_ISN + SYN_BYTE,
        ack_num: SERVER_ISN + SYN_BYTE,
        payload: payload_from("Hello"),
        ..CLIENT_PACKET
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpHandler { seq_num: SERVER_ISN + SYN_BYTE, flags: TcpFlags::Rst, ..SERVER_REPLY })
    );

    Ok(())
}

#[test]
fn handshake_ack_establishes_connection_and_returns_none() -> Result {
    let mut connections = TcpConnections::default();
    // Simulate having sent a SYN-ACK with ISN=SERVER_ISN so ack_num=SERVER_ISN+1 is the correct
    // completion
    connections.insert_syn_recv();
    let mut cloned_state = connections.try_get()?.clone();

    assert_eq!(
        TcpHandler {
            seq_num: CLIENT_ISN + SYN_BYTE,
            ack_num: SERVER_ISN + SYN_BYTE,
            ..CLIENT_PACKET
        }
        .create_reply(&mut connections)?,
        None
    );

    // Reproduce the state changes that should happen at connection establishment
    cloned_state.tcp_state = TcpState::Established;
    cloned_state.rcv_nxt = CLIENT_ISN + SYN_BYTE;
    cloned_state.snd_una.advance_by(SYN_BYTE);
    cloned_state.snd_wnd = u16::MAX;

    assert_eq!(connections.try_get()?, &cloned_state);

    Ok(())
}
