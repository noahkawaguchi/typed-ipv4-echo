use {
    super::*,
    crate::protocol::test_utils::{DST_IP, IP_PAIR, SRC_IP},
    std::error::Error,
};

/// Connection key shared by tests in this module.
const KEY: ConnKey =
    ConnKey { client_ip: SRC_IP, client_port: 1234, server_ip: DST_IP, server_port: 80 };

/// Builds an incoming packet from the client (port 1234) to the server (port 80).
const fn client_packet(
    seq_num: u32,
    ack_num: u32,
    flags: TcpFlags,
    payload: &[u8],
) -> TcpHandler<'_> {
    TcpHandler {
        src_port: KEY.client_port,
        dst_port: KEY.server_port,
        seq_num,
        ack_num,
        offset_bytes: 20,
        flags,
        payload,
    }
}

/// Builds an expected reply from the server (port 80) to the client (port 1234).
const fn server_reply(
    seq_num: u32,
    ack_num: u32,
    flags: TcpFlags,
    payload: &[u8],
) -> TcpHandler<'_> {
    TcpHandler {
        src_port: KEY.server_port,
        dst_port: KEY.client_port,
        seq_num,
        ack_num,
        offset_bytes: 20,
        flags,
        payload,
    }
}

#[test]
fn reply_creates_valid_syn_ack() -> Result<(), Box<dyn Error>> {
    let mut connections = TcpConnections::new();

    let reply =
        client_packet(4096, 0, TcpFlags::Syn, &[]).create_reply(&mut connections, IP_PAIR)?;

    // seq_num is the random ISN that was stored in the connection table
    let stored_isn = connections
        .pending_isn(&KEY)
        .ok_or("ISN not stored in connection table")?;

    assert_eq!(reply, Some(server_reply(stored_isn, 4097, TcpFlags::SynAck, &[])));

    Ok(())
}

#[test]
fn data_packet_before_complete_handshake_gets_rst() -> Result<(), Box<dyn Error>> {
    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, 0); // SYN-ACK sent, but handshake not yet completed

    let reply =
        client_packet(4097, 1, TcpFlags::Ack, b"Hello").create_reply(&mut connections, IP_PAIR)?;

    assert_eq!(reply, Some(server_reply(1, 0, TcpFlags::Rst, &[])));

    Ok(())
}

#[test]
fn handshake_ack_establishes_connection_and_returns_none() -> Result<(), Box<dyn Error>> {
    let mut connections = TcpConnections::new();

    // Simulate having sent a SYN-ACK with ISN=0 so ack_num=1 is the correct completion
    connections.store_isn(KEY, 0);

    assert_eq!(
        client_packet(4097, 1, TcpFlags::Ack, &[]).create_reply(&mut connections, IP_PAIR)?,
        None
    );

    assert!(connections.is_established(&KEY));

    Ok(())
}

#[test]
fn reply_creates_valid_data_echo() -> Result<(), Box<dyn Error>> {
    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, 0);
    connections.establish(&KEY, 4097); // rcv_nxt = client's seq at handshake ACK time

    let reply =
        client_packet(4097, 1, TcpFlags::Ack, b"Hello").create_reply(&mut connections, IP_PAIR)?;

    assert_eq!(reply, Some(server_reply(1, 4102, TcpFlags::Ack, b"Hello")));

    Ok(())
}

#[test]
fn reply_creates_valid_fin_ack() -> Result<(), Box<dyn Error>> {
    // Simulate an established connection
    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, 0);
    connections.establish(&KEY, 4097); // FIN-ACK arrives at seq=4097

    let reply =
        client_packet(4097, 1, TcpFlags::FinAck, &[]).create_reply(&mut connections, IP_PAIR)?;

    assert_eq!(reply, Some(server_reply(1, 4098, TcpFlags::FinAck, &[])));

    // Connection is now in LAST-ACK state (waiting for client's final ACK), not yet removed
    assert!(connections.is_last_ack(&KEY));

    Ok(())
}

#[test]
fn final_ack_after_fin_ack_removes_connection_and_returns_none() -> Result<(), Box<dyn Error>> {
    // Simulates the client's final ACK completing the 4-step close. Should get no reply (not RST)
    // so the client can close cleanly from TIME-WAIT.

    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, 0);
    connections.establish(&KEY, 4097);
    connections.start_last_ack(&KEY);

    // ack=2 (our FIN-ACK seq + 1)
    assert_eq!(
        client_packet(4098, 2, TcpFlags::Ack, &[]).create_reply(&mut connections, IP_PAIR)?,
        None
    );

    assert!(!connections.is_last_ack(&KEY), "Connection should be removed after final ACK");

    Ok(())
}

#[test]
fn pure_ack_on_established_connection_returns_none() -> Result<(), Box<dyn Error>> {
    // Simulates the client ACKing the server's echo reply. This should get no reply (not RST) so
    // the connection stays open for more data.

    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, 0);
    connections.establish(&KEY, 4102); // rcv_nxt after having received "Hello" (4097 + 5)
    connections.advance_snd_nxt(&KEY, 5); // snd_nxt after having sent the 5-byte "Hello" echo

    // ack=6 (our ISN 0 + 5 bytes echoed + 1)
    assert_eq!(
        client_packet(4102, 6, TcpFlags::Ack, &[]).create_reply(&mut connections, IP_PAIR)?,
        None
    );

    assert!(connections.is_established(&KEY), "Connection should remain open after pure ACK");

    Ok(())
}

#[test]
fn consecutive_replies_use_snd_nxt_for_seq_num() -> Result<(), Box<dyn Error>> {
    // Verifies that the server updates and uses its own snd_nxt for seq_num rather than simply
    // mirroring the client's ack_num. After sending a 5-byte echo, snd_nxt=6, then the next reply's
    // seq_num must be 6 even when the client sends a stale ack_num=1.

    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, 0);
    connections.establish(&KEY, 4097);

    // First data packet: "Hello" (5 bytes), ack=1 (acknowledges our ISN+1)
    let reply1 =
        client_packet(4097, 1, TcpFlags::Ack, b"Hello").create_reply(&mut connections, IP_PAIR)?;

    assert_eq!(
        reply1,
        Some(server_reply(1, 4102, TcpFlags::Ack, b"Hello")),
        "Standard reply to the first data packet"
    );

    assert_eq!(
        connections.get_snd_nxt(&KEY),
        Some(6),
        "Stored snd_nxt should be 6 (1 + 5 bytes echoed) between replies"
    );

    // Second data packet: "Hi" (2 bytes), but with stale ack=1 (hasn't ACKed our "Hello" echo)
    let reply2 =
        client_packet(4102, 1, TcpFlags::Ack, b"Hi").create_reply(&mut connections, IP_PAIR)?;

    assert_eq!(
        reply2,
        Some(server_reply(6, 4104, TcpFlags::Ack, b"Hi")),
        "Server's seq_num should be snd_nxt=6, not client's stale ack_num=1"
    );

    Ok(())
}

#[test]
fn old_ack_num_does_not_regress_snd_una() -> Result<(), Box<dyn Error>> {
    // SND.UNA should only ever advance on a "new" ack (RFC 9293, Section 3.10.7.4). After two
    // exchanges bring SND.UNA up to 6, a third packet with a stale ack_num=1 (now older than
    // SND.UNA) must not move SND.UNA backward, even though the segment is otherwise processed
    // normally (seq_num still matches RCV.NXT).

    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, 0); // SND.UNA=0, SND.NXT=1
    connections.establish(&KEY, 4097); // RCV.NXT=4097

    // First packet: "Hello" (5 bytes), ack=1 -> SND.UNA advances to 1, SND.NXT becomes 6
    let reply1 =
        client_packet(4097, 1, TcpFlags::Ack, b"Hello").create_reply(&mut connections, IP_PAIR)?;

    assert_eq!(
        reply1,
        Some(server_reply(1, 4102, TcpFlags::Ack, b"Hello")),
        "Standard reply to the first data packet"
    );

    assert_eq!(connections.get_snd_una(&KEY), Some(1));

    // Second packet: "Hi" (2 bytes), ack=6 -> SND.UNA advances to 6, SND.NXT becomes 8
    let reply2 =
        client_packet(4102, 6, TcpFlags::Ack, b"Hi").create_reply(&mut connections, IP_PAIR)?;

    assert_eq!(
        reply2,
        Some(server_reply(6, 4104, TcpFlags::Ack, b"Hi")),
        "Standard reply to the second data packet"
    );

    assert_eq!(connections.get_snd_una(&KEY), Some(6));

    // Third packet: "Yo" (2 bytes), ack=1 (now stale, older than SND.UNA=6)
    let reply3 =
        client_packet(4104, 1, TcpFlags::Ack, b"Yo").create_reply(&mut connections, IP_PAIR)?;

    // The stale ack_num doesn't make the segment unacceptable (1 <= SND.NXT=8), so it's still
    // processed normally and "Yo" is echoed
    assert_eq!(
        reply3,
        Some(server_reply(8, 4106, TcpFlags::Ack, b"Yo")),
        "Stale ack_num shouldn't prevent normal processing"
    );

    assert_eq!(
        connections.get_snd_una(&KEY),
        Some(6),
        "Stale ack_num=1 must not move SND.UNA backward from 6"
    );

    Ok(())
}

#[test]
fn rst_packet_cleans_up_connection_and_returns_none() -> Result<(), Box<dyn Error>> {
    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, 0);
    connections.establish(&KEY, 4097);

    assert_eq!(
        client_packet(4097, 1, TcpFlags::Rst, &[]).create_reply(&mut connections, IP_PAIR)?,
        None
    );

    assert!(!connections.is_established(&KEY), "Connection should be removed after RST");

    Ok(())
}

#[test]
fn duplicate_data_packet_gets_duplicate_ack_without_echo() -> Result<(), Box<dyn Error>> {
    // A retransmitted segment should get a duplicate ACK pointing at the current rcv_nxt, not
    // another echo. Processing a second distinct packet first makes the seq_num check meaningful
    // because the retransmitted packet's seq+len points back to 4102, but rcv_nxt is 4104 after
    // both deliveries.

    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, 0);
    connections.establish(&KEY, 4097);

    let hello = client_packet(4097, 1, TcpFlags::Ack, b"Hello");
    let hi = client_packet(4102, 6, TcpFlags::Ack, b"Hi");

    // First packet: "Hello" (seq=4097) -> rcv_nxt advances to 4102, snd_nxt advances to 6
    let reply1 = hello.create_reply(&mut connections, IP_PAIR)?;
    assert_eq!(
        reply1,
        Some(server_reply(1, 4102, TcpFlags::Ack, b"Hello")),
        "Standard reply to the first data packet"
    );

    // Second packet: "Hi" (seq=4102) -> rcv_nxt advances to 4104, snd_nxt advances to 8
    let reply2 = hi.create_reply(&mut connections, IP_PAIR)?;
    assert_eq!(
        reply2,
        Some(server_reply(6, 4104, TcpFlags::Ack, b"Hi")),
        "Standard reply to the second data packet"
    );

    // Retransmit of "Hello": seq=4097, but rcv_nxt is now 4104
    let reply3 = hello.create_reply(&mut connections, IP_PAIR)?;

    assert_eq!(
        reply3,
        Some(server_reply(8, 4104, TcpFlags::Ack, &[])),
        "Duplicate ACK should ack rcv_nxt=4104 with no payload, not echo seq+len=4102"
    );

    Ok(())
}

#[test]
fn out_of_order_fin_ack_gets_duplicate_ack_without_closing() -> Result<(), Box<dyn Error>> {
    // A FIN-ACK arriving before data preceding it (seq_num != rcv_nxt, e.g. an earlier data segment
    // was lost) must not be processed yet. Doing so would signal "no more data" before the missing
    // data has been delivered. Until the gap is filled, treat it like out-of-order data by sending
    // a duplicate ACK reflecting the current rcv_nxt with no change to local state.

    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, 0);
    connections.establish(&KEY, 4097); // rcv_nxt = 4097

    // FIN-ACK arrives at seq=4102, but rcv_nxt is still 4097 (a 5-byte gap)
    let reply =
        client_packet(4102, 1, TcpFlags::FinAck, &[]).create_reply(&mut connections, IP_PAIR)?;

    assert_eq!(
        reply,
        Some(server_reply(1, 4097, TcpFlags::Ack, &[])),
        "Out-of-order FIN-ACK should get a duplicate ACK reflecting rcv_nxt=4097, not a FIN-ACK \
         in response"
    );

    assert!(
        connections.is_established(&KEY),
        "Connection must remain established, out-of-order FIN-ACK must not start closing"
    );

    Ok(())
}

#[test]
fn unrecognized_packet_for_unknown_connection_gets_rst() -> Result<(), Box<dyn Error>> {
    // ACK with payload for a connection the server has no record of (e.g. after restart)

    let mut connections = TcpConnections::new(); // Empty, no known connections

    let reply =
        client_packet(4097, 1, TcpFlags::Ack, b"Hello").create_reply(&mut connections, IP_PAIR)?;

    assert_eq!(reply, Some(server_reply(1, 0, TcpFlags::Rst, &[])));

    Ok(())
}

#[test]
fn ack_for_unsent_data_is_dropped_and_gets_current_state_reply() -> Result<(), Box<dyn Error>> {
    // Per RFC 9293 Section 3.10.7.4, an ACK acknowledging data the server hasn't sent yet (ack_num
    // past SND.NXT) must be dropped, and the reply should be a bare ACK reflecting the current
    // SND.NXT/RCV.NXT, with no payload echoed and no state change. seq_num matches RCV.NXT, so this
    // would otherwise be treated as valid in-order data.

    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, 0); // SND.NXT = 1
    connections.establish(&KEY, 4097); // RCV.NXT = 4097

    // seq_num == RCV.NXT, but ack_num=1000 is far past SND.NXT=1
    let reply = client_packet(4097, 1000, TcpFlags::Ack, b"Hello")
        .create_reply(&mut connections, IP_PAIR)?;

    assert_eq!(reply, Some(server_reply(1, 4097, TcpFlags::Ack, &[])));

    // State must be untouched
    assert_eq!(connections.get_snd_nxt(&KEY), Some(1));
    assert_eq!(connections.get_rcv_nxt(&KEY), Some(4097));
    assert_eq!(connections.get_snd_una(&KEY), Some(0));

    Ok(())
}

#[test]
fn wraparound_ack_for_unsent_data_is_still_rejected() -> Result<(), Box<dyn Error>> {
    // ISNs are random (RFC 9293, Section 3.4.1) and can land near `u32::MAX`, wrapping SND.NXT to a
    // small value. An ack_num that wraps one past SND.NXT must still be recognized as acknowledging
    // unsent data, even though a naive numeric comparison (ack_num > snd_nxt) would say 0 >
    // `u32::MAX` is false and let it through.

    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, u32::MAX - 1); // SND.UNA=MAX-1, SND.NXT=MAX
    connections.establish(&KEY, 4097); // RCV.NXT=4097
    connections.update_snd_una(&KEY, u32::MAX); // simulate handshake ack completing

    // ack=0 wraps 1 past SND.NXT = u32::MAX
    let reply =
        client_packet(4097, 0, TcpFlags::Ack, &[]).create_reply(&mut connections, IP_PAIR)?;

    assert_eq!(reply, Some(server_reply(u32::MAX, 4097, TcpFlags::Ack, &[])));

    // State must be untouched
    assert_eq!(connections.get_snd_nxt(&KEY), Some(u32::MAX));
    assert_eq!(connections.get_rcv_nxt(&KEY), Some(4097));
    assert_eq!(connections.get_snd_una(&KEY), Some(u32::MAX));

    Ok(())
}

#[test]
fn close_established_sends_fin_ack_and_transitions_to_fin_wait_1() -> Result<(), Box<dyn Error>> {
    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, 0);
    connections.establish(&KEY, 4097); // snd_nxt=1, rcv_nxt=4097

    let mut replies = TcpHandler::close_established(&mut connections);
    let (reply, ip_pair) = replies.pop().ok_or("Expected one reply")?;

    assert!(replies.is_empty(), "Expected exactly one reply");
    assert_eq!(reply, server_reply(1, 4097, TcpFlags::FinAck, &[]));

    // IP addresses are swapped: server -> client
    assert_eq!(ip_pair.src, DST_IP);
    assert_eq!(ip_pair.dst, SRC_IP);

    assert!(connections.is_fin_wait_1(&KEY));
    assert_eq!(connections.get_snd_nxt(&KEY), Some(2), "FIN consumes one sequence number");

    Ok(())
}

#[test]
fn fin_wait_1_to_fin_wait_2_on_ack_of_our_fin() -> Result<(), Box<dyn Error>> {
    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, 0);
    connections.establish(&KEY, 4097);
    TcpHandler::close_established(&mut connections); // -> FIN-WAIT-1, snd_nxt=2

    // Client acknowledges our FIN (ack=2), no FIN of its own yet
    let reply =
        client_packet(4097, 2, TcpFlags::Ack, &[]).create_reply(&mut connections, IP_PAIR)?;

    assert_eq!(reply, None);
    assert!(connections.is_fin_wait_2(&KEY));
    assert_eq!(connections.get_snd_una(&KEY), Some(2));

    Ok(())
}

#[test]
fn fin_wait_2_closes_on_fin_ack_from_peer() -> Result<(), Box<dyn Error>> {
    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, 0);
    connections.establish(&KEY, 4097);
    TcpHandler::close_established(&mut connections); // -> FIN-WAIT-1, snd_nxt=2

    // Our FIN is acknowledged -> FIN-WAIT-2
    let ack_reply =
        client_packet(4097, 2, TcpFlags::Ack, &[]).create_reply(&mut connections, IP_PAIR)?;

    assert_eq!(ack_reply, None);
    assert!(connections.is_fin_wait_2(&KEY));

    // Client's FIN arrives in order
    let fin_reply =
        client_packet(4097, 2, TcpFlags::FinAck, &[]).create_reply(&mut connections, IP_PAIR)?;

    assert_eq!(fin_reply, Some(server_reply(2, 4098, TcpFlags::Ack, &[])));
    assert_eq!(connections.get_snd_nxt(&KEY), None, "Connection should be removed");

    Ok(())
}

#[test]
fn fin_wait_1_closes_immediately_if_peers_fin_also_acks_ours() -> Result<(), Box<dyn Error>> {
    // Simultaneous close where the peer's FIN, arriving while we're still in FIN-WAIT-1, also
    // acknowledges our FIN -> fully closed immediately, skipping FIN-WAIT-2/CLOSING.

    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, 0);
    connections.establish(&KEY, 4097);
    TcpHandler::close_established(&mut connections); // -> FIN-WAIT-1, snd_nxt=2

    // Client's FIN arrives in order and also acknowledges our FIN (ack=2)
    let reply =
        client_packet(4097, 2, TcpFlags::FinAck, &[]).create_reply(&mut connections, IP_PAIR)?;

    assert_eq!(reply, Some(server_reply(2, 4098, TcpFlags::Ack, &[])));
    assert_eq!(connections.get_snd_nxt(&KEY), None, "Connection should be removed immediately");

    Ok(())
}

#[test]
fn simultaneous_close_transitions_through_closing_to_closed() -> Result<(), Box<dyn Error>> {
    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, 0);
    connections.establish(&KEY, 4097);
    TcpHandler::close_established(&mut connections); // -> FIN-WAIT-1, snd_nxt=2

    // Client's FIN arrives in order, but doesn't yet acknowledge our FIN (ack=1, simultaneous
    // close) -> CLOSING
    let fin_reply =
        client_packet(4097, 1, TcpFlags::FinAck, &[]).create_reply(&mut connections, IP_PAIR)?;

    assert_eq!(fin_reply, Some(server_reply(2, 4098, TcpFlags::Ack, &[])));
    assert!(connections.is_simultaneous_closing(&KEY));

    // Client's ACK of our FIN finally arrives -> fully closed
    let ack_reply =
        client_packet(4098, 2, TcpFlags::Ack, &[]).create_reply(&mut connections, IP_PAIR)?;

    assert_eq!(ack_reply, None);
    assert_eq!(connections.get_snd_nxt(&KEY), None, "Connection should be removed");

    Ok(())
}
