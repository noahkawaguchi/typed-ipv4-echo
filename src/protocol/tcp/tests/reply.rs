use super::*;
use crate::protocol::test_utils::{DST_IP, IP_PAIR, SRC_IP, tcp_udp_test_checksum};
use std::error::Error;

#[test]
fn reply_creates_valid_syn_ack() -> Result<(), Box<dyn Error>> {
    #[rustfmt::skip]
        const SYN_PACKET: [u8; 20] = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x10, 0x00,              // Sequence number: 4096
            0x00, 0x00, 0x00, 0x00,              // Ack number: 0
            0x50, 0x02,                          // Data offset: 5, Flags: SYN
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

    let handler = TcpHandler::parse(&SYN_PACKET)?;
    let mut connections = TcpConnections::new();
    let mut reply = [0u8; ETHERNET_MTU];

    let tcp_len = handler
        .create_reply(&mut connections, IP_PAIR)?
        .ok_or("Unexpected None reply")?
        .write_into(&mut reply[20..], IP_PAIR)?;

    // Verify TCP header at offset 20
    assert_eq!(&reply[20..22], &[0x00, 0x50]); // Source port: 80 (swapped)
    assert_eq!(&reply[22..24], &[0x04, 0xd2]); // Dest port: 1234 (swapped)

    // Seq: the random ISN that was stored in the connection table
    let stored_isn = connections
        .pending_isn(&ConnKey {
            client_ip: SRC_IP,
            client_port: 1234,
            server_ip: DST_IP,
            server_port: 80,
        })
        .ok_or("ISN not stored in connection table")?;

    let seq_bytes: [u8; 4] = reply[24..28]
        .try_into()
        .map_err(|_| "slice length mismatch")?;

    assert_eq!(u32::from_be_bytes(seq_bytes), stored_isn);

    assert_eq!(&reply[28..32], &[0x00, 0x00, 0x10, 0x01]); // Ack: 4097 (client seq + 1)
    assert_eq!(reply[33], 0x12); // Flags: SYN|ACK

    // Verify TCP length (no payload for SYN-ACK)
    assert_eq!(tcp_len, 20);

    // Verify checksum
    assert_eq!(
        tcp_udp_test_checksum(&reply, Protocol::Tcp, tcp_len, IP_PAIR)?,
        0x0000
    );

    Ok(())
}

#[test]
fn data_packet_before_complete_handshake_gets_rst() -> Result<(), Box<dyn Error>> {
    #[rustfmt::skip]
        const DATA_PACKET: [u8; 25] = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x10, 0x01,              // Sequence number: 4097
            0x00, 0x00, 0x00, 0x01,              // Ack number: 1
            0x50, 0x10,                          // Data offset: 5, Flags: ACK
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
            0x48, 0x65, 0x6c, 0x6c, 0x6f,        // Payload: "Hello"
        ];

    let mut connections = TcpConnections::new();

    // Store an ISN as if we sent a SYN-ACK, but never transition to Established
    let key = ConnKey { client_ip: SRC_IP, client_port: 1234, server_ip: DST_IP, server_port: 80 };
    connections.store_isn(key, 0);

    assert_matches!(
        TcpHandler::parse(&DATA_PACKET)?.create_reply(&mut connections, IP_PAIR)?,
        Some(reply) if reply.flags == TcpFlags::Rst
    );

    Ok(())
}

#[test]
fn handshake_ack_establishes_connection_and_returns_none() -> Result<(), Box<dyn Error>> {
    #[rustfmt::skip]
        const ACK_PACKET: [u8; 20] = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x10, 0x01,              // Sequence number: 4097
            0x00, 0x00, 0x00, 0x01,              // Ack number: 1 (our ISN 0 + 1)
            0x50, 0x10,                          // Data offset: 5, Flags: ACK
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

    let mut connections = TcpConnections::new();

    // Simulate having sent a SYN-ACK with ISN=0 so ack_num=1 is the correct completion
    let key = ConnKey { client_ip: SRC_IP, client_port: 1234, server_ip: DST_IP, server_port: 80 };
    connections.store_isn(key, 0);

    assert_eq!(
        TcpHandler::parse(&ACK_PACKET)?.create_reply(&mut connections, IP_PAIR)?,
        None
    );

    assert!(connections.is_established(&key));

    Ok(())
}

#[test]
fn reply_creates_valid_data_echo() -> Result<(), Box<dyn Error>> {
    #[rustfmt::skip]
        const DATA_PACKET: [u8; 25] = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x10, 0x01,              // Sequence number: 4097
            0x00, 0x00, 0x00, 0x01,              // Ack number: 1
            0x50, 0x10,                          // Data offset: 5, Flags: ACK
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
            0x48, 0x65, 0x6c, 0x6c, 0x6f,        // Payload: "Hello"
        ];

    let handler = TcpHandler::parse(&DATA_PACKET)?;
    let mut connections = TcpConnections::new();

    // Simulate a completed handshake (ISN=0, so client's ack_num of 1 is consistent)
    let key = ConnKey { client_ip: SRC_IP, client_port: 1234, server_ip: DST_IP, server_port: 80 };
    connections.store_isn(key, 0);
    connections.establish(&key, 4097); // rcv_nxt = client's seq at handshake ACK time

    let mut reply = [0u8; ETHERNET_MTU];

    let tcp_len = handler
        .create_reply(&mut connections, IP_PAIR)?
        .ok_or("Unexpected None reply")?
        .write_into(&mut reply[20..], IP_PAIR)?;

    // Verify TCP header
    assert_eq!(&reply[20..22], &[0x00, 0x50]); // Source port: 80
    assert_eq!(&reply[22..24], &[0x04, 0xd2]); // Dest port: 1234
    assert_eq!(&reply[24..28], &[0x00, 0x00, 0x00, 0x01]); // Seq: 1 (client's ack_num)
    assert_eq!(&reply[28..32], &[0x00, 0x00, 0x10, 0x06]); // Ack: 4102 (seq + 5)
    assert_eq!(reply[33], 0x10); // Flags: ACK only

    // Verify payload echoed
    assert_eq!(&reply[40..45], b"Hello");

    // Verify TCP length
    assert_eq!(tcp_len, 20 + 5);

    // Verify checksum
    assert_eq!(
        tcp_udp_test_checksum(&reply, Protocol::Tcp, tcp_len, IP_PAIR)?,
        0x0000
    );

    Ok(())
}

#[test]
fn reply_creates_valid_fin_ack() -> Result<(), Box<dyn Error>> {
    #[rustfmt::skip]
        const FIN_ACK_PACKET: [u8; 20] = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x10, 0x01,              // Sequence number: 4097
            0x00, 0x00, 0x00, 0x01,              // Ack number: 1 (our ISN + 1)
            0x50, 0x11,                          // Data offset: 5, Flags: FIN|ACK
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

    let handler = TcpHandler::parse(&FIN_ACK_PACKET)?;
    let mut connections = TcpConnections::new();

    // Simulate an established connection
    let conn_key =
        ConnKey { client_ip: SRC_IP, client_port: 1234, server_ip: DST_IP, server_port: 80 };
    connections.store_isn(conn_key, 0);
    connections.establish(&conn_key, 4097); // FIN-ACK arrives at seq=4097

    let mut reply = [0u8; ETHERNET_MTU];
    let tcp_len = handler
        .create_reply(&mut connections, IP_PAIR)?
        .ok_or("Unexpected None reply")?
        .write_into(&mut reply[20..], IP_PAIR)?;

    // Ports swapped
    assert_eq!(&reply[20..22], &[0x00, 0x50]); // src: 80
    assert_eq!(&reply[22..24], &[0x04, 0xd2]); // dst: 1234

    // seq = client's ack_num (1), ack = client's seq_num + 1 (4098 = 0x1002)
    assert_eq!(&reply[24..28], &[0x00, 0x00, 0x00, 0x01]);
    assert_eq!(&reply[28..32], &[0x00, 0x00, 0x10, 0x02]);

    // Flags: FIN|ACK = 0x11
    assert_eq!(reply[33], 0x11);

    // No payload
    assert_eq!(tcp_len, 20);

    // Connection is now in Closing state (waiting for client's final ACK), not yet removed
    assert!(connections.is_closing(&conn_key));

    // Verify checksum
    assert_eq!(
        tcp_udp_test_checksum(&reply, Protocol::Tcp, tcp_len, IP_PAIR)?,
        0x0000
    );

    Ok(())
}

#[test]
fn final_ack_after_fin_ack_removes_connection_and_returns_none() -> Result<(), Box<dyn Error>> {
    // Simulates the client's final ACK completing the 4-step close. Should get no reply (not RST)
    // so the client can close cleanly from TIME-WAIT.
    #[rustfmt::skip]
    const FINAL_ACK: [u8; 20] = [
        0x04, 0xd2,                          // Source port: 1234
        0x00, 0x50,                          // Dest port: 80
        0x00, 0x00, 0x10, 0x02,              // Sequence number: 4098
        0x00, 0x00, 0x00, 0x02,              // Ack number: 2 (our FIN-ACK seq + 1)
        0x50, 0x10,                          // Data offset: 5, Flags: ACK
        0xff, 0xff,                          // Window size
        0x00, 0x00,                          // Checksum
        0x00, 0x00,                          // Urgent pointer
    ];

    let mut connections = TcpConnections::new();
    let key = ConnKey { client_ip: SRC_IP, client_port: 1234, server_ip: DST_IP, server_port: 80 };
    connections.store_isn(key, 0);
    connections.establish(&key, 4097);
    connections.start_closing(&key);

    assert_eq!(
        TcpHandler::parse(&FINAL_ACK)?.create_reply(&mut connections, IP_PAIR)?,
        None
    );

    assert!(
        !connections.is_closing(&key),
        "connection should be removed after final ACK"
    );

    Ok(())
}

#[test]
fn pure_ack_on_established_connection_returns_none() -> Result<(), Box<dyn Error>> {
    // Simulates the client ACKing the server's echo reply. This should get no reply (not RST) so
    // the connection stays open for more data.
    #[rustfmt::skip]
    const ACK_PACKET: [u8; 20] = [
        0x04, 0xd2,                          // Source port: 1234
        0x00, 0x50,                          // Dest port: 80
        0x00, 0x00, 0x10, 0x06,              // Sequence number: 4102
        0x00, 0x00, 0x00, 0x06,              // Ack number: 6 (our ISN 0 + 5 bytes echoed + 1)
        0x50, 0x10,                          // Data offset: 5, Flags: ACK
        0xff, 0xff,                          // Window size
        0x00, 0x00,                          // Checksum
        0x00, 0x00,                          // Urgent pointer
    ];

    let mut connections = TcpConnections::new();
    let key = ConnKey { client_ip: SRC_IP, client_port: 1234, server_ip: DST_IP, server_port: 80 };
    connections.store_isn(key, 0);
    connections.establish(&key, 4102); // rcv_nxt after having received "Hello" (4097 + 5)
    connections.advance_snd_nxt(&key, 5); // snd_nxt after having sent the 5-byte "Hello" echo

    assert_eq!(
        TcpHandler::parse(&ACK_PACKET)?.create_reply(&mut connections, IP_PAIR)?,
        None
    );

    assert!(
        connections.is_established(&key),
        "connection should remain open after pure ACK"
    );

    Ok(())
}

#[test]
fn consecutive_replies_use_snd_nxt_for_seq_num() -> Result<(), Box<dyn Error>> {
    // Verifies that the server updates and uses its own snd_nxt for seq_num rather than simply
    // mirroring the client's ack_num. After sending a 5-byte echo, snd_nxt=6, then the next reply's
    // seq_num must be 6 even when the client sends a stale ack_num=1.

    const KEY: ConnKey =
        ConnKey { client_ip: SRC_IP, client_port: 1234, server_ip: DST_IP, server_port: 80 };

    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, 0);
    connections.establish(&KEY, 4097);

    // First data packet: "Hello" (5 bytes), ack=1 (acknowledges our ISN+1)
    #[rustfmt::skip]
    let first_packet = [
        0x04, 0xd2, 0x00, 0x50,              // Ports: 1234 -> 80
        0x00, 0x00, 0x10, 0x01,              // seq: 4097
        0x00, 0x00, 0x00, 0x01,              // ack: 1
        0x50, 0x10,                          // Data offset: 5, Flags: ACK
        0xff, 0xff, 0x00, 0x00, 0x00, 0x00,  // Window, checksum, urgent
        0x48, 0x65, 0x6c, 0x6c, 0x6f,        // "Hello"
    ];

    let mut reply1 = [0u8; ETHERNET_MTU];
    TcpHandler::parse(&first_packet)?
        .create_reply(&mut connections, IP_PAIR)?
        .ok_or("Unexpected None reply to first packet")?
        .write_into(&mut reply1[20..], IP_PAIR)?;

    assert_eq!(
        connections.get_snd_nxt(&KEY),
        Some(6),
        "Stored snd_nxt should be 6 (1 + 5 bytes echoed) between replies"
    );

    // Second data packet: "Hi" (2 bytes), but with stale ack=1 (hasn't ACKed our "Hello" echo)
    #[rustfmt::skip]
    let second_packet = [
        0x04, 0xd2, 0x00, 0x50,              // Ports: 1234 -> 80
        0x00, 0x00, 0x10, 0x06,              // seq: 4102
        0x00, 0x00, 0x00, 0x01,              // ack: 1 (stale, hasn't ACKed our "Hello")
        0x50, 0x10,                          // Data offset: 5, Flags: ACK
        0xff, 0xff, 0x00, 0x00, 0x00, 0x00,  // Window, checksum, urgent
        0x48, 0x69,                          // "Hi"
    ];

    let mut reply2 = [0u8; ETHERNET_MTU];
    TcpHandler::parse(&second_packet)?
        .create_reply(&mut connections, IP_PAIR)?
        .ok_or("Unexpected None reply to second packet")?
        .write_into(&mut reply2[20..], IP_PAIR)?;

    assert_matches!(
        reply2[24..28].try_into().map(u32::from_be_bytes),
        Ok(6),
        "Server's seq_num should be snd_nxt=6, not client's stale ack_num=1"
    );

    assert_matches!(
        reply2[28..32].try_into().map(u32::from_be_bytes),
        Ok(4104),
        "Server's ack_num should be client's seq_num 4102 + 2 bytes = 4104"
    );

    Ok(())
}

#[test]
fn old_ack_num_does_not_regress_snd_una() -> Result<(), Box<dyn Error>> {
    // SND.UNA should only ever advance on a "new" ack (RFC 9293, Section 3.10.7.4). After two
    // exchanges bring SND.UNA up to 6, a third packet with a stale ack_num=1 (now older than
    // SND.UNA) must not move SND.UNA backward, even though the segment is otherwise processed
    // normally (seq_num still matches RCV.NXT).

    const KEY: ConnKey =
        ConnKey { client_ip: SRC_IP, client_port: 1234, server_ip: DST_IP, server_port: 80 };

    let mut connections = TcpConnections::new();
    connections.store_isn(KEY, 0); // SND.UNA=0, SND.NXT=1
    connections.establish(&KEY, 4097); // RCV.NXT=4097

    // First packet: "Hello" (5 bytes), ack=1 -> SND.UNA advances to 1, SND.NXT becomes 6
    #[rustfmt::skip]
    let first_packet = [
        0x04, 0xd2, 0x00, 0x50,              // Ports: 1234 -> 80
        0x00, 0x00, 0x10, 0x01,              // seq: 4097
        0x00, 0x00, 0x00, 0x01,              // ack: 1
        0x50, 0x10,                          // Data offset: 5, Flags: ACK
        0xff, 0xff, 0x00, 0x00, 0x00, 0x00,  // Window, checksum, urgent
        0x48, 0x65, 0x6c, 0x6c, 0x6f,        // "Hello"
    ];

    TcpHandler::parse(&first_packet)?
        .create_reply(&mut connections, IP_PAIR)?
        .ok_or("Unexpected None reply to first packet")?;

    assert_eq!(connections.get_snd_una(&KEY), Some(1));

    // Second packet: "Hi" (2 bytes), ack=6 -> SND.UNA advances to 6, SND.NXT becomes 8
    #[rustfmt::skip]
    let second_packet = [
        0x04, 0xd2, 0x00, 0x50,              // Ports: 1234 -> 80
        0x00, 0x00, 0x10, 0x06,              // seq: 4102
        0x00, 0x00, 0x00, 0x06,              // ack: 6
        0x50, 0x10,                          // Data offset: 5, Flags: ACK
        0xff, 0xff, 0x00, 0x00, 0x00, 0x00,  // Window, checksum, urgent
        0x48, 0x69,                          // "Hi"
    ];

    TcpHandler::parse(&second_packet)?
        .create_reply(&mut connections, IP_PAIR)?
        .ok_or("Unexpected None reply to second packet")?;

    assert_eq!(connections.get_snd_una(&KEY), Some(6));

    // Third packet: "Yo" (2 bytes), ack=1 (now stale, older than SND.UNA=6)
    #[rustfmt::skip]
    let third_packet = [
        0x04, 0xd2, 0x00, 0x50,              // Ports: 1234 -> 80
        0x00, 0x00, 0x10, 0x08,              // seq: 4104
        0x00, 0x00, 0x00, 0x01,              // ack: 1 (stale)
        0x50, 0x10,                          // Data offset: 5, Flags: ACK
        0xff, 0xff, 0x00, 0x00, 0x00, 0x00,  // Window, checksum, urgent
        0x59, 0x6f,                          // "Yo"
    ];

    let mut reply3 = [0u8; ETHERNET_MTU];
    let tcp_len = TcpHandler::parse(&third_packet)?
        .create_reply(&mut connections, IP_PAIR)?
        .ok_or("Unexpected None reply to third packet")?
        .write_into(&mut reply3[20..], IP_PAIR)?;

    // The stale ack_num doesn't make the segment unacceptable (1 <= SND.NXT=8), so it's still
    // processed normally and "Yo" is echoed
    assert_eq!(
        tcp_len,
        20 + 2,
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
    #[rustfmt::skip]
    const RST_PACKET: [u8; 20] = [
        0x04, 0xd2,                          // Source port: 1234
        0x00, 0x50,                          // Dest port: 80
        0x00, 0x00, 0x10, 0x01,              // Sequence number: 4097
        0x00, 0x00, 0x00, 0x01,              // Ack number: 1
        0x50, 0x04,                          // Data offset: 5, Flags: RST
        0xff, 0xff,                          // Window size
        0x00, 0x00,                          // Checksum
        0x00, 0x00,                          // Urgent pointer
    ];

    let mut connections = TcpConnections::new();
    let key = ConnKey { client_ip: SRC_IP, client_port: 1234, server_ip: DST_IP, server_port: 80 };
    connections.store_isn(key, 0);
    connections.establish(&key, 4097);

    assert_eq!(
        TcpHandler::parse(&RST_PACKET)?.create_reply(&mut connections, IP_PAIR)?,
        None
    );

    assert!(
        !connections.is_established(&key),
        "connection should be removed after RST"
    );

    Ok(())
}

#[test]
fn duplicate_data_packet_gets_duplicate_ack_without_echo() -> Result<(), Box<dyn Error>> {
    // A retransmitted segment should get a duplicate ACK pointing at the current rcv_nxt, not
    // another echo. Processing a second distinct packet first makes the ack_num check meaningful
    // because the retransmitted packet's seq+len points back to 4102, but rcv_nxt is 4104 after
    // both deliveries.

    #[rustfmt::skip]
    const HELLO_PACKET: [u8; 25] = [
        0x04, 0xd2,                          // Source port: 1234
        0x00, 0x50,                          // Dest port: 80
        0x00, 0x00, 0x10, 0x01,              // seq: 4097
        0x00, 0x00, 0x00, 0x01,              // ack: 1
        0x50, 0x10,                          // Data offset: 5, Flags: ACK
        0xff, 0xff,                          // Window size
        0x00, 0x00,                          // Checksum
        0x00, 0x00,                          // Urgent pointer
        0x48, 0x65, 0x6c, 0x6c, 0x6f,        // Payload: "Hello" (5 bytes)
    ];

    #[rustfmt::skip]
    const HI_PACKET: [u8; 22] = [
        0x04, 0xd2,                          // Source port: 1234
        0x00, 0x50,                          // Dest port: 80
        0x00, 0x00, 0x10, 0x06,              // seq: 4102
        0x00, 0x00, 0x00, 0x06,              // ack: 6
        0x50, 0x10,                          // Data offset: 5, Flags: ACK
        0xff, 0xff,                          // Window size
        0x00, 0x00,                          // Checksum
        0x00, 0x00,                          // Urgent pointer
        0x48, 0x69,                          // Payload: "Hi" (2 bytes)
    ];

    let mut connections = TcpConnections::new();
    let key = ConnKey { client_ip: SRC_IP, client_port: 1234, server_ip: DST_IP, server_port: 80 };
    connections.store_isn(key, 0);
    connections.establish(&key, 4097);

    // First packet: "Hello" (seq=4097) -> rcv_nxt advances to 4102
    TcpHandler::parse(&HELLO_PACKET)?
        .create_reply(&mut connections, IP_PAIR)?
        .ok_or("Unexpected None reply for first packet")?;

    // Second packet: "Hi" (seq=4102) -> rcv_nxt advances to 4104
    TcpHandler::parse(&HI_PACKET)?
        .create_reply(&mut connections, IP_PAIR)?
        .ok_or("Unexpected None reply for second packet")?;

    // Retransmit of "Hello": seq=4097, but rcv_nxt is now 4104
    let mut reply_buf = [0u8; ETHERNET_MTU];
    let tcp_len = TcpHandler::parse(&HELLO_PACKET)?
        .create_reply(&mut connections, IP_PAIR)?
        .ok_or("Unexpected None for duplicate ACK reply")?
        .write_into(&mut reply_buf[20..], IP_PAIR)?;

    assert_eq!(tcp_len, 20, "Duplicate ACK should carry no payload");

    assert_matches!(
        reply_buf[28..32].try_into().map(u32::from_be_bytes),
        Ok(4104),
        "ack_num should be rcv_nxt=4104, not seq+len=4097+5=4102"
    );

    Ok(())
}

#[test]
fn unrecognized_packet_for_unknown_connection_gets_rst() -> Result<(), Box<dyn Error>> {
    // ACK with payload for a connection the server has no record of (e.g. after restart)
    #[rustfmt::skip]
    const DATA_PACKET: [u8; 25] = [
        0x04, 0xd2,                          // Source port: 1234
        0x00, 0x50,                          // Dest port: 80
        0x00, 0x00, 0x10, 0x01,              // Sequence number: 4097
        0x00, 0x00, 0x00, 0x01,              // Ack number: 1
        0x50, 0x10,                          // Data offset: 5, Flags: ACK
        0xff, 0xff,                          // Window size
        0x00, 0x00,                          // Checksum
        0x00, 0x00,                          // Urgent pointer
        0x48, 0x65, 0x6c, 0x6c, 0x6f,        // Payload: "Hello"
    ];

    let mut connections = TcpConnections::new(); // Empty, no known connections

    let reply = TcpHandler::parse(&DATA_PACKET)?
        .create_reply(&mut connections, IP_PAIR)?
        .ok_or("expected RST reply, got None")?;

    let mut buf = [0u8; ETHERNET_MTU];
    reply.write_into(&mut buf, IP_PAIR)?;

    assert_eq!(&buf[0..2], &[0x00, 0x50]); // src port: 80 (swapped)
    assert_eq!(&buf[2..4], &[0x04, 0xd2]); // dst port: 1234 (swapped)
    assert_eq!(buf[13], 0x04); // flags: RST only

    Ok(())
}

#[test]
fn ack_for_unsent_data_is_dropped_and_gets_current_state_reply() -> Result<(), Box<dyn Error>> {
    // Per RFC 9293 Section 3.10.7.4, an ACK acknowledging data the server hasn't sent yet (ack_num
    // past SND.NXT) must be dropped, and the reply should be a bare ACK reflecting the current
    // SND.NXT/RCV.NXT, with no payload echoed and no state change. seq_num matches RCV.NXT, so this
    // would otherwise be treated as valid in-order data.

    #[rustfmt::skip]
    const BAD_ACK_PACKET: [u8; 25] = [
        0x04, 0xd2,                          // Source port: 1234
        0x00, 0x50,                          // Dest port: 80
        0x00, 0x00, 0x10, 0x01,              // Sequence number: 4097 (== RCV.NXT)
        0x00, 0x00, 0x03, 0xe8,              // Ack number: 1000 (SND.NXT is only 1)
        0x50, 0x10,                          // Data offset: 5, Flags: ACK
        0xff, 0xff,                          // Window size
        0x00, 0x00,                          // Checksum
        0x00, 0x00,                          // Urgent pointer
        0x48, 0x65, 0x6c, 0x6c, 0x6f,        // Payload: "Hello"
    ];

    let mut connections = TcpConnections::new();
    let key = ConnKey { client_ip: SRC_IP, client_port: 1234, server_ip: DST_IP, server_port: 80 };
    connections.store_isn(key, 0); // SND.NXT = 1
    connections.establish(&key, 4097); // RCV.NXT = 4097

    let mut reply = [0u8; ETHERNET_MTU];
    let tcp_len = TcpHandler::parse(&BAD_ACK_PACKET)?
        .create_reply(&mut connections, IP_PAIR)?
        .ok_or("Unexpected None reply")?
        .write_into(&mut reply[20..], IP_PAIR)?;

    assert_eq!(tcp_len, 20, "No payload should be echoed");
    assert_eq!(&reply[24..28], &[0x00, 0x00, 0x00, 0x01]); // seq = SND.NXT = 1
    assert_eq!(&reply[28..32], &[0x00, 0x00, 0x10, 0x01]); // ack = RCV.NXT = 4097
    assert_eq!(reply[33], 0x10); // ACK only

    // State must be untouched
    assert_eq!(connections.get_snd_nxt(&key), Some(1));
    assert_eq!(connections.get_rcv_nxt(&key), Some(4097));
    assert_eq!(connections.get_snd_una(&key), Some(0));

    Ok(())
}

#[test]
fn wraparound_ack_for_unsent_data_is_still_rejected() -> Result<(), Box<dyn Error>> {
    // ISNs are random (RFC 9293, Section 3.4.1) and can land near `u32::MAX`, wrapping SND.NXT to a
    // small value. An ack_num that wraps one past SND.NXT must still be recognized as acknowledging
    // unsent data, even though a naive numeric comparison (ack_num > snd_nxt) would say 0 >
    // `u32::MAX` is false and let it through.

    #[rustfmt::skip]
    const WRAPPED_ACK_PACKET: [u8; 20] = [
        0x04, 0xd2,                          // Source port: 1234
        0x00, 0x50,                          // Dest port: 80
        0x00, 0x00, 0x10, 0x01,              // Sequence number: 4097
        0x00, 0x00, 0x00, 0x00,              // Ack number: 0 (wraps 1 past SND.NXT = u32::MAX)
        0x50, 0x10,                          // Data offset: 5, Flags: ACK
        0xff, 0xff,                          // Window size
        0x00, 0x00,                          // Checksum
        0x00, 0x00,                          // Urgent pointer
    ];

    let mut connections = TcpConnections::new();
    let key = ConnKey { client_ip: SRC_IP, client_port: 1234, server_ip: DST_IP, server_port: 80 };
    connections.store_isn(key, u32::MAX - 1); // SND.UNA=MAX-1, SND.NXT=MAX
    connections.establish(&key, 4097); // RCV.NXT=4097
    connections.update_snd_una(&key, u32::MAX); // simulate handshake ack completing

    let mut reply = [0u8; ETHERNET_MTU];
    let tcp_len = TcpHandler::parse(&WRAPPED_ACK_PACKET)?
        .create_reply(&mut connections, IP_PAIR)?
        .ok_or("Unexpected None reply")?
        .write_into(&mut reply[20..], IP_PAIR)?;

    assert_eq!(tcp_len, 20, "no payload should be echoed");
    assert_eq!(&reply[24..28], &[0xff, 0xff, 0xff, 0xff]); // seq = SND.NXT = u32::MAX
    assert_eq!(&reply[28..32], &[0x00, 0x00, 0x10, 0x01]); // ack = RCV.NXT = 4097
    assert_eq!(reply[33], 0x10); // ACK only

    // State must be untouched
    assert_eq!(connections.get_snd_nxt(&key), Some(u32::MAX));
    assert_eq!(connections.get_rcv_nxt(&key), Some(4097));
    assert_eq!(connections.get_snd_una(&key), Some(u32::MAX));

    Ok(())
}
