use super::*;
use crate::protocol::test_utils::tcp_udp_test_checksum;
use std::{error::Error, net::Ipv4Addr};

/// Test source IP address: 10.0.0.2
const SRC_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
/// Test destination IP address: 10.0.0.1
const DST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
/// An `Ipv4AddrPair` of `SRC_IP` and `DST_IP`.
const IP_PAIR: Ipv4AddrPair = Ipv4AddrPair { src: SRC_IP, dst: DST_IP };

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
    connections.establish(&key);

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
    connections.establish(&key);
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
    connections.establish(&key);

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
    connections.establish(&key);

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
