use super::*;
use std::{assert_matches, error::Error, net::Ipv4Addr};

#[test]
fn correctly_parses_valid_packet() -> Result<(), String> {
    #[rustfmt::skip]
        const DATA: [u8; 25] = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x00, 0x01,              // Sequence number: 1
            0x00, 0x00, 0x00, 0x02,              // Ack number: 2
            0x50, 0x12,                          // Data offset: 5 (20 bytes), Flags: SYN|ACK
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
            0x48, 0x65, 0x6c, 0x6c, 0x6f,        // Payload: "Hello"
        ];

    let handler = TcpHandler::parse(&DATA)?;

    assert_eq!(handler.src_port, 1234);
    assert_eq!(handler.dst_port, 80);
    assert_eq!(handler.seq_num, 1);
    assert_eq!(handler.ack_num, 2);
    assert_eq!(handler.offset_bytes, 20);
    assert_eq!(handler.flags, TcpFlags::SynAck);
    assert_eq!(handler.payload, b"Hello");

    Ok(())
}

#[test]
fn parsing_fails_when_too_short() {
    const DATA: [u8; 4] = [0x04, 0xd2, 0x00, 0x50]; // Only 4 bytes
    assert_matches!(TcpHandler::parse(&DATA), Err(e) if e.contains("Too short"));
}

#[test]
fn extracts_syn_flag_correctly() -> Result<(), String> {
    #[rustfmt::skip]
        const DATA: [u8; 20] = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x00, 0x00,              // Sequence number: 0
            0x00, 0x00, 0x00, 0x00,              // Ack number: 0
            0x50, 0x02,                          // Data offset: 5, Flags: SYN only
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

    assert_eq!(TcpHandler::parse(&DATA)?.flags, TcpFlags::Syn);

    Ok(())
}

#[test]
fn extracts_ack_flag_correctly() -> Result<(), String> {
    #[rustfmt::skip]
        const DATA: [u8; 20] = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x00, 0x01,              // Sequence number: 1
            0x00, 0x00, 0x00, 0x01,              // Ack number: 1
            0x50, 0x10,                          // Data offset: 5, Flags: ACK only
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

    assert_eq!(TcpHandler::parse(&DATA)?.flags, TcpFlags::Ack);

    Ok(())
}

#[test]
fn extracts_fin_flag_correctly() -> Result<(), String> {
    #[rustfmt::skip]
        const DATA: [u8; 20] = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x00, 0x00,              // Sequence number: 0
            0x00, 0x00, 0x00, 0x00,              // Ack number: 0
            0x50, 0x11,                          // Data offset: 5, Flags: FIN|ACK
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

    assert_eq!(TcpHandler::parse(&DATA)?.flags, TcpFlags::FinAck);

    Ok(())
}

#[test]
fn parsing_fails_when_no_flags_set() {
    #[rustfmt::skip]
        const DATA: [u8; 20] = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x00, 0x00,              // Sequence number: 0
            0x00, 0x00, 0x00, 0x00,              // Ack number: 0
            0x50, 0x00,                          // Data offset: 5, Flags: none
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

    assert_matches!(
        TcpHandler::parse(&DATA),
        Err(e) if e.contains("Invalid TCP flag combination")
    );
}

#[test]
fn parsing_handles_large_sequence_numbers() -> Result<(), String> {
    #[rustfmt::skip]
        const DATA: [u8; 20] = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0xff, 0xff, 0xff, 0xff,              // Sequence number: u32::MAX
            0xfe, 0xdc, 0xba, 0x98,              // Ack number: 4275878552
            0x50, 0x10,                          // Data offset: 5, Flags: ACK
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

    let handler = TcpHandler::parse(&DATA)?;

    assert_eq!(handler.seq_num, u32::MAX);
    assert_eq!(handler.ack_num, 0xfedc_ba98);

    Ok(())
}

#[test]
fn reply_creates_valid_syn_ack() -> Result<(), String> {
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

    const SRC_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2); // Source: 10.0.0.2
    const DST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1); // Dest: 10.0.0.1

    let handler = TcpHandler::parse(&SYN_PACKET)?;
    let mut connections = TcpConnections::new();
    let mut reply = [0u8; ETHERNET_MTU];

    let tcp_len = handler
        .create_reply(&mut connections, Ipv4AddrPair { src: SRC_IP, dst: DST_IP })
        .map_err(|e| e.to_string())?
        .ok_or("Unexpected None reply")?
        .write_into(&mut reply[20..], Ipv4AddrPair { src: SRC_IP, dst: DST_IP })?;

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

    // Verify checksum is valid using pseudo-header
    let mut pseudo_header = [0u8; 12];
    pseudo_header[0..4].copy_from_slice(&SRC_IP.octets());
    pseudo_header[4..8].copy_from_slice(&DST_IP.octets());
    pseudo_header[8] = 0;
    pseudo_header[9] = Protocol::Tcp.into();
    pseudo_header[10..12].copy_from_slice(&tcp_len.to_be_bytes());

    let mut checksum_data = [0u8; 12 + 20];
    checksum_data[0..12].copy_from_slice(&pseudo_header);
    checksum_data[12..32].copy_from_slice(&reply[20..40]);

    let checksum = checksum::calculate(&checksum_data);
    assert_eq!(checksum, 0x0000);

    Ok(())
}

#[test]
fn data_packet_before_complete_handshake_is_dropped() -> Result<(), Box<dyn Error>> {
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

    const SRC_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const DST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

    let mut connections = TcpConnections::new();

    // Store an ISN as if we sent a SYN-ACK, but never transition to Established
    let key = ConnKey { client_ip: SRC_IP, client_port: 1234, server_ip: DST_IP, server_port: 80 };
    connections.store_isn(key, 0);

    assert_eq!(
        TcpHandler::parse(&DATA_PACKET)?
            .create_reply(&mut connections, Ipv4AddrPair { src: SRC_IP, dst: DST_IP })?,
        None
    );

    Ok(())
}

#[test]
fn reply_returns_none_for_handshake_ack() -> Result<(), Box<dyn Error>> {
    #[rustfmt::skip]
        const ACK_PACKET: [u8; 20] = [
            0x04, 0xd2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x10, 0x01,              // Sequence number: 4097
            0x00, 0x00, 0x00, 0x01,              // Ack number: 1 (LOCAL_SEQ_SYN + 1)
            0x50, 0x10,                          // Data offset: 5, Flags: ACK
            0xff, 0xff,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

    const SRC_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const DST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

    let mut connections = TcpConnections::new();

    assert_eq!(
        TcpHandler::parse(&ACK_PACKET)?
            .create_reply(&mut connections, Ipv4AddrPair { src: SRC_IP, dst: DST_IP })?,
        None
    );

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

    const SRC_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2); // Source: 10.0.0.2
    const DST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1); // Dest: 10.0.0.1

    let handler = TcpHandler::parse(&DATA_PACKET)?;
    let mut connections = TcpConnections::new();

    // Simulate a completed handshake (ISN=0, so client's ack_num of 1 is consistent)
    let key = ConnKey { client_ip: SRC_IP, client_port: 1234, server_ip: DST_IP, server_port: 80 };
    connections.store_isn(key, 0);
    connections.establish(&key);

    let mut reply = [0u8; ETHERNET_MTU];

    let ip_pair = Ipv4AddrPair { src: SRC_IP, dst: DST_IP };
    let tcp_len = handler
        .create_reply(&mut connections, ip_pair)?
        .ok_or("Unexpected None reply")?
        .write_into(&mut reply[20..], ip_pair)?;

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
    let mut pseudo_header = [0u8; 12];
    pseudo_header[0..4].copy_from_slice(&SRC_IP.octets());
    pseudo_header[4..8].copy_from_slice(&DST_IP.octets());
    pseudo_header[8] = 0;
    pseudo_header[9] = Protocol::Tcp.into();
    pseudo_header[10..12].copy_from_slice(&tcp_len.to_be_bytes());

    let mut checksum_data = [0u8; 12 + 25];
    checksum_data[0..12].copy_from_slice(&pseudo_header);
    checksum_data[12..37].copy_from_slice(&reply[20..45]);

    let checksum = checksum::calculate(&checksum_data);
    assert_eq!(checksum, 0x0000);

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

    const SRC_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const DST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

    let handler = TcpHandler::parse(&FIN_ACK_PACKET)?;
    let mut connections = TcpConnections::new();

    // Simulate an established connection
    let conn_key =
        ConnKey { client_ip: SRC_IP, client_port: 1234, server_ip: DST_IP, server_port: 80 };
    connections.store_isn(conn_key, 0);

    let mut reply = [0u8; ETHERNET_MTU];
    let ip_pair = Ipv4AddrPair { src: SRC_IP, dst: DST_IP };
    let tcp_len = handler
        .create_reply(&mut connections, ip_pair)?
        .ok_or("Unexpected None reply")?
        .write_into(&mut reply[20..], ip_pair)?;

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

    // Connection removed from map
    assert_eq!(connections.pending_isn(&conn_key), None);

    // Checksum over pseudo-header + TCP segment must be zero
    let mut pseudo_header = [0u8; 12];
    pseudo_header[0..4].copy_from_slice(&SRC_IP.octets());
    pseudo_header[4..8].copy_from_slice(&DST_IP.octets());
    pseudo_header[8] = 0;
    pseudo_header[9] = Protocol::Tcp.into();
    pseudo_header[10..12].copy_from_slice(&tcp_len.to_be_bytes());

    let mut checksum_data = [0u8; 12 + 20];
    checksum_data[0..12].copy_from_slice(&pseudo_header);
    checksum_data[12..32].copy_from_slice(&reply[20..40]);

    assert_eq!(checksum::calculate(&checksum_data), 0x0000);

    Ok(())
}
