use super::*;

#[test]
fn correctly_parses_valid_packet() -> Result<(), String> {
    #[rustfmt::skip]
        const DATA: [u8; 25] = [
            0x04, 0xD2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x00, 0x01,              // Sequence number: 1
            0x00, 0x00, 0x00, 0x02,              // Ack number: 2
            0x50, 0x12,                          // Data offset: 5 (20 bytes), Flags: SYN|ACK
            0xFF, 0xFF,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
            0x48, 0x65, 0x6C, 0x6C, 0x6F,        // Payload: "Hello"
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
    const DATA: [u8; 4] = [0x04, 0xD2, 0x00, 0x50]; // Only 4 bytes
    assert_matches!(TcpHandler::parse(&DATA), Err(e) if e.contains("Too short"));
}

#[test]
fn parsing_handles_large_sequence_numbers() -> Result<(), String> {
    #[rustfmt::skip]
        const DATA: [u8; 20] = [
            0x04, 0xD2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0xFF, 0xFF, 0xFF, 0xFF,              // Sequence number: u32::MAX
            0xFE, 0xDC, 0xBA, 0x98,              // Ack number: 4275878552
            0x50, 0x10,                          // Data offset: 5, Flags: ACK
            0xFF, 0xFF,                          // Window size
            0x00, 0x00,                          // Checksum
            0x00, 0x00,                          // Urgent pointer
        ];

    let handler = TcpHandler::parse(&DATA)?;

    assert_eq!(handler.seq_num, u32::MAX);
    assert_eq!(handler.ack_num, 0xFEDC_BA98);

    Ok(())
}
