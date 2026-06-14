use {
    super::*,
    crate::protocol::test_utils::{IP_PAIR, tcp_udp_test_checksum},
    std::error::Error,
};

#[test]
fn write_into_produces_correct_bytes_with_no_payload() -> Result<(), Box<dyn Error>> {
    let handler = TcpHandler {
        src_port: 80,
        dst_port: 1234,
        seq_num: 0x1000_0000,
        ack_num: 0x0000_1001,
        offset_bytes: 20,
        flags: TcpFlags::SynAck,
        payload: &[],
    };

    let mut reply = [0u8; ETHERNET_MTU];
    let tcp_len = handler.write_into(&mut reply[20..], IP_PAIR)?;

    assert_eq!(tcp_len, 20, "no payload, so length is just the header");

    assert_eq!(&reply[20..22], &[0x00, 0x50]); // Source port: 80
    assert_eq!(&reply[22..24], &[0x04, 0xD2]); // Dest port: 1234
    assert_eq!(&reply[24..28], &[0x10, 0x00, 0x00, 0x00]); // Seq num
    assert_eq!(&reply[28..32], &[0x00, 0x00, 0x10, 0x01]); // Ack num
    assert_eq!(reply[32], 0x50); // Data offset: 5 (20 bytes), reserved bits: 0
    assert_eq!(reply[33], 0x12); // Flags: SYN|ACK
    assert_eq!(&reply[34..36], &[0xFF, 0xFF]); // Window size
    assert_eq!(&reply[38..40], &[0x00, 0x00]); // Urgent pointer

    assert_eq!(tcp_udp_test_checksum(&reply, Protocol::Tcp, tcp_len, IP_PAIR)?, 0x0000);

    Ok(())
}

#[test]
fn write_into_produces_correct_bytes_with_payload() -> Result<(), Box<dyn Error>> {
    let handler = TcpHandler {
        src_port: 80,
        dst_port: 1234,
        seq_num: 1,
        ack_num: 4102,
        offset_bytes: 20,
        flags: TcpFlags::Ack,
        payload: b"Hello",
    };

    let mut reply = [0u8; ETHERNET_MTU];
    let tcp_len = handler.write_into(&mut reply[20..], IP_PAIR)?;

    assert_eq!(tcp_len, 25, "header (20 bytes) + payload (5 bytes)");

    // Payload copied immediately after the 20-byte header
    assert_eq!(&reply[40..45], b"Hello");

    assert_eq!(tcp_udp_test_checksum(&reply, Protocol::Tcp, tcp_len, IP_PAIR)?, 0x0000);

    Ok(())
}
