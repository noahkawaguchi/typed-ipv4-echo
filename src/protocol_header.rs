mod icmp_echo_header;
mod tcp_header;

use crate::{
    ETHERNET_MTU,
    protocol::Protocol,
    protocol_header::{icmp_echo_header::IcmpEchoHeader, tcp_header::TcpHeader},
};

pub trait ProtocolHeader: std::fmt::Display {
    fn len(&self) -> usize;

    fn write_reply_header(&self, reply: &mut [u8; ETHERNET_MTU], payload: &[u8]) -> Option<usize>;
}

pub fn parse(data: &[u8], protocol: &Protocol) -> Result<Box<dyn ProtocolHeader>, String> {
    Ok(match protocol {
        Protocol::Icmp => Box::new(IcmpEchoHeader::parse(data)?) as Box<dyn ProtocolHeader>,
        Protocol::Tcp => Box::new(TcpHeader::parse(data)?) as Box<dyn ProtocolHeader>,
        _ => return Err(String::from("only ICMP Echo and TCP implemented so far")),
    })
}
