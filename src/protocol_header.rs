mod icmp_echo_header;
mod tcp_header;
mod udp_header;

use crate::{
    ETHERNET_MTU,
    protocol::Protocol,
    protocol_header::{
        icmp_echo_header::IcmpEchoHeader, tcp_header::TcpHeader, udp_header::UdpHeader,
    },
};

pub trait ProtocolHeader: std::fmt::Display {
    /// Writes the protocol-specific sections of the reply into the buffer, returning the total
    /// length of the reply packet in bytes (including the IP header and payload data), or `None` if
    /// no reply should be sent.
    fn write_reply(&self, reply: &mut [u8; ETHERNET_MTU]) -> Option<u16>;
}

pub fn parse<'a>(
    data: &'a [u8],
    protocol: &Protocol,
) -> Result<Box<dyn ProtocolHeader + 'a>, String> {
    Ok(match protocol {
        Protocol::Icmp => Box::new(IcmpEchoHeader::parse(data)?) as Box<dyn ProtocolHeader>,
        Protocol::Tcp => Box::new(TcpHeader::parse(data)?) as Box<dyn ProtocolHeader>,
        Protocol::Udp => Box::new(UdpHeader::parse(data)?) as Box<dyn ProtocolHeader>,
        Protocol::Other(_) => {
            return Err(String::from("only ICMP Echo, TCP, and UDP implemented"));
        }
    })
}
