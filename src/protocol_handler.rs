mod icmp_echo;
mod tcp;
mod udp;

use crate::{
    ETHERNET_MTU,
    protocol::Protocol,
    protocol_handler::{icmp_echo::IcmpEchoHandler, tcp::TcpHandler, udp::UdpHandler},
};

pub trait ProtocolHandler: std::fmt::Display {
    /// Writes the protocol-specific sections of the reply into the buffer, returning the total
    /// length of the reply packet in bytes (including the IP header and payload data), or `None` if
    /// no reply should be sent.
    fn write_reply(&self, reply: &mut [u8; ETHERNET_MTU]) -> Option<u16>;
}

pub fn parse<'a>(
    data: &'a [u8],
    protocol: &Protocol,
) -> Result<Box<dyn ProtocolHandler + 'a>, String> {
    Ok(match protocol {
        Protocol::Icmp => Box::new(IcmpEchoHandler::parse(data)?) as Box<dyn ProtocolHandler>,
        Protocol::Tcp => Box::new(TcpHandler::parse(data)?) as Box<dyn ProtocolHandler>,
        Protocol::Udp => Box::new(UdpHandler::parse(data)?) as Box<dyn ProtocolHandler>,
        Protocol::Other(_) => {
            return Err(String::from("only ICMP Echo, TCP, and UDP implemented"));
        }
    })
}
