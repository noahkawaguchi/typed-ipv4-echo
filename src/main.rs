mod checksum;
mod ipv4_packet;
mod protocol;
mod protocol_handler;
mod tun;

use crate::ipv4_packet::Ipv4Packet;
use std::io::{self, Read, Write};

/// The Maximum Transmission Unit of standard Ethernet (frames up to 1500 bytes of IP packet data).
const ETHERNET_MTU: usize = 1500;

fn main() -> io::Result<()> {
    let (mut tun, name) = tun::init("10.0.0.1/24")?;
    println!("Created and set up TUN device {name} with IP 10.0.0.1/24");
    println!("Waiting for packets...\n");

    let mut buf = [0u8; ETHERNET_MTU];

    loop {
        let n = tun.read(&mut buf)?;

        match Ipv4Packet::parse(&buf[..n]) {
            Err(e) => eprintln!("{e}"),

            Ok(packet) => {
                println!("{packet}");

                if let Some((reply, reply_len)) = packet.create_reply() {
                    tun.write_all(&reply[..reply_len])?;
                    println!("Reply packet sent!");
                }
            }
        }

        println!();
    }
}
