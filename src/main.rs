#[cfg(not(target_os = "linux"))]
compile_error!("This crate only supports Linux because it directly uses Linux TUN devices");

mod checksum;
mod ipv4_packet;
mod protocol;
mod shutdown_signal;
mod try_ops;
mod tun;

use crate::{
    ipv4_packet::Ipv4Packet,
    protocol::{Protocol, icmp_echo::IcmpEchoHandler, tcp::TcpHandler, udp::UdpHandler},
    shutdown_signal::ShutdownSignal,
    try_ops::TryGet,
};
use std::{
    env,
    error::Error,
    io::{self, Read, Write},
};

/// The Maximum Transmission Unit of standard Ethernet (frames up to 1500 bytes of IP packet data).
const ETHERNET_MTU: usize = 1500;

/// Parses the the protocol-specific header and payload and prints its string representation to
/// stdout. If a reply packet should be sent, writes the reply into `write_buf` and returns the
/// total length of the reply packet in bytes (including the IP header and payload data). If no
/// reply should be sent, returns `Ok(None)`.
fn protocol_reply(
    packet: &Ipv4Packet<'_>,
    write_buf: &mut [u8; ETHERNET_MTU],
) -> Result<Option<u16>, String> {
    match packet.protocol {
        Protocol::Icmp => {
            let handler = IcmpEchoHandler::parse(packet.payload)?;
            println!("{handler}");
            handler.write_reply(write_buf)
        }

        Protocol::Tcp => {
            let handler = TcpHandler::parse(packet.payload)?;
            println!("{handler}");
            handler.write_reply(write_buf)
        }

        Protocol::Udp => {
            let handler = UdpHandler::parse(packet.payload)?;
            println!("{handler}");
            handler.write_reply(write_buf)
        }

        Protocol::Other(n) => Err(format!(
            "Protocol {n} not implemented, only TCP, UDP, and ICMP Echo"
        )),
    }
}

/// Runs an echo server that uses a TUN device to read and write IPv4 packets: TCP, UDP, and ICMP.
/// Exits gracefully upon receiving a shutdown signal.
fn main() -> Result<(), Box<dyn Error>> {
    let shutdown = ShutdownSignal::install()?;

    let tun_name = env::var("TUN_DEVICE_NAME").unwrap_or_else(|_| String::from("tun0"));
    let mut tun = tun::open(&tun_name)?;
    println!("Attached to TUN device {tun_name}\nWaiting for packets... (Ctrl+C to stop)\n");

    let mut read_buf = [0u8; ETHERNET_MTU];
    let mut write_buf = [0u8; ETHERNET_MTU];

    while !shutdown.load() {
        let n = match tun.read(&mut read_buf) {
            // If `read()` was interrupted and returned `EINTR`, immediately continue to check the
            // shutdown flag
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
            Ok(n) => n,
        };

        match Ipv4Packet::parse(read_buf.try_get(..n)?) {
            Err(e) => eprintln!("Skipping packet: {e}"),

            Ok(packet) => {
                println!("{packet}");

                match protocol_reply(&packet, &mut write_buf) {
                    Err(e) => eprintln!("Skipping packet: {e}"),

                    Ok(None) => {}

                    Ok(Some(total_len)) => {
                        packet.write_reply(&mut write_buf, total_len);
                        tun.write_all(write_buf.try_get(..usize::from(total_len))?)?;
                        println!("Reply packet sent!");
                    }
                }
            }
        }

        println!();
    }

    println!("\nShutdown signal received, exiting");
    Ok(())
}
