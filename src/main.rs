#[cfg(not(target_os = "linux"))]
compile_error!("This crate only supports Linux because it directly uses Linux TUN devices");

mod checksum;
mod ipv4_packet;
mod protocol;
mod shutdown_signal;
mod tun;

use crate::{ipv4_packet::Ipv4Packet, shutdown_signal::ShutdownSignal};
use std::{
    env,
    io::{self, Read, Write},
};

/// The Maximum Transmission Unit of standard Ethernet (frames up to 1500 bytes of IP packet data).
const ETHERNET_MTU: usize = 1500;

/// Runs an echo server that uses a TUN device to read and write IPv4 packets: TCP, UDP, and ICMP.
/// Exits gracefully upon receiving a shutdown signal.
fn main() -> io::Result<()> {
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
            Err(e) => return Err(e),
            Ok(n) => n,
        };

        match Ipv4Packet::parse(&read_buf[..n], protocol::parse_data) {
            Err(e) => eprintln!("Skipping packet: {e}"),

            Ok(packet) => {
                println!("{packet}");

                if let Some(reply_len) = packet.write_reply(&mut write_buf) {
                    tun.write_all(&write_buf[..reply_len])?;
                    println!("Reply packet sent!");
                }
            }
        }

        println!();
    }

    println!("\nShutdown signal received, exiting");
    Ok(())
}
