#[cfg(not(target_os = "linux"))]
compile_error!("This crate only supports Linux because it directly uses Linux TUN devices");

mod checksum;
mod ipv4_header;
mod protocol;
mod shutdown_signal;
mod try_ops;
mod tun;

use crate::{
    ipv4_header::Ipv4Header,
    protocol::{ProtocolHandler, TcpConnections},
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

/// Runs an echo server that uses a TUN device to read and write IPv4 packets: TCP, UDP, and ICMP.
/// Exits gracefully upon receiving a shutdown signal.
fn main() -> Result<(), Box<dyn Error>> {
    fn divider() { println!("\n{}\n", "=".repeat(60)) }

    let shutdown = ShutdownSignal::install()?;

    let tun_name = env::var("TUN_DEVICE_NAME").unwrap_or_else(|_| String::from("tun0"));
    let mut tun = tun::open(&tun_name)?;
    println!("Attached to TUN device {tun_name}");

    println!("Waiting for packets... (Ctrl+C to stop)");
    divider();

    let mut tcp_connections = TcpConnections::new();
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

        match Ipv4Header::parse(read_buf.try_get(..n)?) {
            Err(e) => eprintln!("Skipping packet: {e}"),

            Ok((ipv4_header, ipv4_payload)) => {
                println!(" ==== Packet received ====");
                println!("{ipv4_header}");

                match ProtocolHandler::parse(
                    ipv4_payload,
                    ipv4_header.protocol,
                    ipv4_header.src_ip,
                    ipv4_header.dst_ip,
                ) {
                    Err(e) => eprintln!("Skipping packet: {e}"),

                    Ok(handler) => {
                        println!("{handler}");
                        println!("\n ==== Packet sent ====");

                        match handler.create_reply(&mut tcp_connections)? {
                            None => println!("<no reply>"),

                            Some(reply_handler) => {
                                // Write the protocol-specific portion of the reply packet first to
                                // have the total length for the IPv4 header
                                let proto_len = reply_handler
                                    .write_into(&mut write_buf[Ipv4Header::REPLY_HEADER_LEN..])?;

                                let reply_ipv4_header = ipv4_header.create_reply(proto_len)?;
                                reply_ipv4_header.write_into(&mut write_buf);

                                tun.write_all(
                                    write_buf.try_get(..reply_ipv4_header.total_len.into())?,
                                )?;

                                println!("{reply_ipv4_header}");
                                println!("{reply_handler}");
                            }
                        }
                    }
                }
            }
        }

        divider();
    }

    println!("\nShutdown signal received, exiting");
    Ok(())
}
