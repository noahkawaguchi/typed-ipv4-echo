#[cfg(not(target_os = "linux"))]
compile_error!("This crate only supports Linux because it uses Linux APIs directly");

mod checksum;
mod ipv4_header;
mod protocol;
mod sys;
mod try_ops;

use {
    crate::{
        ipv4_header::Ipv4Header,
        protocol::{Protocol, ProtocolHandler, TcpConnections},
        try_ops::TryGet as _,
    },
    std::{
        env,
        error::Error,
        io::{self, Read as _},
        net::Ipv4Addr,
        os::unix::io::AsRawFd as _,
        time::{Duration, Instant},
    },
};

/// The Maximum Transmission Unit of standard Ethernet (frames up to 1500 bytes of IP packet data).
const ETHERNET_MTU: usize = 1500;

/// The amount of time to wait for established TCP connections to finish closing after a shutdown
/// signal before exiting unconditionally.
const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
struct Ipv4AddrPair {
    src: Ipv4Addr,
    dst: Ipv4Addr,
}

impl Ipv4AddrPair {
    const fn swapped(self) -> Self { Self { src: self.dst, dst: self.src } }
}

fn divider() { println!("\n{}\n", "=".repeat(60)) }

/// Runs an echo server that uses a TUN device to read and write IPv4 packets: TCP, UDP, and ICMP.
///
/// Upon receiving a shutdown signal, actively closes all established TCP connections and waits up
/// to `SHUTDOWN_GRACE_PERIOD` for them to finish before exiting.
fn main() -> Result<(), Box<dyn Error>> {
    let shutdown = sys::ShutdownSignal::install()?;

    let tun_name = env::var("TUN_DEVICE_NAME").unwrap_or_else(|_| String::from("tun0"));
    let mut tun = sys::tun::attach(&tun_name)?;
    println!("Attached to TUN device {tun_name}");

    println!("Waiting for packets... (Ctrl+C to stop)");
    divider();

    let mut tcp_connections = TcpConnections::new();
    let mut read_buf = [0u8; ETHERNET_MTU];
    let mut write_buf = [0u8; ETHERNET_MTU];

    // Deadline that bounds how long to wait for established connections to finish closing before
    // exiting unconditionally. Set once a shutdown signal starts active close.
    let mut shutdown_deadline = Option::<Instant>::None;

    loop {
        // Block indefinitely (-1) if shutdown hasn't started yet
        let timeout_ms = shutdown_deadline.map_or(-1, |deadline| {
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis()
                .try_into()
                .unwrap_or(i32::MAX)
        });

        match sys::poll::readable(tun.as_raw_fd(), timeout_ms) {
            // If `poll()` was interrupted and returned `EINTR`, a shutdown signal has been
            // received. The first time this happens, actively close all established connections and
            // start the shutdown grace period.
            Err(e) if e.kind() == io::ErrorKind::Interrupted && shutdown.load() => {
                if shutdown_deadline.is_some() {
                    // SIGINT while already draining -> just print the time left
                    println!("\nDraining connections, {timeout_ms}ms left");
                } else {
                    println!("\nShutdown signal received, closing established connections...");

                    for (reply_handler, ip_pair) in
                        ProtocolHandler::close_established(&mut tcp_connections)
                    {
                        println!("\n ==== Packet sent ====");

                        send_packet(
                            &mut tun,
                            &mut write_buf,
                            &reply_handler,
                            Protocol::Tcp,
                            ip_pair,
                        )?;
                    }

                    divider();

                    // Nothing to wait for if no connections were established to actively close
                    if !tcp_connections.closing_in_progress() {
                        println!("No established connections, exiting");
                        break Ok(());
                    }

                    shutdown_deadline = Instant::now()
                        .checked_add(SHUTDOWN_GRACE_PERIOD)
                        .ok_or_else(|| {
                            format!(
                                "Overflowed `Instant` adding {} seconds to now",
                                SHUTDOWN_GRACE_PERIOD.as_secs()
                            )
                        })
                        .map(Some)?;
                }
            }

            Err(e) => break Err(e.into()),

            // The shutdown grace period elapsed before all connections finished closing
            Ok(false) => {
                println!(
                    "Grace period elapsed with {} remaining connection(s), exiting",
                    tcp_connections.len()
                );

                break Ok(());
            }

            Ok(true) => {
                let n = match tun.read(&mut read_buf) {
                    // If `read()` was interrupted and returned `EINTR`, immediately continue to
                    // re-poll and check the shutdown deadline
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
                            ipv4_header.ip_pair,
                        ) {
                            Err(e) => eprintln!("Skipping packet: {e}"),

                            Ok(handler) => {
                                println!("{handler}");
                                println!("\n ==== Packet sent ====");

                                match handler.create_reply(&mut tcp_connections)? {
                                    None => println!("<no reply>"),

                                    Some(reply_handler) => send_packet(
                                        &mut tun,
                                        &mut write_buf,
                                        &reply_handler,
                                        ipv4_header.protocol,
                                        ipv4_header.ip_pair.swapped(),
                                    )?,
                                }
                            }
                        }
                    }
                }

                divider();

                // If active close is in progress and every connection has now finished closing,
                // exit before the shutdown grace period elapses
                if shutdown_deadline.is_some() && !tcp_connections.closing_in_progress() {
                    println!("All connections closed, exiting");
                    break Ok(());
                }
            }
        }
    }
}

/// Writes `handler`'s protocol-specific header and payload into `write_buf`, prefixed with an IPv4
/// header for `protocol` and `ip_pair`, then writes the resulting packet to `tun` and prints its
/// representation to stdout.
fn send_packet(
    tun: &mut impl io::Write,
    write_buf: &mut [u8; ETHERNET_MTU],
    handler: &ProtocolHandler,
    protocol: Protocol,
    ip_pair: Ipv4AddrPair,
) -> Result<(), Box<dyn Error>> {
    // Write the protocol-specific portion of the packet first to have the total length for the IPv4
    // header
    let proto_len = handler.write_into(&mut write_buf[Ipv4Header::REPLY_HEADER_LEN..])?;

    let ipv4_header = Ipv4Header::try_new(protocol, ip_pair, proto_len)?;
    ipv4_header.write_into(write_buf);

    tun.write_all(write_buf.try_get(..ipv4_header.total_len.into())?)?;

    println!("{ipv4_header}");
    println!("{handler}");

    Ok(())
}
