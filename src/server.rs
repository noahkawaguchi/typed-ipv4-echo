use {
    crate::{
        ETHERNET_MTU,
        ipv4_header::Ipv4Header,
        protocol::{Protocol, ProtocolHandler, TcpConnections},
        sys,
        try_ops::TryGet as _,
    },
    std::{
        error::Error,
        io::{self, Read, Write},
        os::fd::AsRawFd,
        time::{Duration, Instant},
    },
};

fn divider() { println!("\n{}\n", "=".repeat(60)) }

/// Reads and writes IPv4 packets to and from `device`, maintaining TCP connection state and echoing
/// payloads as necessary.
///
/// When polling `device` is interrupted and `shutdown_check` returns `true`, actively closes all
/// established TCP connections and waits up to `shutdown_grace_period` for them to finish before
/// returning.
pub fn run(
    device: &mut (impl Read + Write + AsRawFd),
    shutdown_check: impl Fn() -> bool,
    shutdown_grace_period: Duration,
) -> Result<(), Box<dyn Error>> {
    let mut tcp_connections = TcpConnections::new();
    let mut read_buf = [0u8; ETHERNET_MTU];
    let mut write_buf = [0u8; ETHERNET_MTU];

    // Deadline that bounds how long to wait for established connections to finish closing before
    // exiting unconditionally. Set once a shutdown signal starts active close.
    let mut shutdown_deadline = Option::<Instant>::None;

    divider();

    loop {
        // Block indefinitely (-1) if shutdown hasn't started yet
        let timeout_ms = shutdown_deadline.map_or(-1, |deadline| {
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis()
                .try_into()
                .unwrap_or(i32::MAX)
        });

        match sys::poll::readable(device.as_raw_fd(), timeout_ms) {
            // If `poll()` was interrupted and returned `EINTR`, a shutdown signal has been
            // received. The first time this happens, actively close all established connections and
            // start the shutdown grace period.
            Err(e) if e.kind() == io::ErrorKind::Interrupted && shutdown_check() => {
                if shutdown_deadline.is_some() {
                    // SIGINT while already draining -> just print the time left
                    println!("\nDraining connections, {timeout_ms}ms left");
                } else {
                    shutdown_deadline = match start_active_close(
                        device,
                        &mut write_buf,
                        &mut tcp_connections,
                        shutdown_grace_period,
                    )? {
                        Some(deadline) => Some(deadline),
                        None => break Ok(()),
                    }
                }
            }

            Err(e) => break Err(e.into()),

            Ok(false) => {
                println!(
                    "Grace period elapsed with {} remaining connection(s), exiting",
                    tcp_connections.len()
                );

                break Ok(());
            }

            Ok(true) => {
                let n = match device.read(&mut read_buf) {
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
                                        device,
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

                if shutdown_deadline.is_some() && !tcp_connections.closing_in_progress() {
                    println!("All connections closed within grace period, exiting");
                    break Ok(());
                }
            }
        }
    }
}

/// Sends FIN-ACK to all established connections, initiating active close.
///
/// Returns the shutdown deadline to wait until, or `None` if there were no established connections
/// to close (nothing to wait for).
fn start_active_close(
    device: &mut impl Write,
    write_buf: &mut [u8; ETHERNET_MTU],
    tcp_connections: &mut TcpConnections,
    shutdown_grace_period: Duration,
) -> Result<Option<Instant>, Box<dyn Error>> {
    println!("\nShutdown signal received, closing established connections...");

    for (reply_handler, ip_pair) in ProtocolHandler::close_established(tcp_connections) {
        println!("\n ==== Packet sent ====");
        send_packet(device, write_buf, &reply_handler, Protocol::Tcp, ip_pair)?;
    }

    divider();

    if !tcp_connections.closing_in_progress() {
        println!("No established connections, exiting");
        return Ok(None);
    }

    Instant::now()
        .checked_add(shutdown_grace_period)
        .ok_or_else(|| {
            format!(
                "Overflowed `Instant` adding {} seconds to now",
                shutdown_grace_period.as_secs()
            )
        })
        .map(Some)
        .map_err(Into::into)
}

/// Writes `handler`'s protocol-specific header and payload into `write_buf`, prefixed with an IPv4
/// header for `protocol` and `ip_pair`, then writes the resulting packet to `device` and prints its
/// representation to stdout.
fn send_packet(
    device: &mut impl Write,
    write_buf: &mut [u8; ETHERNET_MTU],
    handler: &ProtocolHandler,
    protocol: Protocol,
    ip_pair: crate::Ipv4AddrPair,
) -> Result<(), Box<dyn Error>> {
    // Write the protocol-specific portion of the packet first to have the total length for the IPv4
    // header
    let proto_len = handler.write_into(&mut write_buf[Ipv4Header::REPLY_HEADER_LEN..])?;

    let ipv4_header = Ipv4Header::try_new(protocol, ip_pair, proto_len)?;
    ipv4_header.write_into(write_buf);

    device.write_all(write_buf.try_get(..ipv4_header.total_len.into())?)?;

    println!("{ipv4_header}");
    println!("{handler}");

    Ok(())
}
