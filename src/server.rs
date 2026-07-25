use {
    crate::{
        ETHERNET_MTU, Result,
        ipv4_header::Ipv4Header,
        protocol::{
            TcpConnections,
            handler::{Encode, ProtocolHandler},
        },
        try_ops::TryGet as _,
    },
    std::{
        io::{self, Read, Write},
        os::fd::AsFd,
        time::{Duration, Instant},
    },
};

/// The initial retransmission timeout, i.e. how long to wait before retransmitting an unacked
/// segment the first time before exponential backoff.
const INITIAL_RTO: Duration = Duration::from_millis(500);

/// The number of times to retransmit an unacked segment before giving up and dropping the
/// connection.
const MAX_RETRANSMITS: u8 = 5;

fn divider() { println!("\n{}\n", "=".repeat(60)) }

/// Reads and writes IPv4 packets to and from `device`, maintaining TCP connection state and echoing
/// payloads as necessary.
///
/// When polling `device` with `poll_readable` is interrupted and `shutdown_check` returns `true`,
/// actively closes all established TCP connections and waits up to `shutdown_grace_period` for them
/// to finish before returning.
pub fn run<D, P, S>(
    device: &mut D,
    poll_readable: P,
    shutdown_check: S,
    shutdown_grace_period: Duration,
) -> Result
where
    D: Read + Write + AsFd,
    P: Fn(&D, Option<Duration>) -> io::Result<bool>,
    S: Fn() -> bool,
{
    Server {
        write_buf: [0u8; ETHERNET_MTU],
        tcp_connections: TcpConnections::new(INITIAL_RTO, MAX_RETRANSMITS),
        device,
        poll_readable,
        shutdown_check,
        shutdown_grace_period,
        shutdown_deadline: None,
    }
    .run()
}

struct Server<'a, D, P, S> {
    write_buf: [u8; ETHERNET_MTU],
    tcp_connections: TcpConnections,
    device: &'a mut D,
    poll_readable: P,
    shutdown_check: S,
    shutdown_grace_period: Duration,

    /// Deadline that bounds how long to wait for established connections to finish closing before
    /// exiting unconditionally. Set once a shutdown signal starts active close.
    shutdown_deadline: Option<Instant>,
}

impl<D, P, S> Server<'_, D, P, S>
where
    D: Read + Write + AsFd,
    P: Fn(&D, Option<Duration>) -> io::Result<bool>,
    S: Fn() -> bool,
{
    fn run(&mut self) -> Result {
        let mut read_buf = [0u8; ETHERNET_MTU];

        divider();

        loop {
            // Block with a `None` timeout if there's no shutdown deadline and no segment pending
            // retransmission
            let timeout = [self.shutdown_deadline, self.tcp_connections.next_retransmit_deadline()]
                .into_iter()
                .flatten()
                .min()
                .map(|deadline| deadline.saturating_duration_since(Instant::now()));

            match (self.poll_readable)(self.device, timeout) {
                // If `poll()` was interrupted and returned `EINTR`, a shutdown signal has been
                // received
                Err(e) if e.kind() == io::ErrorKind::Interrupted && (self.shutdown_check)() => {
                    if self.handle_shutdown_interrupt()? {
                        break Ok(());
                    }
                }

                // Interrupted by a signal unrelated to shutdown -> just re-poll
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}

                Err(e) => break Err(e.into()),

                Ok(false)
                    if self
                        .shutdown_deadline
                        .is_some_and(|deadline| deadline <= Instant::now()) =>
                {
                    println!(
                        "Grace period elapsed with {} remaining connection(s), exiting",
                        self.tcp_connections.len()
                    );

                    break Ok(());
                }

                // A retransmit deadline elapsed -> retransmit all expired segments
                Ok(false) => {
                    for reply_handler in self.tcp_connections.make_retransmissions() {
                        println!("\n ==== Packet sent (retransmission) ====");
                        self.send_packet(&reply_handler)?;
                    }
                }

                // The device became readable within the timeout -> regular read and reply
                Ok(true) => {
                    let n = match self.device.read(&mut read_buf) {
                        // If `read()` was interrupted and returned `EINTR`, react to the shutdown
                        // signal in the same way as for a `poll()` interruption
                        Err(e)
                            if e.kind() == io::ErrorKind::Interrupted
                                && (self.shutdown_check)() =>
                        {
                            if self.handle_shutdown_interrupt()? {
                                break Ok(());
                            }

                            continue;
                        }

                        // Interrupted by a signal unrelated to shutdown -> just re-poll
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => break Err(e.into()),
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

                                    match handler.create_reply(&mut self.tcp_connections) {
                                        Err(e) => eprintln!("Error creating reply: {e}"),

                                        Ok(None) => println!("<no reply>"),

                                        Ok(Some(reply_handler)) => {
                                            self.send_packet(&reply_handler)?;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    divider();

                    if self.shutdown_deadline.is_some()
                        && !self.tcp_connections.closing_in_progress()
                    {
                        println!("All connections closed within grace period, exiting");
                        break Ok(());
                    }
                }
            }
        }
    }

    /// Reacts to an `EINTR` caused by the shutdown signal. If already draining, prints the time
    /// left. If not already draining, begins active close, sending a FIN-ACK to all established
    /// connections and setting the shutdown deadline. Returns whether to proceed to shutdown
    /// immediately.
    fn handle_shutdown_interrupt(&mut self) -> Result<bool> {
        Ok(if let Some(deadline) = self.shutdown_deadline {
            println!(
                "\nDraining connections, {}ms left",
                deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis()
            );

            false
        } else {
            println!("\nShutdown signal received, closing established connections...");

            for reply_handler in self.tcp_connections.close_established() {
                println!("\n ==== Packet sent ====");
                self.send_packet(&reply_handler)?;
            }

            divider();

            if self.tcp_connections.closing_in_progress() {
                self.shutdown_deadline = Some(
                    Instant::now()
                        .checked_add(self.shutdown_grace_period)
                        .ok_or_else(|| {
                            format!(
                                "Overflowed `Instant` adding {} seconds to now",
                                self.shutdown_grace_period.as_secs()
                            )
                        })?,
                );

                false
            } else {
                println!("No established connections, exiting");
                true
            }
        })
    }

    /// Writes `handler`'s protocol-specific header and payload into the write buffer, prefixed with
    /// an IPv4 header, then writes the resulting packet to `device` and prints its string
    /// representation to stdout.
    fn send_packet(&mut self, handler: &impl Encode) -> Result {
        let proto_len = handler.write_into(&mut self.write_buf[Ipv4Header::REPLY_HDR_LEN..])?;

        let ipv4_header = Ipv4Header::try_new(handler.proto(), handler.get_ip_pair(), proto_len)?;
        ipv4_header.write_into(&mut self.write_buf);

        self.device
            .write_all(self.write_buf.try_get(..ipv4_header.total_len.into())?)?;

        println!("{ipv4_header}");
        println!("{handler}");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    mod interrupt;
    mod mocks;
    mod packet_handling;
    mod propagate;
    mod shutdown;
    mod timeout;

    use {
        super::*,
        mocks::{MockDevice, MockPoll},
        std::{
            assert_matches,
            cell::{Cell, RefCell},
        },
    };

    /// A zero grace period, meaning the very next iteration's poll timeout is already past the
    /// deadline (real time always advances between the two `Instant::now()` calls), allowing tests
    /// to force the "grace period elapsed" exit deterministically without sleeping.
    const IMMEDIATE_GRACE_PERIOD: Duration = Duration::ZERO;

    /// A grace period of one year, more than long enough that it cannot plausibly elapse between
    /// two nearby `Instant::now()` calls. Deliberately not `Duration::MAX` because adding that to
    /// `Instant::now()` overflows and is itself a different error case.
    const ONE_YEAR_GRACE_PERIOD: Duration = Duration::from_hours(24 * 365);

    /// Builds and runs a test server, bypassing regular construction so tests can seed
    /// `tcp_connections` with pre-established connections.
    fn run_test_server(
        tcp_connections: TcpConnections,
        device: &mut MockDevice,
        poll_readable: impl Fn(&MockDevice, Option<Duration>) -> io::Result<bool>,
        shutdown_check: impl Fn() -> bool,
        shutdown_grace_period: Duration,
    ) -> Result {
        Server {
            write_buf: [0u8; ETHERNET_MTU],
            tcp_connections,
            device,
            poll_readable,
            shutdown_check,
            shutdown_grace_period,
            shutdown_deadline: None,
        }
        .run()
    }
}
