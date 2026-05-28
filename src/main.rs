mod checksum;
mod ipv4_packet;
mod protocol;
mod tun;

use crate::ipv4_packet::Ipv4Packet;
use std::{
    io::{self, Read, Write},
    sync::atomic::{AtomicBool, Ordering},
};

/// The Maximum Transmission Unit of standard Ethernet (frames up to 1500 bytes of IP packet data).
const ETHERNET_MTU: usize = 1500;

/// Global flag for graceful shutdown.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Signal handler to atomically set the shutdown flag when called.
extern "C" fn shutdown_signal_handler(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

/// Installs the SIGINT handler for graceful shutdown.
#[expect(unsafe_code, reason = "libc system calls to install handler")]
fn install_signal_handler() -> io::Result<()> {
    // Use `sigaction` to ensure the `SA_RESTART` flag is not set so that blocking `read()` in the
    // main loop will be interrupted and return `EINTR` without being automatically restarted

    // SAFETY: All fields of `sigaction` have valid all-zero bit patterns.
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };

    sa.sa_sigaction = shutdown_signal_handler as *const () as libc::sighandler_t;

    // SAFETY: `&raw mut sa.sa_mask` is a valid, aligned, writable pointer to an owned `sigset_t` on
    // the stack for `sigemptyset` to write an empty set of signals through.
    if unsafe { libc::sigemptyset(&raw mut sa.sa_mask) } != 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY:
    // - `SIGINT` is a valid `signum`.
    // - `&raw const sa` is a valid, aligned pointer to a fully initialized `sigaction`.
    // - A null `oldact` is permitted.
    // - `shutdown_signal_handler` is async-signal-safe because its body is a single relaxed store
    //   to a lock-free `AtomicBool`.
    if unsafe { libc::sigaction(libc::SIGINT, &raw const sa, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Runs an echo server that uses a TUN device to read and write IPv4 packets: TCP, UDP, and ICMP.
/// Exits gracefully upon receiving SIGINT.
fn main() -> io::Result<()> {
    install_signal_handler()?;

    let (mut tun, name) = tun::init("10.0.0.1/24")?;
    println!("Created and set up TUN device {name} with IP 10.0.0.1/24");
    println!("Waiting for packets... (Ctrl+C to stop)\n");

    let mut read_buf = [0u8; ETHERNET_MTU];
    let mut write_buf = [0u8; ETHERNET_MTU];

    while !SHUTDOWN.load(Ordering::Relaxed) {
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
