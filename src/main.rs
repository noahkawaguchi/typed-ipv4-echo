#[cfg(not(target_os = "linux"))]
compile_error!("This crate only supports Linux because it uses Linux APIs directly");

mod addr_pairs;
mod checksum;
mod ipv4_header;
mod protocol;
mod server;
mod sys;
mod try_ops;

use std::{env, error::Error, time::Duration};

/// The Maximum Transmission Unit of standard Ethernet (frames up to 1500 bytes of IP packet data).
const ETHERNET_MTU: usize = 1500;

/// Runs an echo server that uses a TUN device to read and write IPv4 packets: TCP, UDP, and ICMP.
fn main() -> Result<(), Box<dyn Error>> {
    /// The amount of time to wait for established TCP connections to finish closing after a
    /// shutdown signal before exiting unconditionally.
    const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(5);

    let shutdown = sys::ShutdownSignal::install()?;

    let tun_name = env::var("TUN_DEVICE_NAME").unwrap_or_else(|_| String::from("tun0"));
    let mut tun = sys::tun::attach(&tun_name)?;
    println!("Attached to TUN device {tun_name}");

    println!("Waiting for packets... (Ctrl+C to stop)");
    server::run(&mut tun, || shutdown.load(), SHUTDOWN_GRACE_PERIOD)
}
