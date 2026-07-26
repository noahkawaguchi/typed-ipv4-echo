#[cfg(not(target_os = "linux"))]
compile_error!("This crate only supports Linux because it directly uses low-level Linux APIs");

mod addr_pairs;
mod checksum;
mod config;
mod ipv4_header;
mod protocol;
mod server;
mod sys;
mod try_ops;

type Result<T = (), E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

/// The Maximum Transmission Unit of standard Ethernet (frames up to 1500 bytes of IP packet data).
const ETHERNET_MTU: usize = 1500;

/// Runs an echo server that uses a TUN device to read and write IPv4 packets: TCP, UDP, and ICMP.
fn main() -> Result {
    let shutdown = sys::ShutdownSignal::install()?;

    let config = config::load()?;

    let mut tun = sys::tun::attach(&config.tun_name)?;
    println!("Attached to TUN device {}", config.tun_name);

    println!("Waiting for packets... (Ctrl+C to stop)");

    server::run(
        &mut tun,
        |fd, timeout| sys::poll::readable(fd, timeout),
        || shutdown.load(),
        &config,
    )
}
