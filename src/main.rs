/// Runs an echo server that uses a TUN device to read and write IPv4 packets: TCP, UDP, and ICMP.
fn main() -> typed_ipv4_echo::Result {
    let shutdown = typed_ipv4_echo::sys::ShutdownSignal::install()?;

    let config = typed_ipv4_echo::Config::load()?;

    let mut tun = typed_ipv4_echo::sys::tun::attach(&config.tun_name)?;
    println!("Attached to TUN device {}", config.tun_name);

    println!("Waiting for packets... (Ctrl+C to stop)");

    typed_ipv4_echo::server::run(
        &mut tun,
        |fd, timeout| typed_ipv4_echo::sys::poll::readable(fd, timeout),
        || shutdown.load(),
        &config,
    )
}
