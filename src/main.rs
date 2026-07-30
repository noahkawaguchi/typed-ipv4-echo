use typed_ipv4_echo::{
    Config, Result, server,
    sys::{ShutdownSignal, poll, tun},
};

/// Runs an echo server that uses a TUN device to read and write IPv4 packets: TCP, UDP, and ICMP.
fn main() -> Result {
    let shutdown = ShutdownSignal::install()?;
    let config = Config::load()?;

    let mut tun = tun::attach(&config.tun_name)?;
    println!("Attached to TUN device {}\nWaiting for packets... (Ctrl+C to stop)", config.tun_name);

    server::run(&mut tun, |fd, timeout| poll::readable(fd, timeout), || shutdown.load(), &config)
}
