use typenet::{
    Config, Result, logger, server,
    sys::{ShutdownSignal, poll, tun},
};

/// Runs an echo server that uses a TUN device to read and write IPv4 packets: TCP, UDP, and ICMP.
fn main() -> Result {
    let shutdown = ShutdownSignal::install()?;
    let config = Config::load()?;
    logger::set_level(config.log_level);

    let mut tun = tun::attach(&config.tun_name)?;
    logger::server_info(format_args!("Attached to TUN device {}", config.tun_name));

    logger::server_info("Waiting for packets... (Ctrl+C to stop)");
    server::run(&mut tun, |fd, timeout| poll::readable(fd, timeout), || shutdown.load(), &config)
}
