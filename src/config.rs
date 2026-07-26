use std::{env, time::Duration};

pub struct Config {
    /// The name of the TUN device to attach to.
    pub tun_name: String,

    /// The amount of time to wait for established TCP connections to finish closing after a
    /// shutdown signal before exiting unconditionally.
    pub grace_period: Duration,

    /// The initial retransmission timeout, i.e. how long to wait before retransmitting an unacked
    /// TCP segment the first time before exponential backoff.
    pub initial_rto: Duration,

    /// The number of times to retransmit an unacked TCP segment before giving up and dropping the
    /// connection.
    pub max_retransmits: u8,
}

pub fn load() -> Config {
    Config {
        // NOTE: "TUN_DEVICE_NAME" is also read by the TUN creation script with a "tun0" fallback
        tun_name: env::var("TUN_DEVICE_NAME").unwrap_or_else(|_| String::from("tun0")),
        grace_period: Duration::from_secs(5),
        initial_rto: Duration::from_millis(500),
        max_retransmits: 5,
    }
}
