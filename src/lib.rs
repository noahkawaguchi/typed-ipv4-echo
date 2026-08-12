#[cfg(not(target_os = "linux"))]
compile_error!("This crate only supports Linux because it directly uses low-level Linux APIs");

pub mod server;
pub mod sys;

pub use config::Config;

mod addr_pairs;
mod checksum;
mod config;
mod ipv4_header;
mod logger;
mod protocol;
mod try_ops;

pub type Result<T = (), E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

/// The Maximum Transmission Unit of standard Ethernet (frames up to 1500 bytes of IP packet data).
const ETHERNET_MTU: usize = 1500;

/// One of the communicating parties.
trait Endpoint {
    /// Character representing the direction of traffic from this endpoint.
    const INDICATOR: char;
}

/// Marker type representing a local sender or receiver.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(test, derive(Debug))]
struct Local;

impl Endpoint for Local {
    const INDICATOR: char = '↑';
}

/// Marker type representing a remote sender or receiver.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(test, derive(Debug))]
struct Remote;

impl Endpoint for Remote {
    const INDICATOR: char = '↓';
}
