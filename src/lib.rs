#[cfg(not(target_os = "linux"))]
compile_error!("This crate only supports Linux because it directly uses low-level Linux APIs");

pub mod server;
pub mod sys;

#[cfg(feature = "bench-internals")]
pub mod checksum;

#[cfg(not(feature = "bench-internals"))]
mod checksum;

pub use config::Config;

mod addr_pairs;
mod config;
mod endpoint;
mod ipv4_header;
mod logger;
mod protocol;
mod try_ops;

pub type Result<T = (), E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

/// The Maximum Transmission Unit of standard Ethernet (frames up to 1500 bytes of IP packet data).
const ETHERNET_MTU: usize = 1500;
