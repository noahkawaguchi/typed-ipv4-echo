pub mod tun;
pub use shutdown_signal::ShutdownSignal;

mod shutdown_signal;

use std::{
    fs::File,
    io::{self, Read},
};

pub fn random_u32() -> Result<u32, io::Error> {
    let mut buf = [0u8; 4];
    File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(u32::from_ne_bytes(buf))
}
