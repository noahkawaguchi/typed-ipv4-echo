use libc::{IFF_NO_PI, IFF_TUN, IFNAMSIZ, TUNSETIFF};
use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::io::AsRawFd,
    process::Command,
};

/// The desired name to use when creating a TUN device. A different name may be assigned by the
/// kernel.
const DESIRED_TUN_NAME: &str = "tun0";

/// Creates a TUN device and configures it with IP address `ip_cidr`, returning the opened `File`
/// and the assigned name.
pub fn init(ip_cidr: &str) -> io::Result<(File, String)> {
    let (tun, name) = create_device()?;
    configure_device(&name, ip_cidr)?;
    Ok((tun, name))
}

/// Creates a TUN device, returning the opened `File` and the assigned name.
#[allow(unsafe_code)]
fn create_device() -> io::Result<(File, String)> {
    // Open the kernel's special device file for creating virtual network interfaces
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;

    // Initialize a new interface request C struct
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };

    // Copy desired device name into ifr_name (leaving room for the null terminator)
    for (i, b) in DESIRED_TUN_NAME.bytes().enumerate().take(IFNAMSIZ - 1) {
        ifr.ifr_name[i] = b;
    }

    // Set flags
    #[allow(clippy::cast_possible_truncation)] // This is 0x1 | 0x1000, which fits in a short
    {
        // IFF_TUN   - TUN device (no Ethernet headers) rather than TAP
        // IFF_NO_PI - Do not prepend packet metadata (get IP packet only)
        ifr.ifr_ifru.ifru_flags = (IFF_TUN | IFF_NO_PI) as libc::c_short;
    }

    // Create the TUN interface
    if unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &ifr) } < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok((
        file,
        // Extract the actual device name assigned by the kernel
        ifr.ifr_name
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| char::from(b))
            .collect(),
    ))
}

/// Configures a TUN device with IP address `ip_cidr` and brings it up.
fn configure_device(device_name: &str, ip_cidr: &str) -> io::Result<()> {
    // Set IP address
    let status = Command::new("ip")
        .args(["addr", "add", ip_cidr, "dev", device_name])
        .status()?;

    if !status.success() {
        return Err(io::Error::other(format!(
            "failed to set IP address for TUN device {device_name}: status {status}"
        )));
    }

    // Bring interface up
    let status = Command::new("ip")
        .args(["link", "set", device_name, "up"])
        .status()?;

    if !status.success() {
        return Err(io::Error::other(format!(
            "failed to bring interface up for TUN device {device_name}: status {status}"
        )));
    }

    Ok(())
}
