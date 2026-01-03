use libc::{IFF_NO_PI, IFF_TUN, IFNAMSIZ, TUNSETIFF};
use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::io::AsRawFd,
    process::Command,
};

/// Creates a TUN device, requesting that the name be `desired_name`. Returns the opened `File` and
/// the actual assigned name.
#[allow(unsafe_code)]
pub fn create_device(desired_name: &str) -> io::Result<(File, String)> {
    // Open the kernel's special device file for creating virtual network interfaces
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;

    // Initialize a new interface request C struct
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };

    // Copy desired device name into ifr_name (leaving room for the null terminator)
    for (i, b) in desired_name.bytes().enumerate().take(IFNAMSIZ - 1) {
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

/// Configures a TUN device with an IP address and brings it up.
pub fn configure_device(device_name: &str, ip_cidr: &str) -> io::Result<()> {
    // Set IP address
    let status = Command::new("ip")
        .args(["addr", "add", ip_cidr, "dev", device_name])
        .status()?;

    if !status.success() {
        return Err(io::Error::other(format!(
            "failed to set IP address for TUN device {device_name}: {status}"
        )));
    }

    // Bring interface up
    let status = Command::new("ip")
        .args(["link", "set", device_name, "up"])
        .status()?;

    if !status.success() {
        return Err(io::Error::other(format!(
            "failed to bring interface up for TUN device {device_name}: {status}"
        )));
    }

    Ok(())
}
