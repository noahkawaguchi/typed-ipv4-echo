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

/// The character device (clone device) used to create TUN virtual network interfaces.
const TUN_DEVICE_FILE: &str = "/dev/net/tun";

/// Creates a TUN device and configures it with IP address `ip_cidr`, returning the opened `File`
/// and the assigned name.
pub fn init(ip_cidr: &str) -> io::Result<(File, String)> {
    let (tun, name) = create_device()?;
    configure_device(&name, ip_cidr)?;
    Ok((tun, name))
}

/// Creates a TUN device, returning the opened `File` and the assigned name.
#[expect(unsafe_code, reason = "libc system calls to create TUN device")]
fn create_device() -> io::Result<(File, String)> {
    // Open the kernel's special device file for creating virtual network interfaces
    let tun_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(TUN_DEVICE_FILE)?;

    // Initialize a new interface request C struct
    //
    // SAFETY: All fields of `ifreq` have valid all-zero bit patterns.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };

    // Copy the desired device name into `ifr_name` (leaving room for the null terminator)
    for (i, b) in DESIRED_TUN_NAME.bytes().enumerate().take(IFNAMSIZ - 1) {
        ifr.ifr_name[i] = libc::c_char::from(b);
    }

    // Set flags
    #[expect(
        clippy::cast_possible_truncation,
        reason = "0x1 | 0x1000 fits in a short"
    )]
    {
        // IFF_TUN   - TUN device (no Ethernet headers) rather than TAP
        // IFF_NO_PI - Do not prepend packet metadata (get IP packet only)
        ifr.ifr_ifru.ifru_flags = (IFF_TUN | IFF_NO_PI) as libc::c_short;
    }

    // Create the TUN interface
    //
    // SAFETY: `tun_file` stays open for the whole call, so its fd is valid. `TUNSETIFF` expects a
    // pointer to an `ifreq`, and `&mut ifr` is a unique borrow of a valid, aligned, fully
    // initialized `ifreq` that outlives the call.
    if unsafe { libc::ioctl(tun_file.as_raw_fd(), TUNSETIFF, &mut ifr) } < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok((
        tun_file,
        // Extract the actual device name assigned by the kernel
        ifr.ifr_name
            .into_iter()
            .take_while(|&b| b != b'\0')
            .map(char::from)
            .collect(),
    ))
}

/// Configures a TUN device with IP address `ip_cidr` and brings it up.
fn configure_device(device_name: &str, ip_cidr: &str) -> io::Result<()> {
    // Set IP address
    let addr_status = Command::new("ip")
        .args(["addr", "add", ip_cidr, "dev", device_name])
        .status()?;

    if !addr_status.success() {
        return Err(io::Error::other(format!(
            "Failed to set IP address for TUN device {device_name}: status {addr_status}"
        )));
    }

    // Bring interface up
    let link_status = Command::new("ip")
        .args(["link", "set", device_name, "up"])
        .status()?;

    if !link_status.success() {
        return Err(io::Error::other(format!(
            "Failed to bring interface up for TUN device {device_name}: status {link_status}"
        )));
    }

    Ok(())
}
