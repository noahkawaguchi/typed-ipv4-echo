use libc::{IFF_NO_PI, IFF_TUN, IFNAMSIZ, TUNSETIFF};
use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::io::AsRawFd,
    process::Command,
};

/// The character device (clone device) used to create TUN virtual network interfaces.
const TUN_DEVICE_FILE: &str = "/dev/net/tun";

/// Creates a TUN device and configures it with IP address `ip_cidr`. A device name different from
/// `desired_name` may be assigned by the kernel. Returns the opened `File` and the assigned name.
pub fn init(desired_name: &str, ip_cidr: &str) -> io::Result<(File, String)> {
    let (tun, name) = create_device(desired_name.as_bytes())?;
    configure_device(&name, ip_cidr)?;
    Ok((tun, name))
}

/// Creates a TUN device, returning the opened `File` and the assigned name.
#[expect(unsafe_code, reason = "libc system calls to create TUN device")]
fn create_device(desired_name: &[u8]) -> io::Result<(File, String)> {
    // Open the kernel's special device file for creating virtual network interfaces
    let tun_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(TUN_DEVICE_FILE)?;

    // Initialize a new interface request C struct
    //
    // SAFETY: All fields of `ifreq` have valid all-zero bit patterns.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };

    // Copy the desired device name
    ifr.ifr_name = std::array::from_fn(|i| {
        if i == IFNAMSIZ - 1 {
            // End with at least one NUL, truncating the desired name if it's too long
            c_char_compat::NUL
        } else {
            // Pad with more NUL if the desired name leaves extra room
            desired_name
                .get(i)
                .copied()
                .map_or(c_char_compat::NUL, c_char_compat::from_u8)
        }
    });

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
            .take_while(|&c| c != c_char_compat::NUL)
            .map(c_char_compat::to_u8)
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

/// Module for handling compatibility between C `char` (may or may not be signed depending on the
/// platform) and Rust `u8` (always unsigned), as well as relevant lints.
#[expect(
    clippy::allow_attributes,
    reason = "There's no conditional compilation for C `char` signedness"
)]
#[allow(
    clippy::unnecessary_cast,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    reason = "Casting is the portable solution because `libc::c_char` may be either `u8` or `i8`"
)]
mod c_char_compat {
    /// The NUL character '\0' as either a `u8` or an `i8` depending on the platform.
    pub(super) const NUL: libc::c_char = 0;

    pub(super) const fn from_u8(b: u8) -> libc::c_char { b as libc::c_char }

    pub(super) const fn to_u8(c: libc::c_char) -> u8 { c as u8 }
}
