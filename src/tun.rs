use libc::{IFF_NO_PI, IFF_TUN, IFNAMSIZ, TUNSETIFF};
use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::io::AsRawFd,
    path::Path,
};

/// The character device (clone device) that serves as the entrypoint for TUN virtual network
/// interfaces.
const TUN_DEVICE_FILE: &str = "/dev/net/tun";

/// The pseudo-filesystem directory containing symlinks to networking devices, including TUN
/// interfaces.
const SYSFS_NET_DEVICES: &str = "/sys/class/net";

/// Attaches to the TUN device with name `device_name` as an opened `File`.
#[expect(unsafe_code, reason = "libc FFI to manage TUN device")]
pub fn open(device_name: &str) -> io::Result<File> {
    let device_name_bytes = device_name.as_bytes();

    // There must be at least one byte of space after the name for the trailing NUL
    if device_name_bytes.len() >= IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUN device name too long",
        ));
    }

    // The interface must already exist, otherwise the `ioctl` call will try to create it and fail
    // with permission denied
    if !Path::new(SYSFS_NET_DEVICES)
        .join(device_name)
        .try_exists()?
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("TUN device {device_name} does not exist"),
        ));
    }

    // Initialize a new interface request C struct.
    //
    // SAFETY: All fields of `ifreq` have valid all-zero bit patterns.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };

    // Copy the device name
    ifr.ifr_name = std::array::from_fn(|i| {
        if i == IFNAMSIZ - 1 {
            // End with at least one NUL
            c_char_compat::NUL
        } else {
            // Pad with more NUL if the name leaves extra room
            device_name_bytes
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

    // Open the kernel's TUN/TAP device file
    let tun_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(TUN_DEVICE_FILE)?;

    // Bind the `tun_file` fd to the named interface.
    //
    // SAFETY: `tun_file` stays open for the whole call, so its fd is valid. `TUNSETIFF` expects a
    // pointer to an `ifreq`, and `&mut ifr` is a unique borrow of a valid, aligned, fully
    // initialized `ifreq` that outlives the call.
    if unsafe { libc::ioctl(tun_file.as_raw_fd(), TUNSETIFF, &mut ifr) } < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(tun_file)
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
}
