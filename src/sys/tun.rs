use {
    libc::{IFF_NO_PI, IFF_TUN, IFNAMSIZ, TUNSETIFF},
    std::{
        fs::{File, OpenOptions},
        io,
        os::unix::io::AsRawFd as _,
        path::Path,
    },
};

/// The character device (clone device) that serves as the entrypoint for TUN virtual network
/// interfaces.
const TUN_DEVICE_FILE: &str = "/dev/net/tun";

/// The pseudo-filesystem directory containing symlinks to networking devices, including TUN
/// interfaces.
const SYSFS_NET_DEVICES: &str = "/sys/class/net";

/// The flags to use for the interface request.
///
/// `IFF_TUN`   - TUN device (no Ethernet headers) rather than TAP
/// `IFF_NO_PI` - Do not prepend packet metadata (get IP packet only)
#[expect(clippy::cast_possible_truncation, reason = "0x1 | 0x1000 fits in a short")]
const IFRU_FLAGS: libc::c_short = (IFF_TUN | IFF_NO_PI) as libc::c_short;

/// Attaches to the TUN device with name `device_name` as an opened `File`.
///
/// # Errors
///
/// Returns `Err` if the device does not exist or could not be attached to.
#[expect(unsafe_code, reason = "libc FFI to attach to TUN device")]
pub fn attach(device_name: &str) -> io::Result<File> {
    // The interface must already exist, otherwise the `ioctl()` syscall will try to create it and
    // fail with permission denied
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
    ifr.ifr_name
        .iter_mut()
        .zip(device_name.bytes().map(u8_to_c_char))
        // Leave space for the trailing NUL byte (redundant with the existence check above since the
        // name must be valid for the device to exist)
        .take(IFNAMSIZ - 1)
        .for_each(|(c, b)| *c = b);

    // Set options in flags
    ifr.ifr_ifru.ifru_flags = IFRU_FLAGS;

    // Open the kernel's TUN/TAP device file
    let tun_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(TUN_DEVICE_FILE)?;

    // Bind the file's fd to the named interface and return it.
    //
    // SAFETY: `tun_file` stays open for the whole call, so its fd is valid. `TUNSETIFF` expects a
    // pointer to an `ifreq`, and `&mut ifr` is a unique borrow of a valid, aligned, fully
    // initialized `ifreq` that outlives the call.
    (unsafe { libc::ioctl(tun_file.as_raw_fd(), TUNSETIFF, &mut ifr) } != -1)
        .then_some(tun_file)
        .ok_or_else(io::Error::last_os_error)
}

/// Casts Rust `u8` to C `char` without performing any checks.
///
/// - On platforms where C `char` is unsigned (e.g. `aarch64` Linux), this is a no-op cast to the
///   same type.
/// - On platforms where C `char` is signed (e.g. `x86_64` Linux), values above 127 wrap to negative
///   numbers.
#[expect(clippy::allow_attributes, reason = "No conditional compilation for C `char` signedness")]
#[allow(
    clippy::cast_possible_wrap,
    reason = "Casting is the portable solution because `libc::c_char` may be `u8` or `i8`"
)]
const fn u8_to_c_char(b: u8) -> libc::c_char { b as libc::c_char }

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{Config, Result},
        std::assert_matches,
    };

    #[test]
    fn errors_for_nonexistent_tun() {
        assert_matches!(
            attach("abcdefghijklmnopqrstuvwxyz"),
            Err(e) if e.kind() == io::ErrorKind::NotFound
        );
    }

    #[test]
    #[ignore = "requires TUN setup"]
    fn successfully_attaches_to_existing_tun() -> Result {
        assert_matches!(attach(&Config::load()?.tun_name), Ok(_));
        Ok(())
    }

    /// Causes a compilation error if the two arguments are not of the same type.
    #[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "x86_64")))]
    const fn same_type<T: Copy>(_: T, _: T) {}

    /// Sanity check that C `char` is unsigned on `aarch64` Linux.
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const _: () = same_type(libc::c_char::MAX, u8::MAX);

    /// Sanity check that C `char` is signed on `x86_64` Linux.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const _: () = same_type(libc::c_char::MAX, i8::MAX);

    /// Sanity check that C `size_t` is equivalent to Rust `usize` on both `aarch64` Linux and
    /// `x86_64` Linux.
    #[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "x86_64")))]
    const _: () = same_type(libc::size_t::MAX, usize::MAX);
}
