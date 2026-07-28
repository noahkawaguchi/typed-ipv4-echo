use {
    libc::{IFF_NO_PI, IFF_TUN, IFNAMSIZ, TUNSETIFF},
    std::{
        error::Error,
        fs::{File, OpenOptions},
        io, iter,
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
/// Returns `Err` if the device does not exist, `device_name` is an invalid name, or the device
/// could not be attached to.
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

    ifr.ifr_name = prepare_ifr_name(device_name)?; // Validate and copy the device name
    ifr.ifr_ifru.ifru_flags = IFRU_FLAGS; // Set options in flags

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

/// Converts a `&str` into an interface name. If `n` is the number of bytes in `name`, `n` must be
/// between 1 and `IFNAMSIZ - 1` inclusive, and the remaining `IFNAMSIZ - n` bytes will be NUL.
///
/// # Errors
///
/// Returns `Err` if `name` is invalid for a network device according to the following sources:
/// - `dev_valid_name` in `linux/net/core/dev.c`
/// - `_ctype` in `linux/lib/ctype.c`
/// - `isspace` in `linux/include/linux/ctype.h`
fn prepare_ifr_name(name: &str) -> io::Result<[libc::c_char; IFNAMSIZ]> {
    /// The final index in the interface name array, which must be reserved for the NUL terminator.
    const FINAL_IDX: libc::size_t = IFNAMSIZ - 1;

    if matches!(name, "." | "..") {
        return Err(invalid_input("TUN device name cannot be . or .."));
    }

    let mut ifr_name = [0; IFNAMSIZ];

    ifr_name
        .iter_mut()
        .zip(name.bytes().map(Some).chain(iter::repeat(None)))
        .enumerate()
        .try_for_each(|(i, (ifr_char, name_byte))| {
            *ifr_char = match (i, name_byte) {
                // The first byte must come from the provided name
                (0, None) => return Err(invalid_input("TUN device name cannot be empty")),
                (0, Some(b)) => validate_character(b)?,

                // Intermediate bytes may come from the provided name or be NUL padding
                (1..FINAL_IDX, maybe_b) => maybe_b
                    .map(validate_character)
                    .transpose()?
                    .unwrap_or_default(),

                // The final byte must be the NUL terminator
                (FINAL_IDX.., Some(_)) => return Err(invalid_input("TUN device name too long")),
                (FINAL_IDX.., None) => 0,
            };

            Ok(())
        })?;

    Ok(ifr_name)
}

/// Uses `msg` to create an `io::Error` of kind `InvalidInput`.
fn invalid_input(msg: impl Into<Box<dyn Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

/// If `b` is a disallowed character in Linux network device names, returns `Err`, otherwise
/// converts it to a `libc::c_char`.
fn validate_character(b: u8) -> io::Result<libc::c_char> {
    (!matches!(b, b'/' | b':' | b'\t'..=b'\r' | b' ' | 0xA0))
        .then(|| u8_to_c_char(b))
        .ok_or_else(|| {
            invalid_input(format!(
                "TUN device name cannot contain the character '{}'",
                char::from(b)
            ))
        })
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
    fn pads_short_name_with_nul_bytes() {
        assert_matches!(
            prepare_ifr_name("a"),
            Ok(name) if name == b"a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".map(u8_to_c_char)
        );
    }

    #[test]
    fn allows_name_at_length_limit() {
        const NAME: &str = "abcdefghijklmno";
        const _: () = assert!(NAME.len() == IFNAMSIZ - 1);

        assert_matches!(
            prepare_ifr_name(NAME),
            Ok(name) if name == b"abcdefghijklmno\0".map(u8_to_c_char)
        );
    }

    #[test]
    fn errors_for_name_too_long() {
        const NAME: &str = "abcdefghijklmnop";
        const _: () = assert!(NAME.len() == IFNAMSIZ);

        assert_matches!(
            prepare_ifr_name(NAME),
            Err(e) if e.kind() == io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn errors_for_empty_name() {
        assert_matches!(
            prepare_ifr_name(""),
            Err(e) if e.kind() == io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn errors_for_dot_and_dot_dot_names() {
        for invalid_name in [".", ".."] {
            assert_matches!(
                prepare_ifr_name(invalid_name),
                Err(e) if e.kind() == io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn errors_for_illegal_characters_in_name() {
        for invalid_name in [" tun", "\tun", "tu\n", "t:un", "/dev/null"] {
            assert_matches!(
                prepare_ifr_name(invalid_name),
                Err(e) if e.kind() == io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn errors_for_nonexistent_tun() {
        assert_matches!(attach("nonexistent"), Err(e) if e.kind() == io::ErrorKind::NotFound);
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
