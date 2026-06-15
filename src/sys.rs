pub mod tun;
pub use shutdown_signal::ShutdownSignal;

mod shutdown_signal;

use std::{
    fs::File,
    io::{self, Read as _},
};

pub fn random_u32() -> io::Result<u32> {
    let mut buf = [0u8; 4];
    File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(u32::from_ne_bytes(buf))
}

pub mod poll {
    use std::{io, os::fd::RawFd};

    /// Polls `fd` for readability, blocking for at most `timeout_ms` milliseconds. `-1` blocks
    /// indefinitely, and `0` returns immediately.
    ///
    /// Returns `Ok(true)` if `fd` becomes readable before the timeout elapses, or `Ok(false)` if
    /// the timeout elapses first. If a signal is caught while blocked and `SA_RESTART` is not set,
    /// returns `Err` with `io::ErrorKind::Interrupted`.
    #[expect(unsafe_code, reason = "libc syscall to poll for fd readiness")]
    pub fn readable(fd: RawFd, timeout_ms: i32) -> io::Result<bool> {
        // Set input `events` to `POLLIN` to signify interest in there being data to read for `fd`
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };

        // SAFETY: `&raw mut pfd` is a valid, aligned, writable pointer to a `pollfd` on the stack,
        // and 1 is its correct length (`pfd` points to one item).
        match unsafe { libc::poll(&raw mut pfd, 1, timeout_ms as libc::c_int) } {
            ..0 => Err(io::Error::last_os_error()),

            // Timed out
            0 => Ok(false),

            // Number of elements whose `revents` fields have been set to nonzero (only one here)
            1.. => Ok(true),
        }
    }
}
