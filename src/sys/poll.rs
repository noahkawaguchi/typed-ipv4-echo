use std::{
    io,
    os::fd::{AsFd, AsRawFd as _},
    time::Duration,
};

/// Polls `fd` for readability. If `timeout` is `Some(duration)`, blocks for at most `duration`,
/// otherwise blocks indefinitely (i.e. until `fd` is readable or the syscall is interrupted).
///
/// Returns `Ok(true)` if `fd` becomes readable before the timeout elapses, or `Ok(false)` if
/// the timeout elapses first. If a signal is caught while blocked and `SA_RESTART` is not set,
/// returns `Err` with `io::ErrorKind::Interrupted`.
#[expect(unsafe_code, reason = "libc syscall to poll for fd readiness")]
pub fn readable(fd: impl AsFd, timeout: Option<Duration>) -> io::Result<bool> {
    // Set input `events` to `POLLIN` to signify interest in there being data to read for `fd`
    let mut pfd = libc::pollfd { fd: fd.as_fd().as_raw_fd(), events: libc::POLLIN, revents: 0 };

    // -1 means block indefinitely
    let timeout_ms =
        timeout.map_or(-1, |duration| duration.as_millis().try_into().unwrap_or(libc::c_int::MAX));

    // SAFETY: `&raw mut pfd` is a valid, aligned, writable pointer to a `pollfd` on the stack,
    // and 1 is its correct length (`pfd` points to one item).
    match unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) } {
        ..0 => Err(io::Error::last_os_error()),

        // Timed out
        0 => Ok(false),

        // Number of elements whose `revents` fields have been set to nonzero (only one here)
        1.. => Ok(true),
    }
}
