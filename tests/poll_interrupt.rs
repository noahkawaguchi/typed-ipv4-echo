//! Test confirming that:
//!
//! - A blocking `poll()` syscall is interrupted and returns `EINTR` instead of silently restarting
//!   when `SIGINT` arrives, since the shutdown handler installation should leave `SA_RESTART`
//!   unset.
//! - That error is correctly propagated through `sys::poll::readable`.
//!
//! Written as an integration test so it runs as its own process, since installing a signal handler
//! and flipping the static shutdown flag mutate process-wide state.

#[path = "../src/sys/shutdown_signal.rs"]
#[expect(dead_code, reason = "Parts of `shutdown_signal.rs` are unused in this specific test")]
mod shutdown_signal;

#[path = "../src/sys/poll.rs"]
mod poll;

use {
    shutdown_signal::ShutdownSignal,
    std::{assert_matches, io, os::unix::net::UnixStream, sync::mpsc, thread, time::Duration},
};

#[test]
#[expect(unsafe_code, reason = "libc FFI to target a spawned thread with a real SIGINT")]
fn poll_is_interrupted_by_sigint_instead_of_restarted() -> io::Result<()> {
    ShutdownSignal::install()?; // `SA_RESTART` unset

    let (_tx, rx) = UnixStream::pair()?;
    let (tid_tx, tid_rx) = mpsc::channel();

    let poller = thread::spawn(move || {
        tid_tx
            // SAFETY: `pthread_self` has no preconditions and always succeeds.
            .send(unsafe { libc::pthread_self() })
            .map_err(io::Error::other)?;

        poll::readable(&rx, None)
    });

    let tid = tid_rx.recv().map_err(io::Error::other)?;

    // Bias toward the poller thread already being blocked inside `poll()` before the signal
    // arrives, since if the signal arrived first, there would be nothing to interrupt and the test
    // would hang instead of failing.
    thread::sleep(Duration::from_millis(50));

    // SAFETY: `tid` names the poller thread, which is still alive (joined below), and `SIGINT` is
    // a valid signal number.
    if unsafe { libc::pthread_kill(tid, libc::SIGINT) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let result = poller
        .join()
        .map_err(|_| io::Error::other("poller thread panicked"))?;

    assert_matches!(result, Err(e) if e.kind() == io::ErrorKind::Interrupted);

    Ok(())
}
