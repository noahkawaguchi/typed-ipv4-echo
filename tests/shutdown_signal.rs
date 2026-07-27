//! Test for the shutdown signal handler installation and functionality. Written as an integration
//! test so it runs as a separate process from the main unit test binary, since installing a handler
//! and raising signals mutates process-wide state.

#[path = "../src/sys/shutdown_signal.rs"]
mod shutdown_signal;

use {shutdown_signal::ShutdownSignal, std::io};

#[test]
#[expect(unsafe_code, reason = "libc FFI to raise a real SIGINT for testing the handler")]
fn shutdown_flag_starts_false_and_flips_on_sigint() -> io::Result<()> {
    let shutdown = ShutdownSignal::install()?;

    assert!(!shutdown.load());

    // SAFETY: raising `SIGINT` on the current process is well-defined, and the handler installed
    // above is async-signal-safe (a single relaxed store), so this cannot corrupt process state.
    if unsafe { libc::raise(libc::SIGINT) } != 0 {
        return Err(io::Error::last_os_error());
    }

    assert!(shutdown.load());

    Ok(())
}
