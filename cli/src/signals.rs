//! Shared Ctrl-C handling for the long-running subcommands.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Cleared by Ctrl-C; long-running loops poll this to exit.
pub(crate) static RUNNING: AtomicBool = AtomicBool::new(true);

/// Install a Ctrl-C handler that clears [`RUNNING`].
pub(crate) fn install_sigint() {
    imp::install();
}

/// Ctrl-C. Not a device error.
#[derive(Debug)]
pub(crate) struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cancelled")
    }
}

impl std::error::Error for Cancelled {}

pub(crate) fn cancelled() -> anyhow::Error {
    anyhow::Error::new(Cancelled)
}

pub(crate) fn ensure_running() -> anyhow::Result<()> {
    if RUNNING.load(Ordering::SeqCst) {
        Ok(())
    } else {
        Err(cancelled())
    }
}

/// Whether `err` is a Ctrl-C.
pub(crate) fn is_cancel(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause.downcast_ref::<Cancelled>().is_some()
            || cause
                .downcast_ref::<infishark::Error>()
                .is_some_and(|e| matches!(e, infishark::Error::Interrupted))
            || cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::Interrupted)
    })
}

/// Sleep up to `total`. Returns false on Ctrl-C.
pub(crate) fn sleep_while_running(total: Duration) -> bool {
    let step = Duration::from_millis(50);
    let start = std::time::Instant::now();
    while start.elapsed() < total {
        if !RUNNING.load(Ordering::SeqCst) {
            return false;
        }
        let left = total.saturating_sub(start.elapsed());
        std::thread::sleep(left.min(step));
    }
    RUNNING.load(Ordering::SeqCst)
}

#[cfg(unix)]
mod imp {
    use super::{Ordering, RUNNING};

    extern "C" fn on_sigint(_: libc::c_int) {
        RUNNING.store(false, Ordering::SeqCst);
    }

    pub(super) fn install() {
        // Restarting the read would ignore Ctrl-C until Enter.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_sigint as *const () as libc::sighandler_t;
            sa.sa_flags = 0;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::{Ordering, RUNNING};
    use windows_sys::Win32::System::Console::{CTRL_C_EVENT, SetConsoleCtrlHandler};

    // 1 means this handler consumed the event.
    unsafe extern "system" fn on_ctrl(ctrl_type: u32) -> i32 {
        if ctrl_type == CTRL_C_EVENT {
            RUNNING.store(false, Ordering::SeqCst);
            1
        } else {
            0
        }
    }

    pub(super) fn install() {
        unsafe {
            SetConsoleCtrlHandler(Some(on_ctrl), 1);
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    pub(super) fn install() {}
}
