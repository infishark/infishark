//! Shared Ctrl-C handling for the long-running subcommands

use std::sync::atomic::{AtomicBool, Ordering};

/// Cleared by Ctrl-C; long-running loops poll this to exit.
pub(crate) static RUNNING: AtomicBool = AtomicBool::new(true);

/// Install a Ctrl-C handler that clears RUNNING.
pub(crate) fn install_sigint() {
    imp::install();
}

#[cfg(unix)]
mod imp {
    use super::{Ordering, RUNNING};

    extern "C" fn on_sigint(_: libc::c_int) {
        RUNNING.store(false, Ordering::SeqCst);
    }

    pub(super) fn install() {
        unsafe {
            libc::signal(
                libc::SIGINT,
                on_sigint as extern "C" fn(libc::c_int) as libc::sighandler_t,
            );
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::{Ordering, RUNNING};
    use windows_sys::Win32::System::Console::{CTRL_C_EVENT, SetConsoleCtrlHandler};

    // Returns TRUE to mark Ctrl-C handled; anything else falls through to the next
    // handler.
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
