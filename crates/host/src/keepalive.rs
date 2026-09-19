//! Best-effort "keep the host awake while serving" - the D1 fix.
//!
//! A sleeping laptop is unreachable over iroh, which breaks Portty's core
//! "terminal from anywhere" promise: you open your phone on the train and the
//! host laptop is asleep at home, so nothing connects. While the host is in
//! serve/both mode we hold a platform inhibitor so the machine doesn't idle-sleep
//! while it's waiting for a phone to reach it. Opt out with `PORTTY_KEEP_AWAKE=0`.
//!
//! Platform coverage:
//!   - **macOS** - spawns `caffeinate -is` (idle + system-sleep assertion).
//!   - **Linux** - best-effort `systemd-inhibit --what=idle` (no-op if absent).
//!   - **Windows** - `SetThreadExecutionState` (system + display required).
//!
//! Honest limit: this prevents **idle** sleep (the laptop nodding off on the
//! desk while the daemon waits). It cannot defeat lid-close clamshell sleep
//! without external power + display on macOS, nor a hard `systemctl suspend`.
//! The real fix for "always reachable" is an always-on machine (server / Pi /
//! NAS) - see the roost `Portty/13 - Real-World Defects & Fixes` defect D1.

use std::io;

// `Command`/`Stdio`/`Child` are only used by the macOS + Linux inhibitor
// branches (which spawn caffeinate / systemd-inhibit). Windows uses
// `SetThreadExecutionState` instead, so these are unused there - gate them so
// the crate stays warning-clean on all three platforms.
#[cfg(not(windows))]
use std::process::{Child, Command, Stdio};

/// Decide whether keep-awake is on, given the `PORTTY_KEEP_AWAKE` env value.
/// Pure so it can be unit-tested without mutating the process environment.
fn enabled_from_env(env_val: Option<&str>) -> bool {
    !matches!(env_val, Some("0") | Some("false"))
}

/// RAII handle: the platform inhibitor is active while this is alive. Drop
/// releases it. Construct with [`KeepAwake::activate`].
pub struct KeepAwake {
    handle: Option<KeepHandle>,
    enabled: bool,
}

enum KeepHandle {
    /// A spawned inhibitor process we kill on drop (caffeinate / systemd-inhibit).
    #[cfg(not(windows))]
    Child(Child),
    /// Windows: we set the thread execution state; release resets it.
    #[cfg(windows)]
    WinState,
}

impl KeepAwake {
    /// Activate the inhibitor unless `PORTTY_KEEP_AWAKE=0`. Activation errors are
    /// logged and degraded to a no-op - keep-awake is best-effort and must never
    /// stop the host from starting.
    pub fn activate() -> Self {
        let enabled = enabled_from_env(std::env::var("PORTTY_KEEP_AWAKE").ok().as_deref());
        if !enabled {
            tracing::info!("keep-awake disabled by PORTTY_KEEP_AWAKE=0");
            return Self {
                handle: None,
                enabled,
            };
        }
        match platform_activate() {
            Ok(h) => {
                tracing::info!("keep-awake active: host will not idle-sleep while serving");
                Self {
                    handle: Some(h),
                    enabled,
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "keep-awake unavailable on this platform (host may idle-sleep); continuing"
                );
                Self {
                    handle: None,
                    enabled,
                }
            }
        }
    }
}

impl Drop for KeepAwake {
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }
        if let Some(h) = self.handle.take() {
            release(h);
        }
    }
}

#[cfg(target_os = "macos")]
fn platform_activate() -> io::Result<KeepHandle> {
    let child = Command::new("caffeinate")
        .args(["-is"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(KeepHandle::Child(child))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_activate() -> io::Result<KeepHandle> {
    // Linux: best-effort systemd-inhibit. If systemd isn't the init (or the
    // binary is absent), this errors and we degrade to a logged no-op.
    let child = Command::new("systemd-inhibit")
        .args([
            "--what=idle",
            "--who=Portty",
            "--mode=block",
            "sleep",
            "infinity",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(KeepHandle::Child(child))
}

#[cfg(windows)]
fn platform_activate() -> io::Result<KeepHandle> {
    use windows_sys::Win32::System::Power::{
        SetThreadExecutionState, ES_CONTINUOUS, ES_DISPLAY_REQUIRED, ES_SYSTEM_REQUIRED,
    };
    // SAFETY: `SetThreadExecutionState` takes a flags word, no pointers; it sets
    // thread-local power state. Calling it once on activation is the documented use.
    unsafe {
        SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED);
    }
    Ok(KeepHandle::WinState)
}

// Fallback for targets that are neither a Unix (macOS + Linux/BSD are handled
// above) nor Windows - e.g. wasm. Must exclude ALL unix, not just macOS, or it
// collides with the `all(unix, not(macos))` Linux arm above (duplicate defn).
#[cfg(not(any(unix, windows)))]
fn platform_activate() -> io::Result<KeepHandle> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "keep-awake not implemented on this platform",
    ))
}

fn release(h: KeepHandle) {
    match h {
        #[cfg(not(windows))]
        KeepHandle::Child(mut c) => {
            // Best-effort kill. `caffeinate` also dies with its parent, and
            // systemd-inhibit releases when its child exits - but explicit kill
            // keeps the drop prompt and avoids relying on parent-death semantics.
            let _ = c.kill();
            let _ = c.wait();
        }
        #[cfg(windows)]
        KeepHandle::WinState => {
            use windows_sys::Win32::System::Power::{SetThreadExecutionState, ES_CONTINUOUS};
            // SAFETY: same as activate; ES_CONTINUOUS alone clears the override.
            unsafe {
                SetThreadExecutionState(ES_CONTINUOUS);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggle_defaults_on() {
        assert!(enabled_from_env(None));
        assert!(enabled_from_env(Some("1")));
        assert!(enabled_from_env(Some("yes")));
        assert!(!enabled_from_env(Some("0")));
        assert!(!enabled_from_env(Some("false")));
    }

    #[test]
    fn activate_with_no_inhibitor_is_safe() {
        // On an unsupported platform (or if the binary is missing) activate must
        // degrade to a no-op rather than panic. Constructing + dropping must not
        // unwind. (We can't pick the platform here; this just exercises the path.)
        let _k = KeepAwake::activate();
    }
}
