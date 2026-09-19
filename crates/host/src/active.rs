//! Active-device tracking + immediate revocation.
//!
//! The running daemon keeps an in-memory registry of connected phones keyed by
//! `DeviceId`, each with an [`AbortHandle`] to its connection task. Two things
//! use it:
//!
//!   * **Immediate revoke.** `portty-host revoke` runs in a *separate* process
//!     and only edits the peer store on disk. A watcher task in the daemon polls
//!     that store and aborts any live connection whose token has disappeared -
//!     so a revoke drops an already-connected phone within a couple of seconds,
//!     instead of only taking effect on its next reconnect.
//!
//!   * **Visibility.** The registry is mirrored to a small state file so the
//!     out-of-process `portty-host peers` command can show which devices are
//!     connected right now and when each was last seen.
//!
//! The state file records the daemon's PID so a reader can tell whether the
//! "connected" list is live or left over from a daemon that has since exited.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};
use tokio::task::AbortHandle;

use portty_transport::DeviceId;

const STATE_FILE: &str = "portty-active.dat";

/// Seconds between peer-store reloads in the revocation watcher.
pub const REVOKE_POLL_SECS: u64 = 2;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One currently-connected device (mirrored to disk for the `peers` command).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnEntry {
    pub device_id: DeviceId,
    pub name: String,
    /// Unix seconds when this connection was established.
    pub since: u64,
}

/// The on-disk mirror of the daemon's live connection state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActiveState {
    /// PID of the daemon that wrote this. A reader treats `connected` as live
    /// only if this process is still alive (else it's stale from a crash/exit).
    pub daemon_pid: u32,
    pub connected: Vec<ConnEntry>,
    /// Last time (unix seconds) each known device disconnected.
    pub last_seen: HashMap<DeviceId, u64>,
}

impl ActiveState {
    /// Read the state file (empty if absent/corrupt). Used by the `peers` CLI.
    pub fn load(dir: &Path) -> Self {
        std::fs::read(dir.join(STATE_FILE))
            .ok()
            .and_then(|b| postcard::from_bytes(&b).ok())
            .unwrap_or_default()
    }

    pub fn connected_since(&self, id: &DeviceId) -> Option<u64> {
        if !self.daemon_alive() {
            return None;
        }
        self.connected
            .iter()
            .find(|c| &c.device_id == id)
            .map(|c| c.since)
    }

    pub fn last_seen(&self, id: &DeviceId) -> Option<u64> {
        self.last_seen.get(id).copied()
    }

    /// Whether the daemon that wrote this file is still running. Shares one
    /// probe with the PID-file reader: the old non-Unix arm only checked
    /// `daemon_pid != 0`, so on Windows every leftover mirror reported its
    /// devices as still connected.
    pub fn daemon_alive(&self) -> bool {
        self.daemon_pid != 0 && crate::pid_alive(self.daemon_pid)
    }

    /// Forget the `connected` list left behind by a daemon that is gone, keeping
    /// the `last_seen` history. Used by the CLI when it cleans up after a
    /// force-killed daemon; the daemon itself rewrites the file via `persist`.
    pub fn clear_connected(dir: &Path) {
        let prior = Self::load(dir);
        if prior.daemon_pid == 0 && prior.connected.is_empty() {
            return;
        }
        let state = Self {
            daemon_pid: 0,
            connected: Vec::new(),
            last_seen: prior.last_seen,
        };
        let path = dir.join(STATE_FILE);
        let write = || -> std::io::Result<()> {
            use std::io::Write;
            let bytes = postcard::to_allocvec(&state)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            let tmp = path.with_extension("dat.tmp");
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &path)
        };
        if let Err(e) = write() {
            tracing::warn!(error = %e, "active-state: could not clear stale connections");
        }
    }
}

struct Conn {
    id: u64,
    abort: AbortHandle,
    name: String,
    since: u64,
    control: mpsc::Sender<ConnectionControl>,
}

/// Security control delivered out-of-band from ordinary phone commands. The
/// connection loop prioritizes this channel and sends the notice over its
/// already-authenticated envelope before closing.
#[derive(Debug, Clone)]
pub enum ConnectionControl {
    Revoked {
        pair_id: [u8; 16],
        event_id: [u8; 16],
    },
}

/// The daemon-side registry of live connections.
#[derive(Clone)]
pub struct ActiveDevices {
    inner: Arc<Mutex<HashMap<DeviceId, Conn>>>,
    /// Persisted last-seen times, carried across connect/disconnect.
    last_seen: Arc<Mutex<HashMap<DeviceId, u64>>>,
    next_connection_id: Arc<AtomicU64>,
    /// Serialize snapshot + temp-file rename so concurrent connect/disconnect
    /// persistence cannot overwrite newer state with an older snapshot.
    persist_lock: Arc<Mutex<()>>,
    path: PathBuf,
}

impl ActiveDevices {
    /// Fresh registry for this daemon. Clears any leftover `connected` list from
    /// a previous run but preserves its `last_seen` history.
    pub fn new(dir: &Path) -> Self {
        let prior = ActiveState::load(dir);
        let me = Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            last_seen: Arc::new(Mutex::new(prior.last_seen)),
            next_connection_id: Arc::new(AtomicU64::new(1)),
            persist_lock: Arc::new(Mutex::new(())),
            path: dir.join(STATE_FILE),
        };
        // Rewrite immediately so the file reflects THIS daemon (pid + empty set).
        let me2 = me.clone();
        tokio::spawn(async move { me2.persist().await });
        me
    }

    /// Register a freshly-connected device.
    pub async fn register(
        &self,
        device_id: DeviceId,
        name: String,
        abort: AbortHandle,
        control: mpsc::Sender<ConnectionControl>,
    ) -> u64 {
        let id = self.next_connection_id.fetch_add(1, Ordering::Relaxed);
        let replaced = self.inner.lock().await.insert(
            device_id,
            Conn {
                id,
                abort,
                name,
                since: now_unix(),
                control,
            },
        );
        // One authenticated device owns one live connection. Replacing it closes
        // the old task immediately; otherwise revoking the map's visible entry
        // could leave the hidden duplicate connected.
        if let Some(old) = replaced {
            old.abort.abort();
        }
        self.persist().await;
        id
    }

    /// Remove this exact connection on disconnect and stamp its last-seen time.
    /// Cleanup from an older replaced task must not remove the newer connection.
    pub async fn deregister(&self, device_id: &DeviceId, connection_id: u64) -> bool {
        let removed = {
            let mut inner = self.inner.lock().await;
            if inner
                .get(device_id)
                .is_some_and(|connection| connection.id == connection_id)
            {
                inner.remove(device_id);
                true
            } else {
                false
            }
        };
        if removed {
            self.last_seen.lock().await.insert(*device_id, now_unix());
            self.persist().await;
        }
        removed
    }

    /// Abort any live connection whose `DeviceId` is no longer in `valid` (i.e.
    /// was revoked on disk). Returns the number of connections dropped.
    pub async fn drop_revoked(&self, valid: &HashMap<DeviceId, impl Sized>) -> usize {
        let guard = self.inner.lock().await;
        let mut dropped = 0;
        for (id, conn) in guard.iter() {
            if !valid.contains_key(id) {
                conn.abort.abort();
                dropped += 1;
            }
        }
        dropped
    }

    /// Notify a live peer of a committed generation-bound revocation. A stuck
    /// connection gets a short grace period to flush the sealed notice and is
    /// then aborted unconditionally. Authorization is already denied by the
    /// durable tombstone before this method is called.
    pub async fn notify_revoked(
        &self,
        device: DeviceId,
        pair_id: [u8; 16],
        event_id: [u8; 16],
    ) -> bool {
        let target = self
            .inner
            .lock()
            .await
            .get(&device)
            .map(|conn| (conn.control.clone(), conn.abort.clone()));
        let Some((control, abort)) = target else {
            return false;
        };
        let delivered = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            control.send(ConnectionControl::Revoked { pair_id, event_id }),
        )
        .await
        .is_ok_and(|result| result.is_ok());
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            abort.abort();
        });
        delivered
    }

    /// Write the current state to disk (best-effort; a warn on failure).
    async fn persist(&self) {
        let _persist = self.persist_lock.lock().await;
        let connected: Vec<ConnEntry> = self
            .inner
            .lock()
            .await
            .iter()
            .map(|(id, c)| ConnEntry {
                device_id: *id,
                name: c.name.clone(),
                since: c.since,
            })
            .collect();
        let last_seen = self.last_seen.lock().await.clone();
        let state = ActiveState {
            daemon_pid: std::process::id(),
            connected,
            last_seen,
        };
        match postcard::to_allocvec(&state) {
            Ok(bytes) => {
                // fsync before rename (like the token store): without it a
                // crash could leave the mirror stale/torn behind the rename.
                let tmp = self.path.with_extension("dat.tmp");
                let write = || -> std::io::Result<()> {
                    use std::io::Write;
                    let mut f = std::fs::File::create(&tmp)?;
                    f.write_all(&bytes)?;
                    f.sync_all()?;
                    std::fs::rename(&tmp, &self.path)
                };
                if let Err(e) = write() {
                    tracing::warn!(error = %e, "active-state: persist failed");
                }
            }
            Err(e) => tracing::warn!(error = %e, "active-state: serialize failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn register_drop_revoked_and_deregister() {
        let dir = tempfile::tempdir().unwrap();
        let active = ActiveDevices::new(dir.path());
        let dev = DeviceId([7; 16]);
        let (control, _control_rx) = mpsc::channel(1);

        // A stand-in connection task we can watch for abort.
        let task = tokio::spawn(async { std::future::pending::<()>().await });
        let connection_id = active
            .register(dev, "phone".into(), task.abort_handle(), control)
            .await;

        // Mirror file shows it connected, under THIS pid.
        let state = ActiveState::load(dir.path());
        assert_eq!(state.daemon_pid, std::process::id());
        assert!(state.connected_since(&dev).is_some());

        // Revoke: dev is no longer a valid token → its task is aborted.
        let valid: HashMap<DeviceId, ()> = HashMap::new();
        assert_eq!(active.drop_revoked(&valid).await, 1);
        // The aborted task resolves (to a JoinError) - proves the abort landed.
        assert!(task.await.is_err());

        // After the connection task ends it would deregister; simulate that.
        assert!(active.deregister(&dev, connection_id).await);
        let state = ActiveState::load(dir.path());
        assert!(state.connected_since(&dev).is_none());
        assert!(state.last_seen(&dev).is_some(), "last-seen recorded");
    }

    #[tokio::test]
    async fn valid_token_is_not_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let active = ActiveDevices::new(dir.path());
        let dev = DeviceId([9; 16]);
        let (control, _control_rx) = mpsc::channel(1);
        let task = tokio::spawn(async { std::future::pending::<()>().await });
        let connection_id = active
            .register(dev, "phone".into(), task.abort_handle(), control)
            .await;
        // dev IS a valid token → not dropped.
        let valid: HashMap<DeviceId, ()> = [(dev, ())].into_iter().collect();
        assert_eq!(active.drop_revoked(&valid).await, 0);
        assert!(!task.is_finished());
        task.abort();
        active.deregister(&dev, connection_id).await;
    }

    #[tokio::test]
    async fn replacement_aborts_old_and_stale_cleanup_keeps_new() {
        let dir = tempfile::tempdir().unwrap();
        let active = ActiveDevices::new(dir.path());
        let dev = DeviceId([5; 16]);
        let old = tokio::spawn(async { std::future::pending::<()>().await });
        let new = tokio::spawn(async { std::future::pending::<()>().await });
        let (old_control, _old_control_rx) = mpsc::channel(1);
        let (new_control, _new_control_rx) = mpsc::channel(1);

        let old_id = active
            .register(dev, "old phone".into(), old.abort_handle(), old_control)
            .await;
        let new_id = active
            .register(dev, "new phone".into(), new.abort_handle(), new_control)
            .await;

        assert!(old.await.is_err(), "replacement must abort the old task");
        assert!(!active.deregister(&dev, old_id).await);
        assert!(ActiveState::load(dir.path())
            .connected_since(&dev)
            .is_some());
        assert!(!new.is_finished());

        new.abort();
        assert!(active.deregister(&dev, new_id).await);
    }
}
