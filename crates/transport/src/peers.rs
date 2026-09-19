//! Persisted per-peer reconnect credentials (SEC-2).
//!
//! After a first-pair PIN handshake, both sides derive a 32-byte resumption
//! token from the session and persist it keyed by the peer's `DeviceId`.
//! Reconnects then authenticate by the token instead of re-proving the human
//! PIN - so a PIN that leaks after pairing is no longer a permanent credential.
//!
//! The token is **rotated** on every successful handshake (each session derives
//! a fresh token both sides persist), which bounds the window if a token leaks.
//! If a reconnect's persist is one-sided (connection drops mid-rotation) the
//! next attempt simply fails and degrades to a re-pair - never a security hole.
//!
//! The token is secret material: never log it, store only in a per-user dir.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use rand::Rng;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::credential_store::{
    CredentialStore, Durability, FileCredentialStore, LAST_HOST_RECORD, PAIR_STATE_RECORD,
    PEERS_RECORD, REVOCATIONS_RECORD,
};
use crate::handshake::{PairEventKey, PairId, ResumptionToken};
use crate::identity::DeviceId;

/// Durable metadata for one active pairing generation. This lives beside the
/// legacy peer map so its postcard layout can remain unchanged.
#[derive(Clone, Serialize, Deserialize)]
pub struct PairState {
    pub pair_id: PairId,
    pub event_key: PairEventKey,
}

/// Complete, generation-aware result that may be committed after an
/// authenticated handshake. A named struct avoids security-sensitive boolean
/// and credential arguments being accidentally swapped at call sites.
pub struct HandshakeCommit {
    pub ticket: Option<String>,
    pub token: ResumptionToken,
    pub resumed: bool,
    pub candidate_pair_id: PairId,
    pub candidate_event_key: PairEventKey,
    pub observed_revocation: Option<[u8; 16]>,
    /// The stored token this handshake authenticated against, read before it
    /// began. Required on a resume, ignored on a fresh pair (which is authorized
    /// by the PIN, not by a token). See [`PeerStore::commit_handshake`].
    pub observed_token: Option<ResumptionToken>,
}

impl std::fmt::Debug for HandshakeCommit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeCommit")
            .field("ticket", &self.ticket.as_ref().map(|_| "<present>"))
            .field("token", &"<redacted>")
            .field("resumed", &self.resumed)
            .field("candidate_pair_id", &self.candidate_pair_id)
            .field("candidate_event_key", &"<redacted>")
            .field("observed_revocation", &self.observed_revocation)
            .field(
                "observed_token",
                &self.observed_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl std::fmt::Debug for PairState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairState")
            .field("pair_id", &self.pair_id)
            .field("event_key", &"<redacted>")
            .finish()
    }
}

/// Monotonic evidence that a particular peer generation was revoked. The
/// tombstone is the authorization source of truth: even if removal of the old
/// token file is interrupted, token lookup filters every tombstoned peer.
#[derive(Clone, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub event_id: [u8; 16],
    pub pair_id: Option<PairId>,
    pub event_key: Option<PairEventKey>,
    pub revoked_at_unix: u64,
}

impl std::fmt::Debug for RevocationRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationRecord")
            .field("event_id", &hex::encode(self.event_id))
            .field("pair_id", &self.pair_id)
            .field("event_key", &self.event_key.as_ref().map(|_| "<redacted>"))
            .field("revoked_at_unix", &self.revoked_at_unix)
            .finish()
    }
}

/// One peer's stored reconnect record.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PeerRecord {
    /// The host's `portty1:` ticket, so the phone can reconnect to the same
    /// host without re-pasting. `None` on the host side (the host never dials).
    #[serde(default)]
    pub ticket: Option<String>,
    /// SEC-2 reconnect token - the actual credential. Secret.
    pub token: ResumptionToken,
}

// Manual Debug that NEVER prints the reconnect token - it's a credential, and a
// derived Debug would leak it into any log/panic that formats a PeerStore.
impl std::fmt::Debug for PeerRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerRecord")
            .field("ticket", &self.ticket.as_ref().map(|_| "<present>"))
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Persisted `{ peer DeviceId -> PeerRecord }`, backed by a single postcard file
/// in a per-user dir. Cheap to load once at startup; mutations fsync immediately.
///
/// The most-recently-connected host is tracked in a separate tiny file so the
/// main peers format stays backward-compatible: `last_host` returns THAT host
/// (deterministic) instead of an arbitrary HashMap entry.
#[derive(Clone)]
pub struct PeerStore {
    map: HashMap<DeviceId, PeerRecord>,
    pair_state: HashMap<DeviceId, PairState>,
    revocations: HashMap<DeviceId, RevocationRecord>,
    last_connected: Option<DeviceId>,
    store: Arc<dyn CredentialStore>,
}

impl std::fmt::Debug for PeerStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerStore")
            .field("peer_count", &self.map.len())
            .field("pair_state_count", &self.pair_state.len())
            .field("revocation_count", &self.revocations.len())
            .field("last_connected", &self.last_connected)
            .field("store", &"<credential-store>")
            .finish()
    }
}

impl PeerStore {
    /// Load from `<dir>/portty-peers.dat`, or start empty if absent / corrupt.
    /// Existing credential files are permission-tightened and backup-excluded
    /// before their secret bytes are read; failure is fail-closed.
    pub fn load(dir: &Path) -> std::io::Result<Self> {
        Self::load_from(Arc::new(FileCredentialStore::new(dir)))
    }

    /// Load from an arbitrary credential store. Mobile clients use this with
    /// Android Keystore / iOS Keychain-backed implementations.
    pub fn load_from(store: Arc<dyn CredentialStore>) -> std::io::Result<Self> {
        // Read into an owned buffer, decode, then zeroize it - the raw bytes hold
        // reconnect tokens and must not linger in freed heap.
        let map = match store.read(PEERS_RECORD)? {
            Some(mut b) => {
                let parsed = postcard::from_bytes(&b).unwrap_or_default();
                b.zeroize();
                parsed
            }
            None => HashMap::new(),
        };
        let last_connected = store.read(LAST_HOST_RECORD)?.and_then(|mut b| {
            let parsed = postcard::from_bytes(&b).ok();
            b.zeroize();
            parsed
        });
        let pair_state = match store.read(PAIR_STATE_RECORD)? {
            Some(mut b) => {
                let parsed = postcard::from_bytes(&b).unwrap_or_default();
                b.zeroize();
                parsed
            }
            None => HashMap::new(),
        };
        // A corrupt revocation file must fail closed. Treating it as empty could
        // reactivate a token left in the legacy peer file after a crash between
        // the tombstone commit and best-effort token cleanup.
        let revocations = match store.read(REVOCATIONS_RECORD)? {
            Some(mut b) => {
                let parsed = postcard::from_bytes(&b).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("corrupt revocation store: {e}"),
                    )
                });
                b.zeroize();
                parsed?
            }
            None => HashMap::new(),
        };
        Ok(Self {
            map,
            pair_state,
            revocations,
            last_connected,
            store,
        })
    }

    /// The devices we hold a live (non-revoked) pairing for.
    ///
    /// Ids only, no credential material - for admission decisions that need to
    /// know "have we seen this device before" without touching its token.
    pub fn known_devices(&self) -> Vec<DeviceId> {
        self.map
            .keys()
            .filter(|d| !self.revocations.contains_key(d))
            .copied()
            .collect()
    }

    /// Snapshot of just the tokens (what the server injects into a handshake).
    pub fn tokens(&self) -> HashMap<DeviceId, ResumptionToken> {
        self.map
            .iter()
            .filter(|(d, _)| !self.revocations.contains_key(d))
            .map(|(d, r)| (*d, r.token.clone()))
            .collect()
    }

    pub fn token(&self, id: &DeviceId) -> Option<ResumptionToken> {
        if self.revocations.contains_key(id) {
            return None;
        }
        self.map.get(id).map(|r| r.token.clone())
    }

    pub fn pair_id(&self, id: &DeviceId) -> Option<PairId> {
        if self.revocations.contains_key(id) {
            return None;
        }
        self.pair_state.get(id).map(|s| s.pair_id)
    }

    pub fn revocation(&self, id: &DeviceId) -> Option<RevocationRecord> {
        self.revocations.get(id).cloned()
    }

    pub fn revocation_marker(&self, id: &DeviceId) -> Option<[u8; 16]> {
        self.revocations.get(id).map(|r| r.event_id)
    }

    pub fn is_revoked(&self, id: &DeviceId) -> bool {
        self.revocations.contains_key(id)
    }

    /// The phone's last-connected host: `(host_device_id, ticket, token)`, so a
    /// `reconnect` can dial the same host and resume without the PIN. Prefers the
    /// host recorded by [`set_last_host`]; falls back to any host with a ticket
    /// (older stores that predate recency tracking).
    pub fn last_host(&self) -> Option<(DeviceId, String, ResumptionToken)> {
        if let Some(dev) = self.last_connected {
            if !self.revocations.contains_key(&dev) {
                if let Some(r) = self.map.get(&dev) {
                    if let Some(ticket) = r.ticket.clone() {
                        return Some((dev, ticket, r.token.clone()));
                    }
                }
            }
        }
        self.map
            .iter()
            .filter(|(d, _)| !self.revocations.contains_key(d))
            .find_map(|(d, r)| r.ticket.clone().map(|t| (*d, t, r.token.clone())))
    }

    /// Every dialable saved host `(device, ticket, token)` - peers stored WITH
    /// a ticket (the phone stores one per laptop; hosts store none). This is
    /// the host picker's source. Last-connected sorts first, the rest by id so
    /// the list is stable across loads.
    pub fn known_hosts(&self) -> Vec<(DeviceId, String, ResumptionToken)> {
        let mut v: Vec<_> = self
            .map
            .iter()
            .filter(|(d, _)| !self.revocations.contains_key(d))
            .filter_map(|(d, r)| r.ticket.clone().map(|t| (*d, t, r.token.clone())))
            .collect();
        v.sort_by_key(|(d, _, _)| (Some(*d) != self.last_connected, d.0));
        v
    }

    /// Record which host the phone just connected to, so `last_host` is
    /// deterministic across multiple paired hosts. Called by the phone after a
    /// successful pair/reconnect. Persisted to its own file (0600, no backup).
    pub fn set_last_host(&mut self, peer: DeviceId) -> std::io::Result<()> {
        if self.last_connected == Some(peer) {
            return Ok(());
        }
        let bytes = postcard::to_allocvec(&peer)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        // Which host to redial by default - a convenience, and the previous value
        // is still a valid host. BestEffort.
        self.store
            .write(LAST_HOST_RECORD, &bytes, Durability::BestEffort)?;
        self.last_connected = Some(peer);
        Ok(())
    }

    /// Remember (or rotate) a peer's reconnect token. `ticket` is set by the
    /// phone (so it can redial); `None` on the host. Persists immediately and
    /// returns the persistence result - a caller pairing a device must treat a
    /// failure here as a failed pairing (the token wasn't durably stored).
    ///
    /// Durable: an explicit "remember this pairing" is not a rotation that a
    /// later write would repair.
    pub fn remember(
        &mut self,
        peer: DeviceId,
        ticket: Option<String>,
        token: impl Into<ResumptionToken>,
    ) -> std::io::Result<()> {
        if self.revocations.contains_key(&peer) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "refusing to restore a revoked peer",
            ));
        }
        self.remember_token(peer, ticket, token.into(), Durability::Required)
    }

    fn remember_token(
        &mut self,
        peer: DeviceId,
        ticket: Option<String>,
        token: ResumptionToken,
        durability: Durability,
    ) -> std::io::Result<()> {
        let previous = self.map.insert(
            peer,
            PeerRecord {
                ticket: ticket.or_else(|| self.map.get(&peer).and_then(|r| r.ticket.clone())),
                token,
            },
        );
        if let Err(e) = self.persist(durability) {
            let failed = self.map.remove(&peer);
            if let Some(previous) = previous {
                self.map.insert(peer, previous);
            }
            drop(failed); // zeroizes the rejected token immediately
            return Err(e);
        }
        Ok(())
    }

    /// Is the token we hold for `peer` still the one a handshake authenticated
    /// against? Constant-time, and treats "no record now" as a mismatch: a
    /// `forget` that landed mid-handshake must not be undone by the commit.
    fn token_is_unchanged(&self, peer: &DeviceId, observed: Option<&ResumptionToken>) -> bool {
        let (Some(current), Some(observed)) = (self.map.get(peer), observed) else {
            return false;
        };
        current.token.as_bytes().ct_eq(observed.as_bytes()).into()
    }

    /// Commit the result of an authenticated handshake under the pairing state
    /// observed before that handshake began.
    ///
    /// - A resume can rotate a token only while no tombstone exists AND the
    ///   token it authenticated against is still the one on record. Two
    ///   concurrent resumes both authenticate against the same token T0; without
    ///   that second condition the slower one overwrites the faster one's T1
    ///   with its own T2, silently invalidating the credential the peer was just
    ///   told to keep. The loser is refused here, before it acknowledges
    ///   anything, so the peer keeps exactly one working token.
    /// - A fresh/manual pair may replace an older tombstone, but only if the
    ///   marker is unchanged. A revoke racing the handshake therefore wins. Its
    ///   token write is durable, because it is followed by clearing a tombstone:
    ///   see the ordering note further down.
    /// - Legacy active records acquire generation metadata on their first
    ///   successful upgraded reconnect.
    pub fn commit_handshake(
        &mut self,
        peer: DeviceId,
        commit: HandshakeCommit,
    ) -> std::io::Result<PairId> {
        let HandshakeCommit {
            ticket,
            token,
            resumed,
            candidate_pair_id,
            candidate_event_key,
            observed_revocation,
            observed_token,
        } = commit;
        let current_revocation = self.revocation_marker(&peer);
        if resumed {
            if current_revocation.is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "peer was revoked while reconnecting",
                ));
            }
            if !self.token_is_unchanged(&peer, observed_token.as_ref()) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "peer credential changed while reconnecting",
                ));
            }
            if let Some(existing) = self.pair_state.get(&peer) {
                let pair_id = existing.pair_id;
                // A rotation, and only a rotation: if this write is lost to a
                // crash the peer's previous token is still valid and still on
                // record, so the next reconnect succeeds. BestEffort.
                self.remember_token(peer, ticket, token, Durability::BestEffort)?;
                return Ok(pair_id);
            }
            // Legacy peers have no generation metadata. Install it before the
            // rotated credential, so a failed metadata write can never make a
            // new credential usable. Both writes have in-memory rollback.
            let previous_state = self.pair_state.insert(
                peer,
                PairState {
                    pair_id: candidate_pair_id,
                    event_key: candidate_event_key,
                },
            );
            if let Err(e) = self.persist_pair_state() {
                self.restore_pair_state(peer, previous_state);
                return Err(e);
            }
            // Still a rotation (no tombstone is being cleared here - a resume
            // requires there be none), so the same BestEffort reasoning holds.
            if let Err(token_error) =
                self.remember_token(peer, ticket, token, Durability::BestEffort)
            {
                self.restore_pair_state(peer, previous_state);
                if let Err(rollback_error) = self.persist_pair_state() {
                    return Err(std::io::Error::new(
                        rollback_error.kind(),
                        format!(
                            "token persistence failed ({token_error}); pair metadata rollback also failed ({rollback_error})"
                        ),
                    ));
                }
                return Err(token_error);
            }
            return Ok(candidate_pair_id);
        }

        if current_revocation != observed_revocation {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "peer was revoked while pairing",
            ));
        }

        // Install generation metadata before the credential. When replacing a
        // revoked pair, the old tombstone continues to block both throughout.
        // For a first pair, failure before the token write leaves no credential
        // that could authorize the peer.
        //
        // Both writes below are Required, and that is load-bearing rather than
        // cautious. This path ends by clearing a tombstone, which is itself a
        // Required (write-through) write. A BestEffort token write followed by a
        // durable tombstone removal can be REORDERED by a crash: the removal
        // reaches the disk while the new token does not, leaving on-disk state
        // with no tombstone and the previous - revoked - token still in the file.
        // `PeerRecord` carries no generation, so nothing else would refuse it.
        // Ordering, not per-write durability, is the requirement here.
        let previous_state = self.pair_state.insert(
            peer,
            PairState {
                pair_id: candidate_pair_id,
                event_key: candidate_event_key,
            },
        );
        if let Err(e) = self.persist_pair_state() {
            self.restore_pair_state(peer, previous_state);
            return Err(e);
        }
        if let Err(token_error) = self.remember_token(peer, ticket, token, Durability::Required) {
            self.restore_pair_state(peer, previous_state);
            if let Err(rollback_error) = self.persist_pair_state() {
                return Err(std::io::Error::new(
                    rollback_error.kind(),
                    format!(
                        "token persistence failed ({token_error}); pair metadata rollback also failed ({rollback_error})"
                    ),
                ));
            }
            return Err(token_error);
        }

        // Clear the old tombstone LAST, so every earlier crash point fails
        // closed instead of exposing the newly-written token prematurely.
        if self.revocations.remove(&peer).is_some() {
            if let Err(e) = self.persist_revocations() {
                // Restore an in-memory tombstone by reloading the authoritative
                // record; do not leave this process more permissive than disk.
                if let Some(mut bytes) = self.store.read(REVOCATIONS_RECORD)? {
                    if let Ok(fresh) = postcard::from_bytes(&bytes) {
                        self.revocations = fresh;
                    }
                    bytes.zeroize();
                }
                return Err(e);
            }
        }
        Ok(candidate_pair_id)
    }

    fn restore_pair_state(&mut self, peer: DeviceId, previous: Option<PairState>) {
        if let Some(previous) = previous {
            self.pair_state.insert(peer, previous);
        } else {
            self.pair_state.remove(&peer);
        }
    }

    /// Durably revoke a peer. Tombstone persistence is the commit point. Token
    /// and active-metadata cleanup happens afterwards; failure there is logged
    /// but cannot reactivate the peer because every lookup filters tombstones.
    pub fn revoke(&mut self, peer: &DeviceId) -> std::io::Result<RevocationRecord> {
        let mut event_id = [0u8; 16];
        // An audit identifier, not a secret - infallible thread RNG is fine.
        rand::rng().fill_bytes(&mut event_id);
        let state = self.pair_state.get(peer).cloned();
        let existing = self.revocations.get(peer);
        let record = RevocationRecord {
            event_id,
            pair_id: state
                .as_ref()
                .map(|s| s.pair_id)
                .or_else(|| existing.and_then(|record| record.pair_id)),
            event_key: state
                .map(|s| s.event_key)
                .or_else(|| existing.and_then(|record| record.event_key.clone())),
            revoked_at_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        self.revocations.insert(*peer, record.clone());
        if let Err(e) = self.persist_revocations() {
            self.revocations.remove(peer);
            return Err(e);
        }

        // Required, the mirror image of the fresh-pair ordering: the tombstone
        // that authorizes this removal is already durable. A BestEffort removal
        // could be reordered by a crash into "tombstone present, token absent"
        // (harmless) or - once a later repair durably clears that tombstone -
        // "no tombstone, revoked token still on disk". Making the removal itself
        // durable removes the second case at its source.
        let removed = self.map.remove(peer);
        let removed_state = self.pair_state.remove(peer);
        if let Err(e) = self.persist(Durability::Required) {
            tracing::warn!(peer = %peer, error = %e, "revocation committed; stale token cleanup will be retried on a later write");
        }
        if let Err(e) = self.persist_pair_state() {
            tracing::warn!(peer = %peer, error = %e, "revocation committed; stale pair-metadata cleanup will be retried on a later write");
        }
        drop(removed);
        drop(removed_state);
        if self.last_connected == Some(*peer) {
            let _ = self.store.remove(LAST_HOST_RECORD);
            self.last_connected = None;
        }
        Ok(record)
    }

    /// Drop a peer (e.g. after an explicit disconnect). Persists immediately.
    pub fn forget(&mut self, peer: &DeviceId) -> std::io::Result<()> {
        let Some(removed) = self.map.remove(peer) else {
            return Ok(());
        };
        let removed_state = self.pair_state.remove(peer);
        // Removing a credential is Required: a lost removal leaves a token the
        // user believes is gone.
        if let Err(e) = self.persist(Durability::Required) {
            self.map.insert(*peer, removed);
            if let Some(state) = removed_state {
                self.pair_state.insert(*peer, state);
            }
            return Err(e);
        }
        // Token is already gone, which is the secure direction. Report any
        // cleanup error without restoring a usable credential.
        self.persist_pair_state()?;
        drop(removed);
        if self.last_connected == Some(*peer) {
            self.store.remove(LAST_HOST_RECORD)?;
            self.last_connected = None;
        }
        Ok(())
    }

    /// Snapshot of every stored record - `(DeviceId, PeerRecord)`. Used by the
    /// `portty-host peers` listing and the revoke target resolver.
    pub fn records(&self) -> Vec<(DeviceId, PeerRecord)> {
        self.map
            .iter()
            .filter(|(d, _)| !self.revocations.contains_key(d))
            .map(|(d, r)| (*d, r.clone()))
            .collect()
    }

    /// Remove every paired device (e.g. `portty-host revoke all`). Persists.
    pub fn clear(&mut self) -> std::io::Result<()> {
        if self.map.is_empty() {
            return Ok(());
        }
        let old = std::mem::take(&mut self.map);
        let old_state = std::mem::take(&mut self.pair_state);
        // `revoke all`: same reasoning as `forget`, for every peer at once.
        if let Err(e) = self.persist(Durability::Required) {
            self.map = old;
            self.pair_state = old_state;
            return Err(e);
        }
        self.persist_pair_state()?;
        drop(old);
        drop(old_state);
        if self.last_connected.is_some() {
            self.store.remove(LAST_HOST_RECORD)?;
            self.last_connected = None;
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.records().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Persist the store. Returns an error instead of silently succeeding, so a
    /// pairing that cannot be saved is reported as a failure (a "paired" device
    /// whose reconnect token was never written would fail to reconnect).
    ///
    /// The temp file is *created* at 0600 (Unix) - never briefly world-readable -
    /// and installed only if that succeeds (fail-closed: a perms failure aborts
    /// the write instead of leaving a readable secret). The serialized buffer
    /// (which contains the tokens) is zeroized after the write.
    /// Persist the token map at the durability the caller's situation demands.
    ///
    /// There is no single right answer for this record, which is why the choice
    /// belongs to the caller. A reconnect ROTATION is BestEffort: losing it
    /// leaves the peer's previous token on disk, still valid, so the next
    /// reconnect works. But any write that another durable write depends on -
    /// installing a credential before clearing a tombstone, or removing one
    /// after adding a tombstone - is Required, because a crash can otherwise
    /// reorder the pair into a state that is more permissive than either step
    /// intended. See `commit_handshake` and `revoke`.
    fn persist(&self, durability: Durability) -> std::io::Result<()> {
        let mut bytes = postcard::to_allocvec(&self.map)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let write_res = self.store.write(PEERS_RECORD, &bytes, durability);
        bytes.zeroize();
        write_res
    }

    fn persist_pair_state(&self) -> std::io::Result<()> {
        let mut bytes = postcard::to_allocvec(&self.pair_state)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        // Pair generations bind revocation to a specific relationship, so losing
        // this can un-revoke. Required.
        let result = self
            .store
            .write(PAIR_STATE_RECORD, &bytes, Durability::Required);
        bytes.zeroize();
        result
    }

    fn persist_revocations(&self) -> std::io::Result<()> {
        let mut bytes = postcard::to_allocvec(&self.revocations)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        // Revocation tombstones ARE the revocation. Losing one after a crash
        // resurrects a pairing the user explicitly ended. Required.
        let result = self
            .store
            .write(REVOCATIONS_RECORD, &bytes, Durability::Required);
        bytes.zeroize();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commit_fresh(store: &mut PeerStore, device: DeviceId, byte: u8) -> PairId {
        let pair_id = PairId([byte; 16]);
        store
            .commit_handshake(
                device,
                HandshakeCommit {
                    ticket: Some(format!("portty1:{byte}")),
                    token: ResumptionToken::from([byte; 32]),
                    resumed: false,
                    candidate_pair_id: pair_id,
                    candidate_event_key: PairEventKey::from([byte.wrapping_add(1); 32]),
                    observed_revocation: store.revocation_marker(&device),
                    observed_token: None,
                },
            )
            .unwrap();
        pair_id
    }

    #[test]
    fn remember_then_load_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = PeerStore::load(dir.path()).unwrap();
        assert!(store.is_empty());

        // Phone side: remember a host with a ticket + token.
        store
            .remember(DeviceId([1; 16]), Some("portty1:abc".into()), [0x11; 32])
            .unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(
            store.token(&DeviceId([1; 16])).unwrap().as_bytes(),
            &[0x11; 32]
        );

        // Reload from disk - the record survives.
        let reloaded = PeerStore::load(dir.path()).unwrap();
        assert_eq!(
            reloaded.token(&DeviceId([1; 16])).unwrap().as_bytes(),
            &[0x11; 32]
        );
        let (host, ticket, token) = reloaded.last_host().unwrap();
        assert_eq!(host, DeviceId([1; 16]));
        assert_eq!(ticket, "portty1:abc");
        assert_eq!(token, [0x11; 32]);
    }

    #[test]
    fn rotation_preserves_a_phone_ticket() {
        // A reconnect rotates the token but must NOT clobber the stored ticket
        // (the phone still needs to redial the same host).
        let dir = tempfile::tempdir().unwrap();
        let mut store = PeerStore::load(dir.path()).unwrap();
        store
            .remember(DeviceId([2; 16]), Some("portty1:host".into()), [1; 32])
            .unwrap();
        // Reconnect: new token, no ticket passed (phone already has it).
        store.remember(DeviceId([2; 16]), None, [2; 32]).unwrap();
        let (_h, ticket, token) = store.last_host().unwrap();
        assert_eq!(ticket, "portty1:host");
        assert_eq!(token, [2; 32]);
    }

    #[test]
    fn tokens_snapshot_feeds_the_handshake() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = PeerStore::load(dir.path()).unwrap();
        store.remember(DeviceId([1; 16]), None, [9; 32]).unwrap();
        store.remember(DeviceId([2; 16]), None, [8; 32]).unwrap();
        let snap = store.tokens();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap.get(&DeviceId([1; 16])).unwrap().as_bytes(), &[9; 32]);
    }

    #[test]
    fn last_host_prefers_most_recently_connected() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = PeerStore::load(dir.path()).unwrap();
        // Two paired hosts, each with a ticket.
        store
            .remember(DeviceId([1; 16]), Some("portty1:host-a".into()), [1; 32])
            .unwrap();
        store
            .remember(DeviceId([2; 16]), Some("portty1:host-b".into()), [2; 32])
            .unwrap();
        // Phone last connected to host B.
        store.set_last_host(DeviceId([2; 16])).unwrap();

        // Fresh load (simulate app restart) must deterministically pick host B.
        let reloaded = PeerStore::load(dir.path()).unwrap();
        let (dev, ticket, _tok) = reloaded.last_host().unwrap();
        assert_eq!(dev, DeviceId([2; 16]));
        assert_eq!(ticket, "portty1:host-b");

        // Forgetting the last host clears the pointer; last_host falls back.
        let mut store = PeerStore::load(dir.path()).unwrap();
        store.forget(&DeviceId([2; 16])).unwrap();
        let reloaded = PeerStore::load(dir.path()).unwrap();
        let (dev, _t, _k) = reloaded.last_host().unwrap();
        assert_eq!(
            dev,
            DeviceId([1; 16]),
            "should fall back to the remaining host"
        );
    }

    #[cfg(unix)]
    #[test]
    fn persisted_store_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let mut store = PeerStore::load(dir.path()).unwrap();
        store.remember(DeviceId([3; 16]), None, [7; 32]).unwrap();
        let mode = std::fs::metadata(dir.path().join("portty-peers.dat"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "reconnect tokens must be owner-only");
    }

    #[cfg(unix)]
    #[test]
    fn failed_rotation_rolls_back_in_memory_token() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = PeerStore::load(dir.path()).unwrap();
        let device = DeviceId([4; 16]);
        store.remember(device, None, [1; 32]).unwrap();

        // Make the atomic rename target a directory so persistence fails after
        // the proposed token has been staged in memory.
        let path = dir.path().join(PEERS_RECORD);
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(store.remember(device, None, [2; 32]).is_err());
        assert_eq!(store.token(&device).unwrap().as_bytes(), &[1; 32]);
    }

    #[test]
    fn corrupt_file_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("portty-peers.dat"), b"not postcard").unwrap();
        let store = PeerStore::load(dir.path()).unwrap();
        assert!(
            store.is_empty(),
            "a corrupt store must degrade to empty, not panic"
        );
    }

    #[test]
    fn durable_tombstone_filters_stale_token_and_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let device = DeviceId([0x51; 16]);
        let mut store = PeerStore::load(dir.path()).unwrap();
        let pair_id = commit_fresh(&mut store, device, 0x31);
        let revoked = store.revoke(&device).unwrap();
        assert_eq!(revoked.pair_id, Some(pair_id));
        assert!(store.is_revoked(&device));
        assert!(store.token(&device).is_none());
        assert!(store.pair_id(&device).is_none());

        let reloaded = PeerStore::load(dir.path()).unwrap();
        assert!(reloaded.is_revoked(&device));
        assert!(!reloaded.tokens().contains_key(&device));
        assert_eq!(reloaded.revocation(&device).unwrap().pair_id, Some(pair_id));
    }

    #[test]
    fn revoke_racing_a_fresh_handshake_wins_commit() {
        let dir = tempfile::tempdir().unwrap();
        let device = DeviceId([0x52; 16]);
        let mut store = PeerStore::load(dir.path()).unwrap();
        commit_fresh(&mut store, device, 0x41);
        let observed = store.revocation_marker(&device);
        store.revoke(&device).unwrap();
        let err = store
            .commit_handshake(
                device,
                HandshakeCommit {
                    ticket: None,
                    token: ResumptionToken::from([0x77; 32]),
                    resumed: false,
                    candidate_pair_id: PairId([0x77; 16]),
                    candidate_event_key: PairEventKey::from([0x78; 32]),
                    observed_revocation: observed,
                    observed_token: None,
                },
            )
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(store.is_revoked(&device));
        assert!(store.token(&device).is_none());
    }

    #[test]
    fn resumed_handshake_can_never_clear_a_tombstone() {
        let dir = tempfile::tempdir().unwrap();
        let device = DeviceId([0x53; 16]);
        let mut store = PeerStore::load(dir.path()).unwrap();
        commit_fresh(&mut store, device, 0x42);
        store.revoke(&device).unwrap();
        let err = store
            .commit_handshake(
                device,
                HandshakeCommit {
                    ticket: None,
                    token: ResumptionToken::from([0x79; 32]),
                    resumed: true,
                    candidate_pair_id: PairId([0x79; 16]),
                    candidate_event_key: PairEventKey::from([0x7a; 32]),
                    observed_revocation: store.revocation_marker(&device),
                    // The token this resume really did authenticate against, so
                    // the tombstone rule is what fails it - not a missing CAS.
                    observed_token: Some(ResumptionToken::from([0x42; 32])),
                },
            )
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(store.is_revoked(&device));
    }

    #[test]
    fn explicit_fresh_pair_replaces_only_the_observed_tombstone() {
        let dir = tempfile::tempdir().unwrap();
        let device = DeviceId([0x54; 16]);
        let mut store = PeerStore::load(dir.path()).unwrap();
        let old_pair = commit_fresh(&mut store, device, 0x43);
        store.revoke(&device).unwrap();
        let marker = store.revocation_marker(&device);
        let new_pair = PairId([0x55; 16]);
        let committed = store
            .commit_handshake(
                device,
                HandshakeCommit {
                    ticket: Some("portty1:new".into()),
                    token: ResumptionToken::from([0x55; 32]),
                    resumed: false,
                    candidate_pair_id: new_pair,
                    candidate_event_key: PairEventKey::from([0x56; 32]),
                    observed_revocation: marker,
                    observed_token: None,
                },
            )
            .unwrap();
        assert_eq!(committed, new_pair);
        assert_ne!(committed, old_pair);
        assert!(!store.is_revoked(&device));
        assert_eq!(store.pair_id(&device), Some(new_pair));
    }

    #[test]
    fn repeated_revoke_invalidates_an_inflight_manual_repair() {
        let dir = tempfile::tempdir().unwrap();
        let device = DeviceId([0x58; 16]);
        let mut store = PeerStore::load(dir.path()).unwrap();
        commit_fresh(&mut store, device, 0x58);
        store.revoke(&device).unwrap();
        let observed = store.revocation_marker(&device);
        let refreshed = store.revoke(&device).unwrap();
        assert_ne!(Some(refreshed.event_id), observed);

        let error = store
            .commit_handshake(
                device,
                HandshakeCommit {
                    ticket: None,
                    token: ResumptionToken::from([0x59; 32]),
                    resumed: false,
                    candidate_pair_id: PairId([0x59; 16]),
                    candidate_event_key: PairEventKey::from([0x5a; 32]),
                    observed_revocation: observed,
                    observed_token: None,
                },
            )
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(store.is_revoked(&device));
    }

    /// A resume of `device`, claiming to have authenticated against `observed`
    /// and rotating to `next`.
    fn commit_resume(
        store: &mut PeerStore,
        device: DeviceId,
        observed: Option<[u8; 32]>,
        next: u8,
    ) -> std::io::Result<PairId> {
        store.commit_handshake(
            device,
            HandshakeCommit {
                ticket: None,
                token: ResumptionToken::from([next; 32]),
                resumed: true,
                candidate_pair_id: PairId([next; 16]),
                candidate_event_key: PairEventKey::from([next.wrapping_add(1); 32]),
                observed_revocation: store.revocation_marker(&device),
                observed_token: observed.map(ResumptionToken::from),
            },
        )
    }

    #[test]
    fn a_resume_rotates_the_token_it_authenticated_against() {
        let dir = tempfile::tempdir().unwrap();
        let device = DeviceId([0x71; 16]);
        let mut store = PeerStore::load(dir.path()).unwrap();
        let pair_id = commit_fresh(&mut store, device, 0x21);

        // 0x21 is the token `commit_fresh` installed, so this is the ordinary
        // reconnect: the CAS matches and the rotation lands.
        assert_eq!(
            commit_resume(&mut store, device, Some([0x21; 32]), 0x22).unwrap(),
            pair_id
        );
        assert_eq!(store.token(&device).unwrap().as_bytes(), &[0x22; 32]);
    }

    #[test]
    fn the_slower_of_two_concurrent_resumes_cannot_overwrite_the_faster() {
        let dir = tempfile::tempdir().unwrap();
        let device = DeviceId([0x72; 16]);
        let mut store = PeerStore::load(dir.path()).unwrap();
        commit_fresh(&mut store, device, 0x23);

        // Two reconnects overlap, so BOTH authenticated against 0x23 - that is
        // what concurrency means here, not a forged claim.
        let first = commit_resume(&mut store, device, Some([0x23; 32]), 0x24);
        let second = commit_resume(&mut store, device, Some([0x23; 32]), 0x25);

        assert!(first.is_ok());
        let error = second.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        // The winner's rotation stands. Before the CAS the loser's 0x25 landed
        // here instead, invalidating the token the peer had just been given.
        assert_eq!(store.token(&device).unwrap().as_bytes(), &[0x24; 32]);
    }

    #[test]
    fn a_resume_cannot_commit_without_naming_the_token_it_used() {
        let dir = tempfile::tempdir().unwrap();
        let device = DeviceId([0x73; 16]);
        let mut store = PeerStore::load(dir.path()).unwrap();
        commit_fresh(&mut store, device, 0x26);

        // No observed token is not "skip the check" - a resume authenticates by
        // token, so having none to name is a caller bug and fails closed.
        let error = commit_resume(&mut store, device, None, 0x27).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(store.token(&device).unwrap().as_bytes(), &[0x26; 32]);
    }

    #[test]
    fn a_forget_that_lands_mid_resume_is_not_undone_by_the_commit() {
        let dir = tempfile::tempdir().unwrap();
        let device = DeviceId([0x74; 16]);
        let mut store = PeerStore::load(dir.path()).unwrap();
        commit_fresh(&mut store, device, 0x28);
        // `forget` leaves no tombstone, so the revocation check cannot catch
        // this; only "the token we observed is still on record" can.
        store.forget(&device).unwrap();

        let error = commit_resume(&mut store, device, Some([0x28; 32]), 0x29).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(store.token(&device).is_none());
    }

    #[test]
    fn a_fresh_pair_still_replaces_a_token_a_concurrent_resume_rotated() {
        let dir = tempfile::tempdir().unwrap();
        let device = DeviceId([0x75; 16]);
        let mut store = PeerStore::load(dir.path()).unwrap();
        commit_fresh(&mut store, device, 0x2a);
        commit_resume(&mut store, device, Some([0x2a; 32]), 0x2b).unwrap();

        // The CAS is deliberately NOT applied to a fresh pair: `portty pair` is
        // authorized by the human PIN, and the device that just paired holds the
        // token this installs. Making it lose to a background rotation would
        // break the recovery path.
        let repaired = commit_fresh(&mut store, device, 0x2c);
        assert_eq!(store.pair_id(&device), Some(repaired));
        assert_eq!(store.token(&device).unwrap().as_bytes(), &[0x2c; 32]);
    }

    #[test]
    fn corrupt_revocation_record_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(REVOCATIONS_RECORD), b"not postcard").unwrap();
        let err = PeerStore::load(dir.path()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn failed_pair_metadata_write_never_installs_a_token() {
        let dir = tempfile::tempdir().unwrap();
        let device = DeviceId([0x61; 16]);
        let mut store = PeerStore::load(dir.path()).unwrap();
        let pair_state_path = dir.path().join(PAIR_STATE_RECORD);
        std::fs::create_dir(&pair_state_path).unwrap();

        let result = store.commit_handshake(
            device,
            HandshakeCommit {
                ticket: None,
                token: ResumptionToken::from([0x61; 32]),
                resumed: false,
                candidate_pair_id: PairId([0x61; 16]),
                candidate_event_key: PairEventKey::from([0x62; 32]),
                observed_revocation: None,
                observed_token: None,
            },
        );
        assert!(result.is_err());
        assert!(store.token(&device).is_none());
        assert!(store.pair_id(&device).is_none());
        assert!(!dir.path().join(PEERS_RECORD).exists());
    }

    #[test]
    fn failed_pair_token_write_rolls_back_generation_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let device = DeviceId([0x63; 16]);
        let mut store = PeerStore::load(dir.path()).unwrap();
        let peers_path = dir.path().join(PEERS_RECORD);
        std::fs::create_dir(&peers_path).unwrap();

        let result = store.commit_handshake(
            device,
            HandshakeCommit {
                ticket: None,
                token: ResumptionToken::from([0x63; 32]),
                resumed: false,
                candidate_pair_id: PairId([0x63; 16]),
                candidate_event_key: PairEventKey::from([0x64; 32]),
                observed_revocation: None,
                observed_token: None,
            },
        );
        assert!(result.is_err());
        assert!(store.token(&device).is_none());
        assert!(store.pair_id(&device).is_none());

        // The attempted write hardened the credential DIRECTORY to owner-only.
        // On Windows that means a PROTECTED, non-inheritable DACL, and Windows
        // propagates that downward: this blocker directory carried nothing but
        // INHERITED ACEs, so it is left with an EMPTY DACL and not even its
        // owner can delete it - `remove_dir` fails with ERROR_ACCESS_DENIED.
        // Unix has no equivalent (a 0700 parent says nothing about a child's
        // mode), which is why this only ever failed here. Give the blocker an
        // ACE of its own back before removing it; on Unix the same call is just
        // a 0700 chmod of a directory we already own.
        crate::secure::prepare_secret_dir(&peers_path).unwrap();
        std::fs::remove_dir(&peers_path).unwrap();
        let reloaded = PeerStore::load(dir.path()).unwrap();
        assert!(reloaded.token(&device).is_none());
        assert!(reloaded.pair_id(&device).is_none());
    }
}
