//! Length-prefixed framing with an explicit protocol version. (Forked from Corvux
//! `sync/transport/frame.rs`; byte-for-byte identical logic.)
//!
//! Wire format per frame:
//!
//! ```text
//!   offset  size  field
//!   0       4     payload_length (u32, big-endian; does NOT include these 4 bytes)
//!   4       2     protocol_version (u16, big-endian)
//!   6       N     postcard-encoded message
//! ```
//!
//! `payload_length` covers `protocol_version + postcard bytes` so the reader can
//! `read_exact(payload_length)` in one call after the header.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::TransportError;

/// Wire-protocol version. Portty intentionally supports exactly one phone/host
/// wire generation at a time: there is no downgrade or capability negotiation.
/// Every frame and the authenticated handshake are rejected unless the version
/// is inside [`MIN_SUPPORTED_PROTOCOL_VERSION`]..=[`PROTOCOL_VERSION`]. Frame
/// tags remain append-only, and every schema or semantic wire change bumps this
/// value so mixed builds fail closed before exchanging application data.
///
/// v5 (2026-07-23): appended `AgentPermissionResolvedInfo` (index 39) so a
/// dismissed approval card can name the outcome (allowed / rejected / cancelled)
/// and which viewer answered, instead of vanishing silently. Also added a
/// per-host-lifetime `generation` to `ScreenReset` + `OutputResume` so a warm
/// resume after a host restart repaints instead of replaying a corrupting delta
/// (#14). Rebuild host + phone together.
///
/// v4 (2026-07-21): file-transfer checksums changed from SHA-256 to BLAKE3.
/// Rebuild host + phone together; v3 is rejected explicitly.
///
/// v3 (2026-07-20): direction-separated envelope keys plus authenticated,
/// replay-checked sequence numbers. Rebuild host + phone together.
///
/// v2 (2026-07-10): added `source: SessionSource` to `SessionInfo`. A new field
/// on a struct reorders postcard encoding, so an old peer can't decode it - the
/// handshake now rejects v1 peers. Rebuild host + phone together.
///
/// v6 (2026-08-01): the phone can choose which directory an agent starts in -
/// `RequestKind::ListWorkspaceDirs` / `NewAgentSessionIn` and `Frame::
/// WorkspaceDirs`. All three are pure appends, so this bump is only needed
/// because MIN == latest (below); no existing variant moved. Rebuild host +
/// phone together.
///
/// v7 (2026-08-01): the phone can list and resume a SPECIFIC cached
/// conversation - `RequestKind::ListAgentSessions` / `ResumeAgentSession` and
/// `Frame::AgentSessions`. Pure appends again; the bump is for MIN == latest.
/// Rebuild host + phone together.
///
/// v8 (2026-08-02): SECURITY - the 6-digit PIN is removed from pairing. The
/// first-pair key is now derived from the out-of-band ticket/phrase secret ALONE
/// (`pairing::first_pair_key`), and the human step moves after the exchange as a
/// comparison code the operator confirms at the host.
///
/// This fixes an offline dictionary attack. `HMAC(secret, PIN)` gave an attacker
/// who already held the ticket exactly 20 bits to search, so one captured proof -
/// obtainable by substituting a NodeId into a ticket in transit and letting the
/// victim dial it - yielded the PIN in under a second and then paired with the
/// real host inside its enrollment window.
///
/// No `HandshakeMessage` variant changed shape, but the key derivation did, so
/// every peer must upgrade together: a v7 phone against a v8 host derives a
/// different first-pair key and fails the proof. The manual phrase also grew from
/// four words (32 bits) to six (48 bits), and 32-bit secrets plus the `portty2:`
/// compact code no longer decode. Rebuild host + phone together.
///
/// v9 (2026-08-05): the phone can choose which directory a TERMINAL opens in -
/// `RequestKind::NewSessionIn`, reusing the v6 `ListWorkspaceDirs` listing rather
/// than growing a second directory browser. A pure append, so this bump is only
/// needed because MIN == latest (below). Rebuild host + phone together.
///
/// Shipping beside it, and the reason the picker was asked for: phone-spawned
/// shells never applied `iroh_serve::workspace_dir()` at all, so they opened in
/// HOME (`%USERPROFILE%` on Windows) instead of `PORTTY_WORKSPACE` / the launch
/// dir, while the agent spawn and the local browser proof both got it right. That
/// half is a host behaviour fix, not a wire change - an old phone against a new
/// host lands in the right directory with no new frames involved.
///
/// v10 (2026-08-05): the phone can open a terminal in the user's HOME as well as
/// the workspace - `TerminalRoot`, `RequestKind::ListTerminalRoots` /
/// `ListDirsIn` / `NewSessionInRoot`, and `Frame::TerminalRoots`. Pure appends;
/// the bump is for MIN == latest.
///
/// The point is that the workspace root could only be widened on the LAPTOP
/// (`PORTTY_WORKSPACE`), which is no good for a product whose premise is reaching
/// a machine from your phone. Roots are still host-DECLARED and every `rel` is
/// still resolved and containment-checked inside one, so the wire carries no
/// absolute paths. Terminal-only by construction: `NewAgentSessionIn` stays
/// workspace-relative, because for an agent that directory is also its ACP
/// file-access sandbox root. Rebuild host + phone together.
///
/// v11 (2026-08-06): the phone can continue a conversation it never started -
/// `RequestKind::ListAgentSessionsFor`, which merges Portty's own resume cache
/// with what the agent itself remembers (ACP `session/list`) for one provider and
/// one directory. A pure append answered by the existing `Frame::AgentSessions`;
/// the bump is for MIN == latest.
///
/// The gap it closes: `ListAgentSessions` could only ever offer conversations
/// Portty spawned, so a chat started with `claude` in the laptop terminal was
/// invisible from the phone even though the adapter could resume it all along.
/// The request is provider-scoped because answering it launches that provider's
/// adapter - the phone already knows which agent's picker it is in, and making
/// the host probe all four per folder tap would be four processes for three
/// answers nobody asked for. Rebuild host + phone together.
pub const PROTOCOL_VERSION: u16 = 11;

/// Oldest generation this build can safely decode. It currently equals the
/// latest generation because postcard has no unknown-field negotiation and v4
/// changed the meaning of the file checksum bytes.
///
/// FLAG-DAY: because MIN == latest and peers do not negotiate, every bump is a
/// simultaneous-upgrade event - an un-upgraded phone/host pair cannot connect
/// and gets `PairingFailure::UnsupportedVersion`. The app maps that to a
/// first-class "update the older side" message (app/src-tauri
/// `version_mismatch_message`); call the flag-day out in the release notes
/// whenever you bump this.
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u16 = PROTOCOL_VERSION;

pub const fn supports_protocol_version(version: u16) -> bool {
    version >= MIN_SUPPORTED_PROTOCOL_VERSION && version <= PROTOCOL_VERSION
}

pub fn validate_protocol_version(version: u16) -> Result<(), TransportError> {
    if supports_protocol_version(version) {
        Ok(())
    } else {
        Err(TransportError::UnsupportedProtocolVersion {
            expected: PROTOCOL_VERSION,
            found: version,
        })
    }
}

/// 1 MiB - hard cap on a single frame. Deliberately small: with count-bounded
/// queues, worst-case in-flight memory is `queue_depth × MAX_FRAME_BYTES`, so a
/// large cap (this was 16 MiB) let a modest queue balloon into gigabytes. Every
/// frame we actually send fits well under this: live output is a single PTY read
/// (a few KiB), a scrollback snapshot is bounded by the scrollback cap (≤512 KiB,
/// see `scrollback_cap_from_env`), and a `SessionList` is bounded by the session
/// count × the title cap.
pub const MAX_FRAME_BYTES: u32 = 1024 * 1024;

/// Max time to finish reading a frame's body once its length header has arrived.
/// Generous - even a full 1 MiB frame over a poor link completes well inside
/// this; exceeding it means the peer announced a length then stalled mid-frame,
/// so the connection is effectively dead. The idle wait for the NEXT frame is
/// deliberately NOT bounded, so a healthy but quiet link is never killed (#38).
const FRAME_BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Write one frame to the stream. `payload` must already be postcard-encoded.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    mut w: W,
    version: u16,
    payload: &[u8],
) -> Result<(), TransportError> {
    let total = 2u64 + payload.len() as u64;
    if total > MAX_FRAME_BYTES as u64 {
        return Err(TransportError::FrameTooLarge(total as u32));
    }
    w.write_u32(total as u32).await?;
    w.write_u16(version).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

/// Read one frame from the stream. Returns `(version, payload_bytes)`.
/// Guarantees payload.len() <= MAX_FRAME_BYTES - 2.
pub async fn read_frame<R: AsyncRead + Unpin>(mut r: R) -> Result<(u16, Vec<u8>), TransportError> {
    let len = r.read_u32().await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            TransportError::Closed
        } else {
            TransportError::Io(e)
        }
    })?;
    if len < 2 {
        return Err(TransportError::MalformedFrame);
    }
    if len > MAX_FRAME_BYTES {
        return Err(TransportError::FrameTooLarge(len));
    }
    // The length is known; the body must now arrive promptly (see FRAME_BODY_TIMEOUT).
    tokio::time::timeout(FRAME_BODY_TIMEOUT, async {
        let version = r.read_u16().await?;
        let payload_len = (len - 2) as usize;
        let mut buf = vec![0u8; payload_len];
        r.read_exact(&mut buf).await?;
        Ok::<(u16, Vec<u8>), std::io::Error>((version, buf))
    })
    .await
    .map_err(|_| {
        TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "frame body read timed out",
        ))
    })?
    .map_err(TransportError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn roundtrip_small_frame() {
        let (a, b) = duplex(1024);
        let (mut a_r, a_w) = tokio::io::split(a);
        let (_b_r, mut b_w) = tokio::io::split(b);

        tokio::spawn(async move {
            write_frame(&mut b_w, PROTOCOL_VERSION, b"hello")
                .await
                .unwrap();
        });

        let (ver, payload) = read_frame(&mut a_r).await.unwrap();
        assert_eq!(ver, PROTOCOL_VERSION);
        assert_eq!(payload, b"hello");
        drop(a_w);
    }

    #[tokio::test]
    async fn read_rejects_oversize_header() {
        let (a, b) = duplex(64);
        let (mut a_r, _a_w) = tokio::io::split(a);
        let (_b_r, mut b_w) = tokio::io::split(b);

        tokio::spawn(async move {
            b_w.write_u32(MAX_FRAME_BYTES + 1).await.unwrap();
            b_w.write_u16(PROTOCOL_VERSION).await.unwrap();
        });

        let err = read_frame(&mut a_r).await.unwrap_err();
        assert!(matches!(err, TransportError::FrameTooLarge(_)));
    }

    #[tokio::test]
    async fn read_detects_clean_close() {
        let (a, b) = duplex(64);
        let (mut a_r, _a_w) = tokio::io::split(a);
        drop(b);

        let err = read_frame(&mut a_r).await.unwrap_err();
        assert!(matches!(err, TransportError::Closed));
    }

    #[test]
    fn compatibility_window_is_explicit_and_fail_closed() {
        assert_eq!(MIN_SUPPORTED_PROTOCOL_VERSION, PROTOCOL_VERSION);
        assert!(supports_protocol_version(PROTOCOL_VERSION));
        assert!(!supports_protocol_version(PROTOCOL_VERSION - 1));
        assert!(!supports_protocol_version(PROTOCOL_VERSION + 1));
        assert!(matches!(
            validate_protocol_version(PROTOCOL_VERSION - 1),
            Err(TransportError::UnsupportedProtocolVersion {
                expected: PROTOCOL_VERSION,
                found
            }) if found == PROTOCOL_VERSION - 1
        ));
    }
}
