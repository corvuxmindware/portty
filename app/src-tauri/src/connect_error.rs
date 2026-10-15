//! Plain words for a failed pair or reconnect.
//!
//! `pair` and `reconnect` used to hand the UI `e.to_string()` of a transport
//! error: "transport: io: connection lost", "protocol: pairing failed:
//! WrongPin" (naming a PIN that no longer exists), and "reconnect failed -
//! re-pair: ..." for every failure, including the ones re-pairing cannot fix.
//! This module turns each failure a person can actually hit into one or two
//! short sentences that say what to do next. It branches on the typed error
//! and on how far the handshake got, and keeps the technical text beside it
//! (`detail`) for support.
//!
//! Commands named in a message are wrapped in backticks; the UI shows them as
//! code. Nothing here may carry a ticket, pairing code, key, token or path:
//! `detail` is built only from error `Display` text, which carries none.

use std::future::Future;
use std::io::ErrorKind;
use std::pin::Pin;

use iroh::endpoint::{ConnectionError, ReadError, WriteError};
use portty_transport::{
    run_client_handshake_with, ClientHandshake, HandshakeMessage, HandshakeOutcome, PairingFailure,
    ProtocolError, SyncError, Transport, TransportError, PROTOCOL_VERSION,
};
use serde::Serialize;

/// The first release of the computer program that speaks this app's wire
/// version, named in every "update your computer" message.
///
/// Bump it together with `PROTOCOL_VERSION`: a test below pins the pair, so a
/// protocol bump cannot ship telling people that the old release is enough.
pub(crate) const MIN_HOST_RELEASE: &str = "0.1.3";

/// What went wrong, as a stable name the UI can branch on (for example, to
/// stop retrying a reconnect that cannot succeed by itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConnectErrorKind {
    /// Another pair or reconnect is still running.
    Busy,
    /// The pasted or scanned text is not a usable pairing code.
    InvalidCode,
    /// This phone could not start its own network endpoint.
    Network,
    /// The computer could not be reached at all.
    Unreachable,
    /// The computer closed the link before answering anything - what an older
    /// computer program does with a phone it cannot understand.
    MaybeOldHost,
    /// The two sides speak different wire versions, for certain.
    Version,
    /// The link died part-way through.
    Lost,
    /// The comparison code was shown, then the link closed without an answer.
    NotConfirmed,
    /// The computer said the pairing was declined or timed out there.
    Declined,
    /// The pairing code did not prove itself (old or mistyped).
    CodeRejected,
    /// The pairing code expired or was already used.
    CodeExpired,
    /// The computer is refusing attempts for a while after too many.
    RateLimited,
    /// The computer removed this phone.
    Revoked,
    /// The computer refused this phone's saved pairing: pair again.
    Rejected,
    /// The computer that answered is not the one expected.
    WrongHost,
    /// This phone's saved record for the computer is unusable.
    SavedDamaged,
    /// Nothing is saved to reconnect to.
    NoSavedHost,
    /// The chosen computer is no longer saved.
    HostNotSaved,
    /// The link worked but this phone could not store the result.
    SaveFailed,
    /// Anything else.
    Failed,
}

/// A failed pair or reconnect, as the UI receives it (the command's error).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ConnectError {
    pub(crate) kind: ConnectErrorKind,
    /// One or two short sentences: what happened, then what to do.
    pub(crate) message: String,
    /// The technical text, for support. Shown only behind "Details".
    pub(crate) detail: String,
}

impl ConnectError {
    fn new(kind: ConnectErrorKind, message: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            detail: detail.into(),
        }
    }

    /// Note a failure that reached the screen. `debug` only: release builds
    /// keep the log to warnings, and the UI already holds the detail.
    pub(crate) fn logged(self, attempt: Attempt) -> Self {
        tracing::debug!(?attempt, kind = ?self.kind, detail = %self.detail, "connect attempt failed");
        self
    }
}

/// Which attempt failed. The same refusal means different things for each: a
/// rejected pairing code wants a fresh QR, a rejected saved pairing wants a
/// fresh pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Attempt {
    FirstPair,
    Reconnect,
}

/// How far the handshake got before it failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Progress {
    /// Nothing at all came back from the computer.
    NoReply,
    /// The computer answered at least once.
    Replied,
    /// First pair only: this phone is showing the comparison code, so the
    /// computer is waiting for a person there to confirm it.
    CodeShown,
}

impl Progress {
    fn of(replies: usize, code_shown: bool) -> Self {
        if code_shown {
            Self::CodeShown
        } else if replies > 0 {
            Self::Replied
        } else {
            Self::NoReply
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::NoReply => "before any reply",
            Self::Replied => "after a reply",
            Self::CodeShown => "while the code was shown",
        }
    }
}

const RUN_PAIR_AGAIN: &str = "Run `portty pair` on your computer again and scan the new QR code.";
const CONFIRM_AGAIN: &str = "Run `portty pair` on your computer again, scan the new QR code, \
                             and type y there when the codes match.";

fn update_host() -> String {
    format!(
        "Update the Portty program on your computer to {MIN_HOST_RELEASE} or newer \
         (check with `portty --version`), then try again."
    )
}

/// Where this app is updated from, by platform.
fn update_app_for(os: &str) -> &'static str {
    match os {
        "android" => "Update Portty from Google Play, then try again.",
        "ios" => "Update Portty from the App Store, then try again.",
        _ => "Update this app, then try again.",
    }
}

fn update_app() -> &'static str {
    update_app_for(std::env::consts::OS)
}

/// The definite version mismatch. Peers do NOT negotiate (append-only wire,
/// see `frame.rs`), so the only remedy is updating the older side.
///
/// `peer_version` is the version stamped on the peer's frame, when the frame
/// layer rejected it; comparing it with ours names the older side. `None`
/// (the handshake's `UnsupportedVersion` carries no number) asks to update
/// both.
pub(crate) fn version_mismatch_message(peer_version: Option<u16>) -> String {
    match peer_version {
        Some(peer) if peer < PROTOCOL_VERSION => format!(
            "Your computer has an older version of Portty than this app. {}",
            update_host()
        ),
        Some(peer) if peer > PROTOCOL_VERSION => format!(
            "This app is older than the Portty program on your computer. {}",
            update_app()
        ),
        _ => "This app and your computer have different versions of Portty. Update both to \
              the newest version (check the computer with `portty --version`), then try again."
            .to_string(),
    }
}

pub(crate) fn busy() -> ConnectError {
    ConnectError::new(
        ConnectErrorKind::Busy,
        "Portty is already connecting. Wait a moment, then try again.",
        "a connection attempt is already in progress",
    )
}

/// The pasted or scanned text cannot be used to pair: unreadable, or missing
/// the secret that is the whole first-pair credential.
pub(crate) fn invalid_code(detail: impl Into<String>) -> ConnectError {
    ConnectError::new(
        ConnectErrorKind::InvalidCode,
        "That isn't a complete pairing code. Scan the QR code from `portty pair` on your \
         computer, or paste the whole code it shows.",
        detail,
    )
}

/// This phone could not build its iroh endpoint.
pub(crate) fn network(error: &TransportError) -> ConnectError {
    ConnectError::new(
        ConnectErrorKind::Network,
        "Couldn't start a connection on this phone. Check that it's online, then try again.",
        error.to_string(),
    )
}

/// The dial itself failed: the computer is off, offline, not running Portty,
/// or this phone is offline. Never the "older version" message - that needs a
/// link that opened and then closed.
pub(crate) fn unreachable(error: &TransportError) -> ConnectError {
    ConnectError::new(
        ConnectErrorKind::Unreachable,
        "Can't reach your computer. Check that both devices are online and that \
         `portty-host` is running on the computer. Then try again.",
        error.to_string(),
    )
}

/// The computer that answered is not the one the code or the saved record
/// names. Stop, and never offer to carry on.
pub(crate) fn wrong_host(attempt: Attempt, detail: impl Into<String>) -> ConnectError {
    let message = match attempt {
        Attempt::FirstPair => format!(
            "The computer that answered isn't the one in this pairing code, so Portty \
             stopped. {RUN_PAIR_AGAIN}"
        ),
        Attempt::Reconnect => "The computer that answered isn't the one this phone saved, so \
                               Portty stopped. Remove that computer from your saved list, then \
                               pair again."
            .to_string(),
    };
    ConnectError::new(ConnectErrorKind::WrongHost, message, detail)
}

pub(crate) fn saved_damaged(detail: impl Into<String>) -> ConnectError {
    ConnectError::new(
        ConnectErrorKind::SavedDamaged,
        "This phone's saved details for that computer are damaged. Remove it from your saved \
         list, then pair again.",
        detail,
    )
}

pub(crate) fn no_saved_host() -> ConnectError {
    ConnectError::new(
        ConnectErrorKind::NoSavedHost,
        "No computer is saved on this phone yet. Tap \u{201c}Connect to a host\u{201d} to pair \
         one.",
        "no saved host",
    )
}

pub(crate) fn host_not_saved() -> ConnectError {
    ConnectError::new(
        ConnectErrorKind::HostNotSaved,
        "That computer is no longer saved on this phone. To use it again, pair again with \
         `portty pair`.",
        "that host is no longer saved",
    )
}

pub(crate) fn save_failed(attempt: Attempt, detail: impl Into<String>) -> ConnectError {
    let message = match attempt {
        Attempt::FirstPair => {
            format!("Paired, but this phone couldn't save the pairing. {RUN_PAIR_AGAIN}")
        }
        Attempt::Reconnect => {
            "Connected, but this phone couldn't save the updated pairing. Try again.".to_string()
        }
    };
    ConnectError::new(ConnectErrorKind::SaveFailed, message, detail)
}

/// The computer removed this phone.
pub(crate) fn revoked(attempt: Attempt) -> ConnectError {
    let message = match attempt {
        Attempt::FirstPair => {
            "This phone was removed from your computer earlier. To pair it \
                               again, run `portty pair` on your computer and scan the new QR \
                               code."
        }
        Attempt::Reconnect => {
            "Your computer removed this phone. To use it again, pair again: \
                               run `portty pair` on your computer and scan the new QR code."
        }
    };
    ConnectError::new(
        ConnectErrorKind::Revoked,
        message,
        "pairing failed: Revoked",
    )
}

/// The computer removed this phone, and clearing the saved record here failed.
pub(crate) fn revoked_cleanup_failed(detail: impl Into<String>) -> ConnectError {
    ConnectError::new(
        ConnectErrorKind::Revoked,
        "Your computer removed this phone, but this phone couldn't clear its saved details. \
         Remove that computer from your saved list, then pair again.",
        detail,
    )
}

/// How a link that died mid-handshake ended, as far as this phone can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkEnd {
    /// The computer closed or reset it.
    Closed,
    /// It went quiet: the computer vanished or the network dropped.
    TimedOut,
}

fn link_end(error: &SyncError) -> Option<LinkEnd> {
    let io = match error {
        SyncError::Transport(TransportError::Closed) => return Some(LinkEnd::Closed),
        SyncError::Transport(TransportError::Io(io)) | SyncError::Io(io) => io,
        _ => return None,
    };
    if io_timed_out(io) {
        return Some(LinkEnd::TimedOut);
    }
    match io.kind() {
        ErrorKind::NotConnected
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::BrokenPipe
        | ErrorKind::UnexpectedEof => Some(LinkEnd::Closed),
        _ => None,
    }
}

/// QUIC reports a lost connection as `NotConnected` whatever the reason, so the
/// idle timeout has to be read from the error inside.
fn io_timed_out(io: &std::io::Error) -> bool {
    if io.kind() == ErrorKind::TimedOut {
        return true;
    }
    let Some(inner) = io.get_ref() else {
        return false;
    };
    if let Some(read) = inner.downcast_ref::<ReadError>() {
        return matches!(read, ReadError::ConnectionLost(ConnectionError::TimedOut));
    }
    if let Some(write) = inner.downcast_ref::<WriteError>() {
        return matches!(write, WriteError::ConnectionLost(ConnectionError::TimedOut));
    }
    matches!(
        inner.downcast_ref::<ConnectionError>(),
        Some(ConnectionError::TimedOut)
    )
}

/// The handshake failed. `progress` says how far it got.
pub(crate) fn handshake_error(
    error: &SyncError,
    attempt: Attempt,
    progress: Progress,
) -> ConnectError {
    let detail = format!("handshake {}: {error}", progress.label());
    let (kind, message) = match error {
        // The frame layer read the computer's own version off its reply.
        SyncError::Transport(TransportError::UnsupportedProtocolVersion { found, .. }) => (
            ConnectErrorKind::Version,
            version_mismatch_message(Some(*found)),
        ),
        SyncError::Protocol(ProtocolError::PairingFailed(reason)) => {
            return pairing_failed(reason, attempt, detail);
        }
        _ => match (link_end(error), progress) {
            // An older computer program cannot read this app's first message
            // and drops the link without a word (it has no way to reply in a
            // version we accept). A computer shutting down mid-connect looks
            // the same, which is why the message says "may".
            (Some(LinkEnd::Closed), Progress::NoReply) => (
                ConnectErrorKind::MaybeOldHost,
                format!(
                    "Couldn't finish connecting. Your computer may have an older version of \
                     Portty. {}",
                    update_host()
                ),
            ),
            // The computer held the link open while a person there looked at
            // the code, then closed it: an older computer program says "no" (or
            // "nobody answered") this way.
            (Some(LinkEnd::Closed), Progress::CodeShown) => (
                ConnectErrorKind::NotConfirmed,
                format!(
                    "Pairing didn't finish. The code may not have been confirmed on your \
                     computer in time. {CONFIRM_AGAIN}"
                ),
            ),
            (Some(_), _) => (
                ConnectErrorKind::Lost,
                "Lost the connection to your computer while connecting. Check that both \
                 devices are online, then try again."
                    .to_string(),
            ),
            (None, _) => (
                ConnectErrorKind::Failed,
                "Couldn't connect to your computer. Try again. If it keeps happening, update \
                 Portty on both devices."
                    .to_string(),
            ),
        },
    };
    ConnectError::new(kind, message, detail)
}

/// The computer answered with a refusal.
fn pairing_failed(reason: &PairingFailure, attempt: Attempt, detail: String) -> ConnectError {
    use ConnectErrorKind as Kind;
    let (kind, message) = match (reason, attempt) {
        (PairingFailure::UnsupportedVersion, _) => (Kind::Version, version_mismatch_message(None)),
        (PairingFailure::Revoked, _) => {
            return ConnectError {
                detail,
                ..revoked(attempt)
            }
        }
        // `WrongPin` keeps its wire name, but there is no PIN any more: it is
        // the generic "that credential did not prove itself".
        (PairingFailure::WrongPin, Attempt::FirstPair) => (
            Kind::CodeRejected,
            format!("This pairing code didn't work. It may be old or mistyped. {RUN_PAIR_AGAIN}"),
        ),
        (PairingFailure::PairingClosed, Attempt::FirstPair) => (
            Kind::CodeExpired,
            format!("This pairing code has expired or was already used. {RUN_PAIR_AGAIN}"),
        ),
        // A reconnect refused with either of these means the computer no longer
        // holds this phone's pairing (forgotten, reset, or the credential
        // rotated away). This is the one case where pairing again is the fix.
        (PairingFailure::WrongPin | PairingFailure::PairingClosed, Attempt::Reconnect) => (
            Kind::Rejected,
            "Your computer no longer accepts this phone's saved pairing. Pair again: run \
             `portty pair` on your computer and scan the new QR code."
                .to_string(),
        ),
        (PairingFailure::RateLimited, Attempt::FirstPair) => (
            Kind::RateLimited,
            "Your computer paused pairing after too many tries. Wait a few minutes, then run \
             `portty pair` again and scan the new QR code."
                .to_string(),
        ),
        (PairingFailure::RateLimited, Attempt::Reconnect) => (
            Kind::RateLimited,
            "Your computer paused connections from this phone after too many tries. Wait a few \
             minutes, then try again."
                .to_string(),
        ),
        (PairingFailure::Cancelled, Attempt::FirstPair) => (
            Kind::Declined,
            format!("Pairing was declined or timed out on your computer. {CONFIRM_AGAIN}"),
        ),
        // Nothing asks a person about a reconnect, so a host has no reason to
        // send this; say something true rather than guess.
        (PairingFailure::Cancelled, Attempt::Reconnect) => (
            Kind::Failed,
            "Your computer turned down the connection. Try again.".to_string(),
        ),
    };
    ConnectError::new(kind, message, detail)
}

/// A failed handshake and how far it got.
pub(crate) struct HandshakeFailure {
    pub(crate) error: SyncError,
    pub(crate) progress: Progress,
}

impl HandshakeFailure {
    pub(crate) fn is_revoked(&self) -> bool {
        matches!(
            self.error,
            SyncError::Protocol(ProtocolError::PairingFailed(PairingFailure::Revoked))
        )
    }

    pub(crate) fn describe(&self, attempt: Attempt) -> ConnectError {
        handshake_error(&self.error, attempt, self.progress)
    }
}

/// Run the client handshake while counting what the computer sends, so a
/// failure can tell "it closed the link before answering at all" (an older
/// computer program, see `MaybeOldHost`) from a link that died later.
///
/// `on_code` gets the comparison code on a first pair, exactly as
/// [`run_client_handshake_with`] gives it.
pub(crate) async fn run_counted_handshake<T, F>(
    transport: &mut T,
    client: &mut ClientHandshake,
    mut on_code: F,
) -> Result<HandshakeOutcome, HandshakeFailure>
where
    T: Transport<HandshakeMessage>,
    F: FnMut(&str),
{
    let mut code_shown = false;
    let mut counted = ReplyCounter {
        inner: transport,
        replies: 0,
    };
    let result = run_client_handshake_with(&mut counted, client, |code| {
        code_shown = true;
        on_code(code);
    })
    .await;
    let replies = counted.replies;
    result.map_err(|error| HandshakeFailure {
        error,
        progress: Progress::of(replies, code_shown),
    })
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Passes every message through and counts the ones received.
///
/// `Transport` is an `#[async_trait]` trait and the app does not depend on
/// `async-trait` itself, so the three methods are written out in the form the
/// macro generates: a boxed `Send` future borrowing `self`.
struct ReplyCounter<'a, T> {
    inner: &'a mut T,
    replies: usize,
}

impl<T> Transport<HandshakeMessage> for ReplyCounter<'_, T>
where
    T: Transport<HandshakeMessage>,
{
    fn send<'life0, 'life1, 'async_trait>(
        &'life0 mut self,
        msg: &'life1 HandshakeMessage,
    ) -> BoxFuture<'async_trait, Result<(), TransportError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { self.inner.send(msg).await })
    }

    fn recv<'life0, 'async_trait>(
        &'life0 mut self,
    ) -> BoxFuture<'async_trait, Result<HandshakeMessage, TransportError>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let message = self.inner.recv().await?;
            self.replies += 1;
            Ok(message)
        })
    }

    fn close<'life0, 'async_trait>(
        &'life0 mut self,
    ) -> BoxFuture<'async_trait, Result<(), TransportError>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { self.inner.close().await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portty_transport::{DeviceId, PairingSecret, ResumptionToken};
    use std::collections::VecDeque;

    /// Every message a person reads must be plain words: no wire names, no
    /// "re-pair", no PIN, and never empty.
    fn assert_plain(error: &ConnectError) {
        let message = &error.message;
        assert!(!message.trim().is_empty());
        for jargon in [
            "WrongPin",
            "PairingClosed",
            "transport:",
            "protocol:",
            "iroh",
            "re-pair",
            "PIN",
            "laptop",
        ] {
            assert!(
                !message.contains(jargon),
                "{:?} message names {jargon:?}: {message}",
                error.kind
            );
        }
    }

    #[test]
    fn host_release_named_in_messages_tracks_the_wire_version() {
        // 0.1.3 is the first computer program that speaks wire version 11. When
        // PROTOCOL_VERSION moves, MIN_HOST_RELEASE must move with it - telling
        // people the old release is enough would send them round in circles.
        assert_eq!(
            PROTOCOL_VERSION, 11,
            "update MIN_HOST_RELEASE with the protocol"
        );
        assert_eq!(MIN_HOST_RELEASE, "0.1.3");
    }

    #[test]
    fn version_mismatch_names_the_older_side_and_says_computer() {
        let host_older = version_mismatch_message(Some(PROTOCOL_VERSION - 1));
        assert!(host_older.contains("Your computer has an older version"));
        assert!(host_older.contains("portty --version"));
        assert!(host_older.contains(MIN_HOST_RELEASE));

        let app_older = version_mismatch_message(Some(PROTOCOL_VERSION + 1));
        assert!(app_older.starts_with("This app is older"));

        let unknown = version_mismatch_message(None);
        assert!(unknown.contains("different versions"));

        for message in [host_older, app_older, unknown] {
            assert!(!message.contains("laptop"), "{message}");
        }
    }

    #[test]
    fn the_app_store_named_matches_the_platform() {
        assert!(update_app_for("android").contains("Google Play"));
        assert!(update_app_for("ios").contains("App Store"));
        assert!(!update_app_for("android").contains("App Store"));
        assert!(!update_app_for("ios").contains("Google Play"));
        assert!(!update_app_for("windows").contains("Google Play"));
    }

    #[test]
    fn link_closed_before_any_reply_points_at_an_older_computer() {
        // What a v0.1.2 computer (wire version 5) does with this app's Hello:
        // its recv() rejects the frame and the link drops. Seen on the phone as
        // either a lost connection or a clean close.
        let lost = SyncError::Transport(TransportError::Io(std::io::Error::from(
            ReadError::ConnectionLost(ConnectionError::Reset),
        )));
        let closed = SyncError::Transport(TransportError::Closed);
        for (error, attempt) in [
            (&lost, Attempt::FirstPair),
            (&closed, Attempt::FirstPair),
            (&lost, Attempt::Reconnect),
            (&closed, Attempt::Reconnect),
        ] {
            let described = handshake_error(error, attempt, Progress::NoReply);
            assert_eq!(described.kind, ConnectErrorKind::MaybeOldHost);
            assert!(described.message.contains("may have an older version"));
            assert!(described.message.contains("portty --version"));
            assert!(described.message.contains(MIN_HOST_RELEASE));
            assert!(!described.message.to_lowercase().contains("pair again"));
            assert_plain(&described);
            assert!(described.detail.contains("before any reply"));
        }
    }

    #[test]
    fn a_link_that_goes_quiet_is_a_lost_connection_not_an_old_computer() {
        let timed_out = SyncError::Transport(TransportError::Io(std::io::Error::from(
            ReadError::ConnectionLost(ConnectionError::TimedOut),
        )));
        let described = handshake_error(&timed_out, Attempt::Reconnect, Progress::NoReply);
        assert_eq!(described.kind, ConnectErrorKind::Lost);

        let write_timed_out = SyncError::Transport(TransportError::Io(std::io::Error::from(
            WriteError::ConnectionLost(ConnectionError::TimedOut),
        )));
        assert_eq!(
            handshake_error(&write_timed_out, Attempt::FirstPair, Progress::NoReply).kind,
            ConnectErrorKind::Lost
        );
    }

    #[test]
    fn a_link_closed_after_the_computer_answered_is_not_blamed_on_its_version() {
        let closed = SyncError::Transport(TransportError::Closed);
        let described = handshake_error(&closed, Attempt::Reconnect, Progress::Replied);
        assert_eq!(described.kind, ConnectErrorKind::Lost);
        assert!(!described.message.contains("older version"));
    }

    #[test]
    fn a_link_closed_while_the_code_was_shown_asks_to_confirm_on_the_computer() {
        let closed = SyncError::Transport(TransportError::Closed);
        let described = handshake_error(&closed, Attempt::FirstPair, Progress::CodeShown);
        assert_eq!(described.kind, ConnectErrorKind::NotConfirmed);
        assert!(described.message.contains("type y"));
        assert_plain(&described);
    }

    #[test]
    fn a_frame_from_another_wire_version_names_the_older_side_on_both_paths() {
        let older_host = SyncError::Transport(TransportError::UnsupportedProtocolVersion {
            expected: PROTOCOL_VERSION,
            found: PROTOCOL_VERSION - 1,
        });
        for attempt in [Attempt::FirstPair, Attempt::Reconnect] {
            let described = handshake_error(&older_host, attempt, Progress::NoReply);
            assert_eq!(described.kind, ConnectErrorKind::Version);
            assert!(described
                .message
                .contains("Your computer has an older version"));
            assert_plain(&described);
        }
        let newer_host = SyncError::Transport(TransportError::UnsupportedProtocolVersion {
            expected: PROTOCOL_VERSION,
            found: PROTOCOL_VERSION + 1,
        });
        let described = handshake_error(&newer_host, Attempt::Reconnect, Progress::NoReply);
        assert!(described.message.starts_with("This app is older"));
    }

    fn refusal(reason: PairingFailure) -> SyncError {
        SyncError::Protocol(ProtocolError::PairingFailed(reason))
    }

    #[test]
    fn only_a_refused_saved_pairing_says_pair_again() {
        for reason in [PairingFailure::WrongPin, PairingFailure::PairingClosed] {
            let reconnect = handshake_error(
                &refusal(reason.clone()),
                Attempt::Reconnect,
                Progress::Replied,
            );
            assert_eq!(reconnect.kind, ConnectErrorKind::Rejected);
            assert!(reconnect.message.contains("Pair again"));
            assert_plain(&reconnect);

            let first = handshake_error(&refusal(reason), Attempt::FirstPair, Progress::Replied);
            assert!(!first.message.to_lowercase().contains("pair again"));
            assert!(first.message.contains("scan the new QR code"));
            assert_plain(&first);
        }
        assert_eq!(
            handshake_error(
                &refusal(PairingFailure::WrongPin),
                Attempt::FirstPair,
                Progress::CodeShown
            )
            .kind,
            ConnectErrorKind::CodeRejected
        );
        assert_eq!(
            handshake_error(
                &refusal(PairingFailure::PairingClosed),
                Attempt::FirstPair,
                Progress::NoReply
            )
            .kind,
            ConnectErrorKind::CodeExpired
        );
    }

    #[test]
    fn every_refusal_reads_as_plain_words() {
        for reason in [
            PairingFailure::WrongPin,
            PairingFailure::RateLimited,
            PairingFailure::UnsupportedVersion,
            PairingFailure::Cancelled,
            PairingFailure::PairingClosed,
            PairingFailure::Revoked,
        ] {
            for attempt in [Attempt::FirstPair, Attempt::Reconnect] {
                let described =
                    handshake_error(&refusal(reason.clone()), attempt, Progress::Replied);
                assert_plain(&described);
                assert!(
                    described.detail.contains("pairing failed"),
                    "{}",
                    described.detail
                );
            }
        }
        assert_eq!(
            handshake_error(
                &refusal(PairingFailure::Cancelled),
                Attempt::FirstPair,
                Progress::CodeShown
            )
            .kind,
            ConnectErrorKind::Declined
        );
        assert_eq!(
            handshake_error(
                &refusal(PairingFailure::UnsupportedVersion),
                Attempt::Reconnect,
                Progress::NoReply
            )
            .kind,
            ConnectErrorKind::Version
        );
        assert_eq!(
            handshake_error(
                &refusal(PairingFailure::Revoked),
                Attempt::Reconnect,
                Progress::Replied
            )
            .kind,
            ConnectErrorKind::Revoked
        );
    }

    #[test]
    fn every_fixed_message_reads_as_plain_words() {
        let detail = TransportError::Iroh("connect: timed out".into());
        for error in [
            busy(),
            invalid_code("ticket b64: bad"),
            network(&detail),
            unreachable(&detail),
            wrong_host(Attempt::FirstPair, "mismatch"),
            wrong_host(Attempt::Reconnect, "mismatch"),
            saved_damaged("bad"),
            no_saved_host(),
            host_not_saved(),
            save_failed(Attempt::FirstPair, "disk"),
            save_failed(Attempt::Reconnect, "disk"),
            revoked(Attempt::FirstPair),
            revoked(Attempt::Reconnect),
            revoked_cleanup_failed("disk"),
        ] {
            assert_plain(&error);
        }
        // Unreachable is its own message: never the older-version guess.
        assert!(!unreachable(&detail).message.contains("older version"));
    }

    #[test]
    fn the_ui_receives_kind_message_and_detail() {
        let json = serde_json::to_value(busy()).unwrap();
        assert_eq!(json["kind"], "busy");
        assert!(json["message"]
            .as_str()
            .unwrap()
            .starts_with("Portty is already connecting"));
        assert_eq!(
            json["detail"],
            "a connection attempt is already in progress"
        );
        assert_eq!(
            serde_json::to_value(ConnectErrorKind::MaybeOldHost).unwrap(),
            "maybe_old_host"
        );
    }

    // ── The counting wrapper, driven through the real handshake ──────────

    /// A computer that answers from a script, then runs out.
    struct ScriptedHost {
        replies: VecDeque<Result<HandshakeMessage, TransportError>>,
    }

    impl Transport<HandshakeMessage> for ScriptedHost {
        fn send<'life0, 'life1, 'async_trait>(
            &'life0 mut self,
            _msg: &'life1 HandshakeMessage,
        ) -> BoxFuture<'async_trait, Result<(), TransportError>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { Ok(()) })
        }

        fn recv<'life0, 'async_trait>(
            &'life0 mut self,
        ) -> BoxFuture<'async_trait, Result<HandshakeMessage, TransportError>>
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                self.replies
                    .pop_front()
                    .unwrap_or(Err(TransportError::Closed))
            })
        }

        fn close<'life0, 'async_trait>(
            &'life0 mut self,
        ) -> BoxFuture<'async_trait, Result<(), TransportError>>
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { Ok(()) })
        }
    }

    /// A well-formed challenge. The X25519 base point is a valid, contributory
    /// public key, so the client gets as far as sending its proof.
    fn challenge() -> HandshakeMessage {
        let mut server_eph_pub = [0u8; 32];
        server_eph_pub[0] = 9;
        HandshakeMessage::PairingChallenge {
            nonce: [7; 32],
            server_eph_pub,
        }
    }

    fn first_pair() -> ClientHandshake {
        ClientHandshake::first_pair(
            DeviceId([1; 16]),
            "phone".into(),
            PairingSecret::from_ticket_bytes([0x42; 16]),
        )
    }

    fn resume() -> ClientHandshake {
        ClientHandshake::resume(
            DeviceId([1; 16]),
            "phone".into(),
            ResumptionToken::from([0x24; 32]),
        )
    }

    #[tokio::test]
    async fn a_computer_that_never_answers_is_counted_as_no_reply() {
        let mut host = ScriptedHost {
            replies: VecDeque::new(),
        };
        let failure = run_counted_handshake(&mut host, &mut resume(), |_| {})
            .await
            .err()
            .expect("the link closed");
        assert_eq!(failure.progress, Progress::NoReply);
        assert_eq!(
            failure.describe(Attempt::Reconnect).kind,
            ConnectErrorKind::MaybeOldHost
        );
    }

    #[tokio::test]
    async fn a_reconnect_that_dies_after_the_challenge_is_a_lost_link() {
        let mut host = ScriptedHost {
            replies: VecDeque::from([Ok(challenge())]),
        };
        let failure = run_counted_handshake(&mut host, &mut resume(), |_| {})
            .await
            .err()
            .expect("the link closed");
        assert_eq!(failure.progress, Progress::Replied);
        assert_eq!(
            failure.describe(Attempt::Reconnect).kind,
            ConnectErrorKind::Lost
        );
    }

    #[tokio::test]
    async fn a_first_pair_closed_while_the_code_is_shown_is_not_confirmed() {
        let mut host = ScriptedHost {
            replies: VecDeque::from([Ok(challenge())]),
        };
        let mut codes = Vec::new();
        let failure = run_counted_handshake(&mut host, &mut first_pair(), |code| {
            codes.push(code.to_string())
        })
        .await
        .err()
        .expect("the link closed");
        assert_eq!(codes.len(), 1, "the code still reaches the screen");
        assert_eq!(failure.progress, Progress::CodeShown);
        assert_eq!(
            failure.describe(Attempt::FirstPair).kind,
            ConnectErrorKind::NotConfirmed
        );
    }

    #[tokio::test]
    async fn a_refusal_after_the_code_is_reported_as_the_refusal() {
        let mut host = ScriptedHost {
            replies: VecDeque::from([
                Ok(challenge()),
                Ok(HandshakeMessage::PairingFailed {
                    reason: PairingFailure::Cancelled,
                }),
            ]),
        };
        let failure = run_counted_handshake(&mut host, &mut first_pair(), |_| {})
            .await
            .err()
            .expect("the computer said no");
        assert!(!failure.is_revoked());
        assert_eq!(
            failure.describe(Attempt::FirstPair).kind,
            ConnectErrorKind::Declined
        );
    }

    #[tokio::test]
    async fn a_revoked_reconnect_is_recognised() {
        let mut host = ScriptedHost {
            replies: VecDeque::from([Ok(HandshakeMessage::PairingFailed {
                reason: PairingFailure::Revoked,
            })]),
        };
        let failure = run_counted_handshake(&mut host, &mut resume(), |_| {})
            .await
            .err()
            .expect("the computer said no");
        assert!(failure.is_revoked());
        assert_eq!(failure.progress, Progress::Replied);
    }
}
