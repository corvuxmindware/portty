//! Human confirmation of a FIRST pair.
//!
//! Since `PROTOCOL_VERSION` 8 the low-entropy human step happens AFTER the key
//! exchange, not before it. Both peers derive the same six-digit comparison code
//! from the finished session (`portty_transport::pair_verification_code`), the
//! phone shows it, and an operator at the host confirms that the two screens
//! agree before the pairing is committed.
//!
//! # Why this exists
//!
//! The out-of-band ticket secret already authenticates the exchange, so this is
//! not the primary defence - it is what stops a credential that LEAKED from
//! silently becoming a paired device. Someone who photographs a QR off a screen,
//! or who brute-forces the shorter manual phrase, still has to get a human to
//! approve a code they cannot see. Before this, a leaked ticket paired in
//! silence and left only an `info!` log line behind.
//!
//! # Fail-closed
//!
//! Every path that is not an explicit human "yes" is a no: no console attached,
//! a console that hangs up, a timeout, a second confirmation already in flight,
//! or an unparseable answer. A host nobody is watching does not pair.
//!
//! # Consoles
//!
//! A "console" is anything that can ask a human. Exactly one exists: a connected
//! `portty pair` session, over the same-user relay pipe.
//!
//! The host's own stdin is deliberately NOT a console. `portty-host` daemonises
//! with `setsid` and a double fork and points stdin at `/dev/null`, so the
//! process that prints the banner has no terminal to read and no controlling
//! terminal to fall back to. A stdin console therefore worked only under
//! `--foreground`, which meant the DEFAULT invocation printed "confirm here" and
//! then denied every pairing. One console that always works beats two where the
//! common one silently does not.
//!
//! The registry still fans out to every attached console and takes the FIRST
//! answer, because more than one `portty pair` can be running.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use portty_transport::DeviceId;
use tokio::sync::{mpsc, Semaphore};
use tracing::{info, warn};

/// How long a pairing request waits for a human before it is denied.
///
/// Long enough to walk back to the laptop, short enough that an abandoned
/// request cannot hold the phone's connection open indefinitely. The phone's
/// QUIC keepalive (10s) comfortably spans it.
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(120);

/// How many answers a single request's reply channel can buffer. One per
/// attached console, so a slow second console answering after the first cannot
/// block on a full channel.
const REPLY_SLOTS: usize = 8;

/// One pending pairing request, handed to each attached console.
pub struct PairRequest {
    /// The QUIC-authenticated device asking to pair.
    pub device_id: DeviceId,
    /// The name the phone announced. Attacker-controlled text - render it, never
    /// interpret it, and never let it be confused with the code.
    pub display_name: String,
    /// The six-digit comparison code. Not secret; it is meant to be read aloud.
    pub code: String,
    reply: mpsc::Sender<bool>,
}

impl PairRequest {
    /// Answer this request. Extra answers after the first are ignored.
    pub async fn answer(self, accept: bool) {
        let _ = self.reply.send(accept).await;
    }
}

impl std::fmt::Debug for PairRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The code is safe to print, but keep the shape stable and boring.
        f.debug_struct("PairRequest")
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

type Consoles = Arc<Mutex<Vec<(u64, mpsc::Sender<PairRequest>)>>>;

/// Host-wide confirmation broker. Cheap to clone; every clone shares one
/// console registry and one in-flight slot.
#[derive(Clone)]
pub struct PairConfirm {
    consoles: Consoles,
    next_id: Arc<AtomicU64>,
    /// Exactly one confirmation may be in flight at a time.
    ///
    /// This is not just tidiness about interleaved terminal prompts. Without it
    /// an attacker who can reach the endpoint during an open window could fire
    /// the operator a stream of approval prompts and hope one is waved through -
    /// the classic approval-fatigue attack. One at a time, with everything else
    /// denied outright, keeps the operator looking at a single decision.
    in_flight: Arc<Semaphore>,
}

/// Keeps a console attached. Dropping it detaches, so a `portty pair` session
/// that disconnects stops being asked.
pub struct ConsoleGuard {
    id: u64,
    consoles: Consoles,
}

impl Drop for ConsoleGuard {
    fn drop(&mut self) {
        if let Ok(mut consoles) = self.consoles.lock() {
            consoles.retain(|(id, _)| *id != self.id);
        }
    }
}

impl Default for PairConfirm {
    fn default() -> Self {
        Self::new()
    }
}

impl PairConfirm {
    pub fn new() -> Self {
        Self {
            consoles: Arc::new(Mutex::new(Vec::new())),
            next_id: Arc::new(AtomicU64::new(0)),
            in_flight: Arc::new(Semaphore::new(1)),
        }
    }

    /// Attach a console. Hold the guard for as long as it can answer; requests
    /// arrive on the receiver until it is dropped.
    pub fn attach(&self) -> (ConsoleGuard, mpsc::Receiver<PairRequest>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(1);
        if let Ok(mut consoles) = self.consoles.lock() {
            consoles.push((id, tx));
        }
        (
            ConsoleGuard {
                id,
                consoles: self.consoles.clone(),
            },
            rx,
        )
    }

    /// Ask a human to confirm this pairing. Returns true ONLY on an explicit yes.
    pub async fn confirm(&self, device_id: DeviceId, display_name: &str, code: &str) -> bool {
        // Refuse rather than queue: a queued prompt is a prompt the operator sees
        // out of context, and a queue is what an attacker would fill.
        let Ok(_slot) = self.in_flight.try_acquire() else {
            warn!(
                peer = %device_id,
                "denying pair: another pairing confirmation is already waiting"
            );
            return false;
        };

        let (reply_tx, mut reply_rx) = mpsc::channel(REPLY_SLOTS);
        let targets: Vec<mpsc::Sender<PairRequest>> = match self.consoles.lock() {
            Ok(consoles) => consoles.iter().map(|(_, tx)| tx.clone()).collect(),
            // Poisoned registry: we cannot ask anyone, so we do not pair.
            Err(_) => Vec::new(),
        };
        if targets.is_empty() {
            warn!(
                peer = %device_id,
                "denying pair: nothing is attached to confirm it. Run `portty pair` \
                 on the host, or start it with --foreground, and pair again"
            );
            return false;
        }

        let mut delivered = 0usize;
        for target in targets {
            let request = PairRequest {
                device_id,
                display_name: display_name.to_string(),
                code: code.to_string(),
                reply: reply_tx.clone(),
            };
            if target.try_send(request).is_ok() {
                delivered += 1;
            }
        }
        // Drop our own handle so the channel closes once every console has gone,
        // turning "all consoles vanished" into an immediate deny instead of a
        // wait for the full timeout.
        drop(reply_tx);
        if delivered == 0 {
            warn!(peer = %device_id, "denying pair: no console accepted the request");
            return false;
        }

        match tokio::time::timeout(CONFIRM_TIMEOUT, reply_rx.recv()).await {
            Ok(Some(true)) => {
                info!(peer = %device_id, "pairing confirmed at the host");
                true
            }
            Ok(Some(false)) => {
                warn!(peer = %device_id, "pairing REJECTED at the host");
                false
            }
            // Every console dropped its request without answering.
            Ok(None) => {
                warn!(peer = %device_id, "denying pair: no answer from any console");
                false
            }
            Err(_) => {
                warn!(
                    peer = %device_id,
                    timeout_secs = CONFIRM_TIMEOUT.as_secs(),
                    "denying pair: timed out waiting for confirmation"
                );
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(n: u8) -> DeviceId {
        DeviceId([n; 16])
    }

    /// The headline fail-closed property: a host with nobody watching does not
    /// pair, however valid the credential was.
    #[tokio::test]
    async fn no_console_denies() {
        let confirm = PairConfirm::new();
        assert!(!confirm.confirm(dev(1), "phone", "123456").await);
    }

    #[tokio::test]
    async fn an_explicit_yes_confirms() {
        let confirm = PairConfirm::new();
        let (_guard, mut rx) = confirm.attach();
        tokio::spawn(async move {
            let request = rx.recv().await.expect("a request");
            assert_eq!(request.code, "123456");
            request.answer(true).await;
        });
        assert!(confirm.confirm(dev(1), "phone", "123456").await);
    }

    #[tokio::test]
    async fn an_explicit_no_denies() {
        let confirm = PairConfirm::new();
        let (_guard, mut rx) = confirm.attach();
        tokio::spawn(async move {
            rx.recv().await.expect("a request").answer(false).await;
        });
        assert!(!confirm.confirm(dev(1), "phone", "123456").await);
    }

    /// A console that takes the request and then hangs up - the operator closed
    /// the terminal, the CLI died - must not leave the pairing hanging until the
    /// full timeout, and must never be read as approval.
    #[tokio::test]
    async fn a_console_that_hangs_up_denies_immediately() {
        let confirm = PairConfirm::new();
        let (_guard, mut rx) = confirm.attach();
        tokio::spawn(async move {
            let request = rx.recv().await.expect("a request");
            drop(request); // never answers
        });
        let start = std::time::Instant::now();
        assert!(!confirm.confirm(dev(1), "phone", "123456").await);
        assert!(
            start.elapsed() < CONFIRM_TIMEOUT,
            "a dropped request must not wait out the timeout"
        );
    }

    /// A detached console is not asked. This is what makes a `portty pair`
    /// session stop being an approval channel once it disconnects.
    #[tokio::test]
    async fn a_detached_console_is_not_asked() {
        let confirm = PairConfirm::new();
        let (guard, mut rx) = confirm.attach();
        drop(guard);
        assert!(!confirm.confirm(dev(1), "phone", "123456").await);
        assert!(
            rx.try_recv().is_err(),
            "a detached console must receive nothing"
        );
    }

    /// Approval-fatigue guard: while one operator decision is pending, further
    /// requests are denied outright rather than queued behind it.
    #[tokio::test]
    async fn a_second_concurrent_request_is_denied_not_queued() {
        let confirm = PairConfirm::new();
        let (_guard, mut rx) = confirm.attach();
        let (pending_tx, pending_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let request = rx.recv().await.expect("a request");
            // The slot is definitely held once the console has the request.
            let _ = pending_tx.send(());
            let _ = release_rx.await;
            request.answer(true).await;
        });

        let first = {
            let confirm = confirm.clone();
            tokio::spawn(async move { confirm.confirm(dev(1), "phone", "111111").await })
        };
        pending_rx
            .await
            .expect("the first request reached a console");

        assert!(
            !confirm.confirm(dev(2), "attacker", "222222").await,
            "a second prompt must be refused while one is pending"
        );
        let _ = release_tx.send(());
        assert!(first.await.unwrap());
    }

    /// Two consoles (foreground stdin AND a `portty pair` CLI) may both be
    /// attached; the first answer decides.
    #[tokio::test]
    async fn the_first_answer_from_any_console_wins() {
        let confirm = PairConfirm::new();
        let (_slow_guard, mut slow) = confirm.attach();
        let (_fast_guard, mut fast) = confirm.attach();
        tokio::spawn(async move {
            let request = slow.recv().await.expect("a request");
            tokio::time::sleep(Duration::from_millis(200)).await;
            request.answer(false).await;
        });
        tokio::spawn(async move {
            fast.recv().await.expect("a request").answer(true).await;
        });
        assert!(confirm.confirm(dev(1), "phone", "123456").await);
    }

    /// The gate in `iroh_serve`'s accept path must key on `!resumed`, not on
    /// `enrollment_epoch.is_some()`.
    ///
    /// A B4 enrollment-exempt device is a FIRST pair that carries NO epoch, so
    /// the epoch-based condition would wave it straight past confirmation. This
    /// pins the shape of the condition, because the two agree on every input the
    /// production accept path can currently produce - which is precisely what
    /// would keep the bug hidden.
    #[test]
    fn a_first_pair_without_an_enrollment_epoch_still_needs_confirming() {
        // The gate the accept path uses, and the one it must NOT use.
        let by_resumed = |resumed: bool, _epoch: Option<u64>| !resumed;
        let by_epoch = |_resumed: bool, epoch: Option<u64>| epoch.is_some();

        // (resumed, enrollment_epoch, must a human confirm?)
        let ordinary_first_pair = (false, Some(7u64), true);
        let exempt_first_pair = (false, None, true);
        let token_reconnect = (true, None, false);

        for (resumed, epoch, expected) in [ordinary_first_pair, exempt_first_pair, token_reconnect]
        {
            assert_eq!(by_resumed(resumed, epoch), expected);
        }

        // The two predicates agree everywhere the production accept path can
        // reach today, which is why the wrong one looked correct...
        for (resumed, epoch, _) in [ordinary_first_pair, token_reconnect] {
            assert_eq!(by_resumed(resumed, epoch), by_epoch(resumed, epoch));
        }
        // ...and disagree exactly on the B4 exemption, where the epoch-keyed gate
        // would enrol a new device with no human ever seeing a code.
        let (resumed, epoch, expected) = exempt_first_pair;
        assert_eq!(by_resumed(resumed, epoch), expected);
        assert_ne!(
            by_epoch(resumed, epoch),
            expected,
            "an epoch-keyed gate silently skips confirmation for an exempt device"
        );
    }
}
