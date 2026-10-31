//! Ask the host whether it will serve a download before the phone picks where
//! to save it.
//!
//! On Android the system Save dialog creates the destination file, empty, the
//! moment the user taps Save - before the host has been asked for a single
//! byte. When the host then refuses (no such file, outside the home folder, too
//! large), that empty file is left under the chosen name, and removing it again
//! is not reliable: OnePlus's Downloads provider reports the delete as done but
//! deletes `<name>.oplusdownload` instead, and the framework then revokes the
//! app's access, so the leftover cannot even be checked.
//!
//! So the frontend asks first. A probe is an ordinary `FileGetReq`, and only
//! its first answer matters: a chunk (or, for an empty file, `FileDone`) means
//! the host will serve the file, and the stream is cancelled at once; `FileErr`
//! carries the host's reason. Probe ids have their own range, so the chunks of a
//! cancelled probe still in flight are dropped quietly rather than reported as
//! belonging to some other transfer.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::Duration;

use portty_protocol::{Frame, TransferId};
use tauri::State;
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};

use crate::{try_enqueue, PorttyState, TransferOwner};

/// Probe ids carry this bit; transfer ids count up from 1 and never reach it.
const PROBE_ID_BIT: u64 = 1 << 63;

/// How long to wait for the host's first answer. It sends one as soon as it has
/// tried to open the file, so this only fires on a stalled link.
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

type Answer = Result<(), String>;

/// Probes waiting for the host's first answer, by id.
#[derive(Default)]
pub(crate) struct Probes(AsyncMutex<HashMap<TransferId, (TransferOwner, oneshot::Sender<Answer>)>>);

pub(crate) fn is_probe(id: TransferId) -> bool {
    id.0 & PROBE_ID_BIT != 0
}

/// Settle a probe from a host frame about it.
///
/// Frames from a host other than the one asked, and frames after the first
/// (the in-flight chunks of a cancelled probe), are dropped. `cancel` is the
/// link to stop the host's stream on, given when the frame was a chunk.
pub(crate) async fn answer(
    probes: &Probes,
    id: TransferId,
    owner: TransferOwner,
    answer: Answer,
    cancel: Option<&mpsc::Sender<Frame>>,
) {
    let waiter = {
        let mut waiting = probes.0.lock().await;
        match waiting.get(&id) {
            Some((asked, _)) if *asked == owner => waiting.remove(&id),
            _ => None,
        }
    };
    let Some((_, reply)) = waiter else {
        return;
    };
    if let Some(link) = cancel {
        // Spawned, not awaited: the caller is the session loop, which is also
        // the consumer of this queue.
        let link = link.clone();
        tokio::spawn(async move {
            let _ = link
                .send(Frame::FileErr {
                    id,
                    reason: "the phone only checked that the file can be read".into(),
                })
                .await;
        });
    }
    let _ = reply.send(answer);
}

/// Whether the host will serve `remote_path`: `Ok` once it has started to, the
/// host's own reason otherwise. Nothing is written anywhere. A phone that
/// cannot save downloads (iOS) says so here, before its Save dialog runs.
#[tauri::command]
pub(crate) async fn probe_download(
    state: State<'_, PorttyState>,
    remote_path: String,
    allow_outside_home: Option<bool>,
) -> Result<(), String> {
    crate::local_files::check_download_supported(crate::local_files::Platform::CURRENT)?;
    // Owner and sender from ONE look at the connection, as for real transfers.
    let (owner, outbound) = {
        let connection = state.connection.lock().await;
        let connection = connection
            .as_ref()
            .ok_or_else(|| "not paired".to_string())?;
        (
            TransferOwner {
                peer_device_id: connection.peer_device_id,
                pair_id: connection.pair_id,
            },
            connection.outbound.clone(),
        )
    };
    let id = TransferId(PROBE_ID_BIT | state.transfers.next_id.fetch_add(1, Ordering::Relaxed));
    let probes = &state.transfers.probes;
    let (reply, answered) = oneshot::channel();
    probes.0.lock().await.insert(id, (owner, reply));
    let request = Frame::FileGetReq {
        id,
        path: remote_path,
        start_seq: 0,
        allow_outside_home: allow_outside_home.unwrap_or(false),
    };
    if let Err(error) = try_enqueue(&outbound, request) {
        probes.0.lock().await.remove(&id);
        return Err(error);
    }
    match tokio::time::timeout(PROBE_TIMEOUT, answered).await {
        Ok(Ok(answer)) => answer,
        Ok(Err(_)) => Err("connection closed".into()),
        Err(_) => {
            probes.0.lock().await.remove(&id);
            // Stop the host in case it starts streaming after all.
            let _ = try_enqueue(
                &outbound,
                Frame::FileErr {
                    id,
                    reason: "the phone stopped waiting".into(),
                },
            );
            Err("the host did not answer".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portty_transport::{DeviceId, PairId};

    fn owner(byte: u8) -> TransferOwner {
        TransferOwner {
            peer_device_id: DeviceId([byte; 16]),
            pair_id: PairId([byte; 16]),
        }
    }

    async fn waiting(
        probes: &Probes,
        id: TransferId,
        asked: TransferOwner,
    ) -> oneshot::Receiver<Answer> {
        let (reply, answered) = oneshot::channel();
        probes.0.lock().await.insert(id, (asked, reply));
        answered
    }

    #[test]
    fn probe_ids_never_collide_with_transfer_ids() {
        assert!(!is_probe(TransferId(1)));
        assert!(!is_probe(TransferId(PROBE_ID_BIT - 1)));
        assert!(is_probe(TransferId(PROBE_ID_BIT | 1)));
    }

    /// The fix for the leftover empty file: the host's refusal reaches the
    /// frontend before any Save dialog has been opened.
    #[tokio::test]
    async fn a_refusal_carries_the_hosts_reason() {
        let probes = Probes::default();
        let id = TransferId(PROBE_ID_BIT | 7);
        let answered = waiting(&probes, id, owner(1)).await;

        let reason = "cannot open C:\\Users\\me\\missing.txt: not found".to_string();
        answer(&probes, id, owner(1), Err(reason.clone()), None).await;

        assert_eq!(answered.await.unwrap(), Err(reason));
        assert!(probes.0.lock().await.is_empty());
    }

    #[tokio::test]
    async fn the_first_chunk_accepts_and_stops_the_hosts_stream() {
        let probes = Probes::default();
        let id = TransferId(PROBE_ID_BIT | 8);
        let answered = waiting(&probes, id, owner(2)).await;
        let (link, mut sent) = mpsc::channel(4);

        answer(&probes, id, owner(2), Ok(()), Some(&link)).await;

        assert_eq!(answered.await.unwrap(), Ok(()));
        match tokio::time::timeout(Duration::from_secs(5), sent.recv()).await {
            Ok(Some(Frame::FileErr { id: cancelled, .. })) => assert_eq!(cancelled, id),
            other => panic!("expected the stream to be cancelled, got {other:?}"),
        }
    }

    /// Chunks already in flight when the probe was settled must neither answer
    /// again nor send the host another cancel.
    #[tokio::test]
    async fn late_frames_of_a_settled_probe_are_dropped() {
        let probes = Probes::default();
        let id = TransferId(PROBE_ID_BIT | 9);
        let (link, mut sent) = mpsc::channel(4);

        answer(&probes, id, owner(3), Ok(()), Some(&link)).await;
        tokio::task::yield_now().await;

        assert!(sent.try_recv().is_err());
    }

    #[tokio::test]
    async fn another_host_cannot_answer_a_probe() {
        let probes = Probes::default();
        let id = TransferId(PROBE_ID_BIT | 10);
        let mut answered = waiting(&probes, id, owner(4)).await;

        answer(&probes, id, owner(5), Ok(()), None).await;

        assert!(
            answered.try_recv().is_err(),
            "a different pairing settled it"
        );
        assert!(probes.0.lock().await.contains_key(&id));
    }
}
