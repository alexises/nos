//! Chunked, in-place import-policy re-evaluation for peers with soft
//! reconfiguration inbound (#859). The RIB lock is released between chunks so
//! UPDATEs interleave; see `docs/protocols/bgp-internals.md`.

use super::{info, Arc, Instant, IpAddr, PeerSlot, SessionManager};
use crate::collision::{ReevalResult, REEVAL_MAX_PREFIX, REEVAL_SESSION_DOWN};
use crate::rib::{ChunkOutcome, REEVAL_CHUNK};
use tokio::sync::oneshot;

impl SessionManager {
    /// Starts (or, for a `soft-in` waiter, joins) a pass for `slot`. A policy
    /// change or flag enable `supersede`s a running one.
    pub(super) fn start_reeval(
        self: &Arc<Self>,
        slot: Arc<PeerSlot>,
        supersede: bool,
        waiter: Option<oneshot::Sender<ReevalResult>>,
    ) {
        let Some(generation) = slot.reeval_begin(supersede, waiter) else {
            return;
        };
        let this = self.clone();
        tokio::spawn(async move { this.run_reeval(slot, generation).await });
    }

    /// `clear bgp ... soft-in` on a flagged, established peer: re-evaluates
    /// the retained routes locally and waits for the pass. `None`: not
    /// applicable, the caller sends a Route Refresh instead.
    pub async fn soft_in_local(self: &Arc<Self>, peer: IpAddr) -> Option<ReevalResult> {
        let slot = self.peers.read().await.get(&peer).cloned()?;
        if !slot.soft_reconfig() || !slot.is_established().await {
            return None;
        }
        let (tx, rx) = oneshot::channel();
        self.start_reeval(slot, false, Some(tx));
        Some(rx.await.unwrap_or_else(|_| Err("aborted".into())))
    }

    async fn run_reeval(self: Arc<Self>, slot: Arc<PeerSlot>, generation: u64) {
        let peer = slot.peer.remote_address;
        let started = Instant::now();
        let mut chunks = 0u32;
        let begun = self
            .bgp_rib
            .lock()
            .await
            .begin_reevaluation(peer, slot.import_policies());
        let Some(mut pass) = begun else {
            return Self::abort_reeval(&slot, generation, peer, "disabled");
        };
        let reason = loop {
            let step = {
                let mut rib = self.bgp_rib.lock().await;
                if !slot.reeval_current(generation) {
                    // Superseded: the new pass owns the waiters.
                    return;
                }
                let outcome = rib.reevaluate_chunk(&mut pass, REEVAL_CHUNK);
                chunks += 1;
                let trip = (outcome != ChunkOutcome::Gone)
                    .then(|| rib.check_max_prefix(peer))
                    .flatten();
                (outcome, trip)
            };
            match step {
                (ChunkOutcome::Gone, _) => break Some(REEVAL_SESSION_DOWN),
                (_, Some((family, limit, _))) => {
                    if !slot.max_prefix_held() {
                        crate::fsm::trip_max_prefix(&slot, family, limit);
                    }
                    break Some(REEVAL_MAX_PREFIX);
                }
                (ChunkOutcome::Done, None) => break None,
                (ChunkOutcome::More, None) => {
                    tracing::debug!(peer = %peer, chunks, "soft reconfiguration: re-evaluation chunk done");
                    tokio::task::yield_now().await;
                }
            }
        };
        if let Some(reason) = reason {
            return Self::abort_reeval(&slot, generation, peer, reason);
        }
        pass.log();
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        info!(peer = %peer, chunks, elapsed_ms, "soft reconfiguration: re-evaluation finished");
        slot.reeval_finish(generation, &Ok(pass.families()));
    }

    fn abort_reeval(slot: &PeerSlot, generation: u64, peer: IpAddr, reason: &str) {
        info!(peer = %peer, reason, "soft reconfiguration: re-evaluation aborted");
        slot.reeval_finish(generation, &Err(reason.to_string()));
    }
}
