use std::{net::SocketAddr, sync::Arc, time::Duration};

use alloy::primitives::Address;
use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use eyre::Result;
use serde::Deserialize;
use tokio::sync::{
    mpsc::{channel, Receiver},
    watch, RwLock,
};
use url::Url;

use crate::{types::ExecutionPayload, SequencerCommitment};

use self::net::{block_handler::BlockHandler, gossip::GossipService};

pub mod net;
mod poller;

pub async fn start_server(
    server_addr: SocketAddr,
    gossip_addr: SocketAddr,
    chain_id: u64,
    signer: Address,
    replica_urls: Vec<Url>,
) -> Result<()> {
    // Anything waiting on a new commitment parks here instead of re-asking:
    // the /latest?after= handlers, and the replica poller building its own
    // `after`. Created before ServerState so the poller can take a receiver.
    let (head_send, head_recv) = watch::channel::<Option<(SequencerCommitment, u64)>>(None);

    let (state, mut commitment_recv) = ServerState::new(
        gossip_addr,
        chain_id,
        signer,
        replica_urls,
        head_recv.clone(),
    )?;
    let state = Arc::new(RwLock::new(state));

    let app = AppState {
        chain_id,
        head: head_recv,
    };

    let state_copy = state.clone();
    let head_send = Arc::new(head_send);
    let head_send_task = head_send.clone();
    let _handle = tokio::spawn(async move {
        // Upstream ran this as `loop { state.write().await.update(); sleep(1s) }`
        // -- a timer draining a channel that libp2p gossip already wakes. It had
        // to: the Receiver lived inside the RwLock, so awaiting recv() would have
        // held the write lock across the await and blocked every /latest reader
        // until the next block. try_recv + sleep was the workaround, and it cost
        // a mean 500ms on every block.
        //
        // Moving the receiver out of the lock removes the reason for the timer.
        // We now block on the push and take the write lock only once a
        // commitment has actually arrived, so /latest is never held for longer
        // than the store itself.
        while let Some(commitment) = commitment_recv.recv().await {
            if let Some(newest) = state_copy.write().await.apply(commitment) {
                // Wakes every parked /latest?after= request immediately.
                head_send_task.send_replace(Some(newest));
            }
        }
        tracing::warn!("commitment channel closed; server will stop advancing");
    });

    let router = Router::new()
        .route("/latest", get(latest_handler))
        .route("/chain_id", get(chain_id_handler))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind(server_addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

#[derive(Clone)]
struct AppState {
    chain_id: u64,
    head: watch::Receiver<Option<(SequencerCommitment, u64)>>,
}

#[derive(Deserialize)]
struct LatestQuery {
    /// Block number the caller already has. When present the request is held
    /// until a strictly newer commitment exists, so the caller never polls.
    after: Option<u64>,
}

/// Upper bound on how long one held request may live. This is a connection
/// lifetime cap, not a poll interval: it exists so a client that vanishes does
/// not pin a task forever. In steady state the watch fires long before it.
const HOLD_MAX: Duration = Duration::from_secs(60);

async fn latest_handler(
    State(state): State<AppState>,
    Query(q): Query<LatestQuery>,
) -> Json<Option<SequencerCommitment>> {
    let mut head = state.head.clone();

    // No `after` -> classic immediate read, so existing clients are unaffected.
    let Some(after) = q.after else {
        return Json(head.borrow().clone().map(|v| v.0));
    };

    let wait = async {
        loop {
            if let Some((commitment, number)) = head.borrow_and_update().clone() {
                if number > after {
                    return Some(commitment);
                }
            }
            if head.changed().await.is_err() {
                return None;
            }
        }
    };

    match tokio::time::timeout(HOLD_MAX, wait).await {
        Ok(Some(commitment)) => Json(Some(commitment)),
        // Timed out or sender gone: hand back whatever we have rather than erroring.
        _ => Json(head.borrow().clone().map(|v| v.0)),
    }
}

async fn chain_id_handler(State(state): State<AppState>) -> Json<u64> {
    Json(state.chain_id)
}

/// Holds only the last commitment. chain_id lives on AppState, which is what
/// the handlers read; keeping a second copy here just went stale.
struct ServerState {
    latest_commitment: Option<(SequencerCommitment, u64)>,
}

impl ServerState {
    /// Returns the state and the commitment receiver *separately*.
    ///
    /// The receiver deliberately does not live in the struct: the struct sits
    /// behind an RwLock, and awaiting recv() while holding that lock would
    /// block every /latest reader until the next block arrived. Keeping it
    /// outside lets the caller await the gossip push with no lock held.
    pub fn new(
        addr: SocketAddr,
        chain_id: u64,
        signer: Address,
        replica_urls: Vec<Url>,
        head: watch::Receiver<Option<(SequencerCommitment, u64)>>,
    ) -> Result<(Self, Receiver<SequencerCommitment>)> {
        let (send, commitment_recv) = channel(256);
        poller::start(replica_urls, signer, chain_id, send.clone(), head);
        let handler = BlockHandler::new(signer, chain_id, send);
        let gossip = GossipService::new(addr, chain_id, handler);
        gossip.start()?;

        Ok((
            Self {
                latest_commitment: None,
            },
            commitment_recv,
        ))
    }

    /// Store one commitment. Called once per gossip push, with the write lock
    /// held only for the duration of this call. Returns the stored pair when
    /// this commitment advanced the head, so the caller can wake waiters.
    pub fn apply(&mut self, commitment: SequencerCommitment) -> Option<(SequencerCommitment, u64)> {
        let payload = ExecutionPayload::try_from(&commitment).ok()?;
        if !self.is_latest_commitment(payload.block_number) {
            return None;
        }
        tracing::info!("new commitment for block: {}", payload.block_number);
        let stored = (commitment, payload.block_number);
        self.latest_commitment = Some(stored.clone());
        Some(stored)
    }

    fn is_latest_commitment(&self, block_number: u64) -> bool {
        if let Some((_, latest_block_number)) = self.latest_commitment {
            block_number > latest_block_number
        } else {
            true
        }
    }
}
