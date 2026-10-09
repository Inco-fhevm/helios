use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::primitives::Address;
use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use eyre::Result;
use serde::Serialize;
use tokio::{
    sync::{
        mpsc::{channel, Receiver},
        RwLock,
    },
    time::sleep,
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
    let state = Arc::new(RwLock::new(ServerState::new(
        gossip_addr,
        chain_id,
        signer,
        replica_urls,
    )?));

    let state_copy = state.clone();
    let _handle = tokio::spawn(async move {
        loop {
            state_copy.write().await.update();
            sleep(Duration::from_secs(1)).await;
        }
    });

    let router = Router::new()
        .route("/latest", get(latest_handler))
        .route("/chain_id", get(chain_id_handler))
        .route("/healthz", get(healthz_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(server_addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

async fn latest_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Json<Option<SequencerCommitment>> {
    Json(state.read().await.latest_commitment.clone().map(|v| v.0))
}

/// Max age of the served head before `/healthz` reports unhealthy. Base
/// produces a block every 2s, so 30s is ~15 missed blocks. Consumers (helios
/// light clients) reject heads older than 60s, so this trips first.
const MAX_HEAD_AGE: Duration = Duration::from_secs(30);

#[derive(Serialize)]
struct Health {
    healthy: bool,
    block_number: Option<u64>,
    head_age_secs: Option<u64>,
}

/// Readiness endpoint: 200 only while this replica serves a fresh head, 503
/// otherwise (no commitment yet, or the newest one is older than
/// MAX_HEAD_AGE). `/chain_id` answers as soon as the HTTP server is up, so
/// gating readiness on it keeps replicas that serve `null` in rotation.
async fn healthz_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> (StatusCode, Json<Health>) {
    let head = state
        .read()
        .await
        .latest_commitment
        .as_ref()
        .map(|(_, block_number, timestamp)| (*block_number, *timestamp));

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let health = compute_health(head, now);

    let status = if health.healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(health))
}

/// `head` is (block number, block timestamp) of the served commitment.
fn compute_health(head: Option<(u64, u64)>, now: u64) -> Health {
    match head {
        Some((block_number, timestamp)) => {
            let age = now.saturating_sub(timestamp);
            Health {
                healthy: age <= MAX_HEAD_AGE.as_secs(),
                block_number: Some(block_number),
                head_age_secs: Some(age),
            }
        }
        None => Health {
            healthy: false,
            block_number: None,
            head_age_secs: None,
        },
    }
}

async fn chain_id_handler(State(state): State<Arc<RwLock<ServerState>>>) -> Json<u64> {
    Json(state.read().await.chain_id)
}

struct ServerState {
    chain_id: u64,
    commitment_recv: Receiver<SequencerCommitment>,
    /// (commitment, block number, block timestamp)
    latest_commitment: Option<(SequencerCommitment, u64, u64)>,
}

impl ServerState {
    pub fn new(
        addr: SocketAddr,
        chain_id: u64,
        signer: Address,
        replica_urls: Vec<Url>,
    ) -> Result<Self> {
        let (send, commitment_recv) = channel(256);
        poller::start(replica_urls, signer, chain_id, send.clone());
        let handler = BlockHandler::new(signer, chain_id, send);
        let gossip = GossipService::new(addr, chain_id, handler);
        gossip.start()?;

        Ok(Self {
            chain_id,
            commitment_recv,
            latest_commitment: None,
        })
    }

    pub fn update(&mut self) {
        while let Ok(commitment) = self.commitment_recv.try_recv() {
            if let Ok(payload) = ExecutionPayload::try_from(&commitment) {
                if self.is_latest_commitment(payload.block_number) {
                    tracing::info!("new commitment for block: {}", payload.block_number);
                    self.latest_commitment =
                        Some((commitment, payload.block_number, payload.timestamp));
                }
            }
        }
    }

    fn is_latest_commitment(&self, block_number: u64) -> bool {
        if let Some((_, latest_block_number, _)) = self.latest_commitment {
            block_number > latest_block_number
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_requires_a_head() {
        let h = compute_health(None, 1_000);
        assert!(!h.healthy);
        assert_eq!(h.block_number, None);
    }

    #[test]
    fn health_tracks_head_age() {
        let fresh = compute_health(Some((42, 1_000)), 1_000 + MAX_HEAD_AGE.as_secs());
        assert!(fresh.healthy);
        assert_eq!(fresh.block_number, Some(42));

        let stale = compute_health(Some((42, 1_000)), 1_001 + MAX_HEAD_AGE.as_secs());
        assert!(!stale.healthy);
        assert_eq!(stale.head_age_secs, Some(31));
    }

    #[test]
    fn health_tolerates_clock_skew() {
        // Head timestamp slightly ahead of the local clock reads as age 0.
        let h = compute_health(Some((42, 1_005)), 1_000);
        assert!(h.healthy);
        assert_eq!(h.head_age_secs, Some(0));
    }
}
