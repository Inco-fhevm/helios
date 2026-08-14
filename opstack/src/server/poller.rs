use std::time::Duration;

use alloy::primitives::Address;
use eyre::Result;
use reqwest::{Client, ClientBuilder};
use tokio::{
    sync::{mpsc::Sender, watch},
    time::sleep,
};
use tracing::warn;
use url::Url;

use crate::SequencerCommitment;

/// Backfill path: pick up commitments a peer replica saw and we missed on gossip.
///
/// This used to run as `loop { fetch all peers; sleep(500ms) }`, which put up to
/// 500ms on any block that arrived here rather than over gossip. Since /latest
/// now supports `?after=`, each fetch parks on the peer until the peer actually
/// has something newer than our head, so the round trip *is* the wait and there
/// is no timer in the steady state.
///
/// `head` is our own current head, used to build `after`. It is read fresh each
/// round, so once gossip advances us the next round asks for something newer.
pub fn start(
    urls: Vec<Url>,
    signer: Address,
    chain_id: u64,
    sender: Sender<SequencerCommitment>,
    head: watch::Receiver<Option<(SequencerCommitment, u64)>>,
) {
    tokio::spawn(async move {
        // Must exceed the peer's HOLD_MAX (60s) or every held request would be
        // torn down by our own timeout instead of returning a block.
        let client = ClientBuilder::new()
            .timeout(Duration::from_secs(65))
            .build()
            .unwrap();

        // The chain-id handshake is a normal short request, but it must not
        // inherit the long-poll timeout either. 5s, because a replica may be an
        // external endpoint over the public internet -- upstream's 500ms
        // silently rejected one that answered in ~520ms.
        let probe = ClientBuilder::new()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        // Upstream probed each URL exactly once, at startup, and dropped any
        // that failed -- permanently, because final_urls is never recomputed.
        // During a rolling restart the Service backing these URLs has no ready
        // endpoints, so every replica came up with an empty list and the
        // backfill path was dead for the lifetime of the process. Retry until
        // something answers.
        const PROBE_ATTEMPTS: usize = 10;
        const PROBE_GAP: Duration = Duration::from_secs(3);

        let mut final_urls = Vec::new();
        for attempt in 1..=PROBE_ATTEMPTS {
            for url in &urls {
                if final_urls.contains(url) {
                    continue;
                }
                match get_chain_id(&probe, url).await {
                    Ok(replica_chain_id) if replica_chain_id == chain_id => {
                        final_urls.push(url.clone());
                    }
                    Ok(_) => warn!("received bad chain id from {}", url),
                    Err(e) => warn!(
                        "no chain id from {} (attempt {}/{}): {}",
                        url, attempt, PROBE_ATTEMPTS, e
                    ),
                }
            }
            if final_urls.len() == urls.len() {
                break;
            }
            if attempt < PROBE_ATTEMPTS {
                sleep(PROBE_GAP).await;
            }
        }
        if final_urls.is_empty() {
            warn!("no usable replica URLs; backfill disabled, relying on gossip alone");
        }

        // One independent loop per peer. Upstream drove them with join_all,
        // which waits for the slowest -- fine when every peer answered
        // instantly, fatal now that a patched peer HOLDS the request until it
        // has a newer block. A single long-polling peer would stall the whole
        // round for up to its HOLD_MAX, starving the fast ones: observed 3
        // commitments in 2 minutes instead of one per block.
        for url in final_urls {
            let client = client.clone();
            let sender = sender.clone();
            let mut head = head.clone();
            tokio::spawn(async move {
                // Only fires when this peer answered without giving us anything
                // newer -- i.e. it predates `?after=` and replied instantly.
                // Stops a hot loop against an old build; never runs against a
                // patched peer, which simply holds the request instead.
                const NO_PROGRESS_BACKOFF: Duration = Duration::from_millis(200);
                loop {
                    let before = head.borrow_and_update().as_ref().map(|(_, n)| *n);
                    if let Err(e) =
                        get_commitment(&client, &url, sender.clone(), signer, chain_id, before).await
                    {
                        warn!("poll of {} failed: {}", url, e);
                        sleep(NO_PROGRESS_BACKOFF).await;
                        continue;
                    }
                    if head.borrow_and_update().as_ref().map(|(_, n)| *n) == before {
                        sleep(NO_PROGRESS_BACKOFF).await;
                    }
                }
            });
        }
    });
}

async fn get_commitment(
    client: &Client,
    url: &Url,
    sender: Sender<SequencerCommitment>,
    signer: Address,
    chain_id: u64,
    after: Option<u64>,
) -> Result<()> {
    let mut endpoint = url.join("latest")?;
    if let Some(after) = after {
        endpoint
            .query_pairs_mut()
            .append_pair("after", &after.to_string());
    }

    let commitment = client
        .get(endpoint)
        .send()
        .await?
        .json::<SequencerCommitment>()
        .await?;

    if commitment.verify(signer, chain_id).is_ok() {
        sender.send(commitment).await?;
    }

    Ok(())
}

async fn get_chain_id(client: &Client, url: &Url) -> Result<u64> {
    let chain_id = client
        .get(url.join("chain_id")?)
        .send()
        .await?
        .json::<u64>()
        .await?;

    Ok(chain_id)
}
