use std::time::Duration;

use alloy::primitives::Address;
use eyre::Result;
use futures::future::join_all;
use reqwest::{Client, ClientBuilder};
use tokio::{sync::mpsc::Sender, time::sleep};
use tracing::{info, warn};
use url::Url;

use crate::SequencerCommitment;

pub fn start(urls: Vec<Url>, signer: Address, chain_id: u64, sender: Sender<SequencerCommitment>) {
    tokio::spawn(async move {
        let client = ClientBuilder::new()
            .timeout(Duration::from_millis(500))
            .build()
            .unwrap();

        // Replicas are verified lazily and retried every iteration. Checking
        // once at startup dropped a replica for the life of the process
        // whenever that single 500ms request failed (e.g. the Service had no
        // ready endpoints yet during a node replacement), leaving the pod on
        // gossip alone and serving `null` for hours.
        let mut pending: Vec<Url> = urls;
        let mut verified: Vec<Url> = Vec::new();
        let mut warned = false;

        loop {
            if !pending.is_empty() {
                let mut still_pending = Vec::new();
                for url in pending {
                    match get_chain_id(&client, &url).await {
                        Ok(replica_chain_id) if replica_chain_id == chain_id => {
                            info!("replica verified: {}", url);
                            verified.push(url);
                        }
                        Ok(_) => warn!("received bad chain id from {}", url),
                        Err(_) => {
                            if !warned {
                                warn!("received no chain id from {}, will retry", url);
                            }
                            still_pending.push(url);
                        }
                    }
                }
                warned = !still_pending.is_empty();
                pending = still_pending;
            }

            join_all(
                verified
                    .iter()
                    .map(|url| get_commitment(&client, url, sender.clone(), signer, chain_id)),
            )
            .await;
            sleep(Duration::from_millis(500)).await;
        }
    });
}

async fn get_commitment(
    client: &Client,
    url: &Url,
    sender: Sender<SequencerCommitment>,
    signer: Address,
    chain_id: u64,
) -> Result<()> {
    let commitment = client
        .get(url.join("latest")?)
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
