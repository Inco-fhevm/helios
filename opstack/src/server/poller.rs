use std::time::Duration;

use alloy::primitives::Address;
use eyre::Result;
use futures::future::join_all;
use reqwest::{Client, ClientBuilder};
use tokio::{
    net::lookup_host,
    sync::{mpsc::Sender, watch},
    time::{sleep, timeout},
};
use tracing::info;
use url::{Host, Url};

use crate::SequencerCommitment;

const POLL_INTERVAL: Duration = Duration::from_millis(500);
const RESOLVE_INTERVAL: Duration = Duration::from_secs(5);
const LOOKUP_TIMEOUT: Duration = Duration::from_millis(500);

/// Polls `/latest` on every replica twice a second and forwards each verified
/// commitment to the server.
///
/// An `http` replica URL whose host is a DNS name is resolved every
/// `RESOLVE_INTERVAL` by a separate task, and each address it returns is
/// polled on its own. Pointed at a headless Service, this reaches every
/// sibling pod, including pods started after this one. The poll loop reads
/// the latest target set on each tick, so a slow DNS lookup does not delay
/// a poll. A URL that does not resolve is polled as written.
///
/// There is no separate chain-id handshake: `SequencerCommitment::verify`
/// checks the sequencer signature over a message bound to `chain_id`, so a
/// commitment from another chain is rejected there.
pub fn start(urls: Vec<Url>, signer: Address, chain_id: u64, sender: Sender<SequencerCommitment>) {
    if urls.is_empty() {
        return;
    }

    let (targets_tx, mut targets_rx) = watch::channel(Vec::new());
    tokio::spawn(async move {
        loop {
            let targets = resolve_all(&urls).await;
            targets_tx.send_if_modified(|polled| {
                if *polled == targets {
                    return false;
                }
                let list: Vec<&str> = targets.iter().map(Url::as_str).collect();
                info!("polling replicas: {}", list.join(", "));
                *polled = targets;
                true
            });
            sleep(RESOLVE_INTERVAL).await;
        }
    });

    tokio::spawn(async move {
        let client = ClientBuilder::new()
            .timeout(Duration::from_millis(500))
            .build()
            .unwrap();

        loop {
            let polled = targets_rx.borrow_and_update().clone();
            join_all(
                polled
                    .iter()
                    .map(|url| get_commitment(&client, url, sender.clone(), signer, chain_id)),
            )
            .await;
            sleep(POLL_INTERVAL).await;
        }
    });
}

async fn resolve_all(urls: &[Url]) -> Vec<Url> {
    let mut targets = Vec::new();
    for url in urls {
        targets.extend(resolve(url).await);
    }
    targets.sort();
    targets.dedup();
    targets
}

/// Expands `url` into one URL per address its host resolves to. Only `http`
/// URLs are expanded: an `https` URL rewritten to an IP would fail TLS
/// hostname verification.
async fn resolve(url: &Url) -> Vec<Url> {
    let (Some(Host::Domain(name)), Some(port)) = (url.host(), url.port_or_known_default()) else {
        return vec![url.clone()];
    };
    if url.scheme() != "http" {
        return vec![url.clone()];
    }

    let Ok(Ok(addrs)) = timeout(LOOKUP_TIMEOUT, lookup_host((name, port))).await else {
        return vec![url.clone()];
    };
    let resolved: Vec<Url> = addrs
        .filter_map(|addr| {
            let mut target = url.clone();
            target.set_ip_host(addr.ip()).ok()?;
            Some(target)
        })
        .collect();

    if resolved.is_empty() {
        vec![url.clone()]
    } else {
        resolved
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[tokio::test]
    async fn ip_url_is_kept() {
        let u = url("http://10.0.0.7:8080/");
        assert_eq!(resolve(&u).await, vec![u]);
    }

    #[tokio::test]
    async fn https_url_is_kept() {
        let u = url("https://localhost:8080/");
        assert_eq!(resolve(&u).await, vec![u]);
    }

    #[tokio::test]
    async fn dns_name_expands_to_every_address() {
        let resolved = resolve(&url("http://localhost:8080/")).await;
        assert!(!resolved.is_empty());
        for target in &resolved {
            assert!(matches!(
                target.host(),
                Some(Host::Ipv4(_)) | Some(Host::Ipv6(_))
            ));
            assert_eq!(target.port(), Some(8080));
            assert_eq!(target.path(), "/");
        }
    }

    #[tokio::test]
    async fn unresolvable_name_is_kept() {
        let u = url("http://replica.invalid:8080/");
        assert_eq!(resolve(&u).await, vec![u]);
    }

    #[tokio::test]
    async fn targets_are_deduplicated() {
        let u = url("http://10.0.0.7:8080/");
        assert_eq!(resolve_all(&[u.clone(), u.clone()]).await, vec![u]);
    }
}
