use std::{
    collections::{HashMap, HashSet},
    future::Future,
    io,
    net::SocketAddr,
    time::Duration,
};

use alloy::primitives::Address;
use eyre::Result;
use futures::future::join_all;
use reqwest::{Client, ClientBuilder};
use tokio::{
    net::lookup_host,
    sync::{mpsc::Sender, watch},
    time::{sleep, timeout},
};
use tracing::{info, warn};
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
/// a poll. When a lookup fails or times out, the last set that URL resolved
/// to stays in use. A URL that has never resolved is polled as written.
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
        let mut resolver = Resolver::new(system_lookup);
        loop {
            let targets = resolver.resolve_all(&urls).await;
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

async fn system_lookup(name: String, port: u16) -> io::Result<Vec<SocketAddr>> {
    Ok(lookup_host((name.as_str(), port)).await?.collect())
}

/// Expands replica URLs into one URL per address, and keeps the last
/// successful expansion of each URL for the ticks where its lookup fails.
struct Resolver<L> {
    lookup: L,
    last_good: HashMap<Url, Vec<Url>>,
    failing: HashSet<Url>,
}

impl<L, F> Resolver<L>
where
    L: Fn(String, u16) -> F,
    F: Future<Output = io::Result<Vec<SocketAddr>>>,
{
    fn new(lookup: L) -> Self {
        Self {
            lookup,
            last_good: HashMap::new(),
            failing: HashSet::new(),
        }
    }

    async fn resolve_all(&mut self, urls: &[Url]) -> Vec<Url> {
        let mut targets = Vec::new();
        for url in urls {
            targets.extend(self.resolve(url).await);
        }
        targets.sort();
        targets.dedup();
        targets
    }

    /// Only `http` URLs are expanded: an `https` URL rewritten to an IP
    /// would fail TLS hostname verification. An empty answer means that no
    /// sibling is ready, and it is used as is.
    async fn resolve(&mut self, url: &Url) -> Vec<Url> {
        let (Some(Host::Domain(name)), Some(port)) = (url.host(), url.port_or_known_default())
        else {
            return vec![url.clone()];
        };
        if url.scheme() != "http" {
            return vec![url.clone()];
        }

        let result = match timeout(LOOKUP_TIMEOUT, (self.lookup)(name.to_string(), port)).await {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "lookup timed out")),
        };
        match result {
            Ok(addrs) => {
                let resolved: Vec<Url> = addrs
                    .into_iter()
                    .filter_map(|addr| {
                        let mut target = url.clone();
                        target.set_ip_host(addr.ip()).ok()?;
                        Some(target)
                    })
                    .collect();
                if self.failing.remove(url) {
                    info!("replica lookup for {url} recovered");
                }
                self.last_good.insert(url.clone(), resolved.clone());
                resolved
            }
            Err(err) => {
                let cached = self.last_good.get(url).cloned();
                if self.failing.insert(url.clone()) {
                    match cached {
                        Some(_) => warn!(
                            "replica lookup for {url} failed: {err}; keeping the last resolved set"
                        ),
                        None => warn!(
                            "replica lookup for {url} failed: {err}; polling the URL as written"
                        ),
                    }
                }
                cached.unwrap_or_else(|| vec![url.clone()])
            }
        }
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
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use super::*;

    type Answers = Arc<Mutex<VecDeque<Option<io::Result<Vec<SocketAddr>>>>>>;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// Returns a lookup that gives the queued answers in order. `None`
    /// never completes, so the lookup deadline fires.
    fn scripted(
        answers: Vec<Option<io::Result<Vec<SocketAddr>>>>,
    ) -> impl Fn(String, u16) -> futures::future::BoxFuture<'static, io::Result<Vec<SocketAddr>>>
    {
        let answers: Answers = Arc::new(Mutex::new(answers.into()));
        move |_, _| {
            let next = answers
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected lookup");
            Box::pin(async move {
                match next {
                    Some(answer) => answer,
                    None => std::future::pending().await,
                }
            })
        }
    }

    fn failure() -> Option<io::Result<Vec<SocketAddr>>> {
        Some(Err(io::Error::other("no such host")))
    }

    #[tokio::test]
    async fn ip_and_https_urls_are_kept() {
        let mut resolver = Resolver::new(scripted(vec![]));
        let ip = url("http://10.0.0.7:8080/");
        let https = url("https://replicas.example:8080/");
        assert_eq!(resolver.resolve(&ip).await, vec![ip]);
        assert_eq!(resolver.resolve(&https).await, vec![https]);
    }

    #[tokio::test]
    async fn dns_name_expands_to_every_address() {
        let mut resolver = Resolver::new(scripted(vec![Some(Ok(vec![
            addr("10.0.0.1:8080"),
            addr("10.0.0.2:8080"),
        ]))]));
        assert_eq!(
            resolver
                .resolve(&url("http://replicas.example:8080/"))
                .await,
            vec![url("http://10.0.0.1:8080/"), url("http://10.0.0.2:8080/")]
        );
    }

    #[tokio::test]
    async fn failed_lookup_keeps_the_last_good_set() {
        let mut resolver = Resolver::new(scripted(vec![
            Some(Ok(vec![addr("10.0.0.1:8080"), addr("10.0.0.2:8080")])),
            failure(),
            failure(),
        ]));
        let u = url("http://replicas.example:8080/");
        let good = resolver.resolve(&u).await;
        assert_eq!(resolver.resolve(&u).await, good);
        assert_eq!(resolver.resolve(&u).await, good);
    }

    #[tokio::test]
    async fn timed_out_lookup_keeps_the_last_good_set() {
        let mut resolver =
            Resolver::new(scripted(vec![Some(Ok(vec![addr("10.0.0.1:8080")])), None]));
        let u = url("http://replicas.example:8080/");
        let good = resolver.resolve(&u).await;
        assert_eq!(resolver.resolve(&u).await, good);
    }

    #[tokio::test]
    async fn never_resolved_url_is_polled_as_written() {
        let mut resolver = Resolver::new(scripted(vec![failure()]));
        let u = url("http://replicas.example:8080/");
        assert_eq!(resolver.resolve(&u).await, vec![u]);
    }

    #[tokio::test]
    async fn empty_answer_is_used_as_is() {
        let mut resolver = Resolver::new(scripted(vec![
            Some(Ok(vec![addr("10.0.0.1:8080")])),
            Some(Ok(vec![])),
        ]));
        let u = url("http://replicas.example:8080/");
        resolver.resolve(&u).await;
        assert_eq!(resolver.resolve(&u).await, Vec::<Url>::new());
    }

    #[tokio::test]
    async fn targets_are_deduplicated() {
        let mut resolver = Resolver::new(scripted(vec![]));
        let u = url("http://10.0.0.7:8080/");
        assert_eq!(resolver.resolve_all(&[u.clone(), u.clone()]).await, vec![u]);
    }
}
