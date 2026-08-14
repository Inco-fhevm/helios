use std::{marker::PhantomData, sync::Arc};

use alloy::{
    eips::BlockId,
    primitives::{Address, B256, U256},
    rpc::types::{Filter, ValueOrArray},
};
use async_trait::async_trait;
use eyre::{eyre, Result};
use reqwest::{self, Response};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};
use serde::de::DeserializeOwned;
#[cfg(not(target_arch = "wasm32"))]
use tokio::time::Duration;
use url::Url;

use helios_common::network_spec::NetworkSpec;
use helios_verifiable_api_types::*;

use super::VerifiableApi;

#[derive(Clone)]
pub struct HttpVerifiableApi<N: NetworkSpec> {
    client: Arc<ClientWithMiddleware>,
    base_url: Url,
    phantom: PhantomData<N>,
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N: NetworkSpec> VerifiableApi<N> for HttpVerifiableApi<N> {
    fn new(base_url: &Url) -> Self {
        let builder = reqwest::ClientBuilder::default();

        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder
            // Keep 30 connections ready per host
            .pool_max_idle_per_host(30)
            // Disable idle timeout - keep connections indefinitely
            .pool_idle_timeout(None)
            // Aggressive TCP keepalive
            .tcp_keepalive(Some(Duration::from_secs(30)))
            // HTTP/2 specific settings
            .http2_keep_alive_interval(Some(Duration::from_secs(30)))
            .http2_keep_alive_timeout(Duration::from_secs(30))
            .http2_keep_alive_while_idle(true)
            // Flow-control windows. hyper defaults to 64 KiB per stream AND
            // 64 KiB per CONNECTION. getExecutionHint returns ~134 KB of account
            // and storage proofs, so a single response cannot fit in one window:
            // the sender stalls until the reader drains and emits WINDOW_UPDATE,
            // costing a round trip each time. At concurrency 16 every stream also
            // shares that one 64 KiB connection window, so they starve each other.
            // Measured effect: 134 KB bodies taking 261 ms at p50 and 6026 ms at
            // worst -- 0.02 MB/s, which is stalling, not transfer.
            // Sized so a whole hint response fits in one window with room for
            // many concurrent streams.
            .http2_initial_stream_window_size(8 * 1024 * 1024)
            .http2_initial_connection_window_size(32 * 1024 * 1024)
            // Escape hatch for the h2 multiplexing hypothesis.
            //
            // Measured from the TDX VM against the same host and path: 16 CONCURRENT
            // HTTP/1.1 requests each moved a 28KB body in ~18ms (wall 192ms for all
            // 16, no degradation from 1 -> 8 -> 16). helios needs ~1700ms for a 40KB
            // hint body over h2. Payload size, bandwidth and concurrency are
            // therefore all ruled out; the remaining difference is that h2
            // multiplexes every request onto ONE connection, and the window sizes
            // set above only govern traefik -> client, while traefik re-originates
            // h2 to the verifiable-api with its own windows.
            //
            // Setting VAPI_FORCE_HTTP1 turns the request pattern into the one that
            // was measured fast, which either reproduces that or kills the
            // hypothesis outright. Kept as a flag, not a default, because h1 costs
            // a connection per in-flight request.
            // Prevent connection closure
            .tcp_nodelay(true)
            // Fast decompression
            .brotli(true)
            // Faster DNS resolution
            .hickory_dns(true);
        // Upstream calls .http2_prior_knowledge() here. Prior knowledge means
        // "skip negotiation, assume h2", so behind a TLS terminator that picks
        // the protocol by ALPN the server can still answer HTTP/1.1; the client
        // then reads "HTTP/1.1 200 OK" as an h2 frame header, derives a nonsense
        // length and tears the connection down:
        //   h2::proto::connection  error=GoAway(FRAME_SIZE_ERROR, Library)
        //   hyper_util::client::legacy::client: client connection error
        // Observed against Traefik on base-sepolia.core.internal.inco.org --
        // every verifiable-api call failed there while plain HTTP/1.1 to the
        // same URL returned 200. Without it ALPN negotiates: h2 when the peer
        // offers it (Traefik does), HTTP/1.1 otherwise. The h2 keep-alive and
        // pooling settings above still apply once h2 is negotiated.

        #[cfg(not(target_arch = "wasm32"))]
        let builder = if std::env::var("VAPI_FORCE_HTTP1").is_ok_and(|v| !v.is_empty()) {
            tracing::warn!("VAPI_FORCE_HTTP1 set: forcing HTTP/1.1 to the verifiable-api");
            builder.http1_only()
        } else {
            builder
        };

        let client = builder.build().expect("Failed to build HTTP client");

        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(3);
        let client = Arc::new(
            ClientBuilder::new(client)
                // Retry outermost: it wraps the attempts, so its backoff gaps
                // fall between the attempt spans rather than inside one.
                .with(RetryTransientMiddleware::new_with_policy(retry_policy))
                // One span per ATTEMPT, so per-attempt status and the backoff
                // gaps are visible instead of hidden in one long client span.
                .with(crate::trace::AttemptSpanMiddleware)
                // Injection must be INSIDE the attempt span, not outside it.
                // Registered before AttemptSpanMiddleware it ran first, so the
                // traceparent carried the CALLER's span (helios.vapi_get_account)
                // and traefik + the verifiable-api server became siblings of the
                // attempt instead of its children -- measured: 237 attempts, 237
                // server spans, and only 1 attempt with any child. Same trace, so
                // nothing was lost, but the per-attempt split could not be
                // computed by parentage. Injecting here parents each server span
                // to the attempt that caused it.
                .with(crate::trace::TraceInjectMiddleware)
                .build(),
        );

        #[cfg(not(target_arch = "wasm32"))]
        {
            let client_ref = client.clone();
            let base_url_str = base_url.to_string();
            tokio::spawn(async move {
                loop {
                    _ = client_ref.head(&base_url_str).send().await;
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            });
        }

        Self {
            client,
            base_url: base_url.clone(),
            phantom: PhantomData,
        }
    }

    async fn get_account(
        &self,
        address: Address,
        storage_slots: &[U256],
        block_id: Option<BlockId>,
        include_code: bool,
    ) -> Result<AccountResponse> {
        let url = self
            .base_url
            .join(&format!("eth/v1/proof/account/{address}"))
            .map_err(|e| eyre!("Failed to construct account URL: {}", e))?;
        let mut request = self.client.get(url.as_str());
        if let Some(block_id) = block_id {
            request = request.query(&[("block", block_id)]);
        }
        for slot in storage_slots {
            request = request.query(&[("storageSlots", slot)]);
        }
        request = request.query(&[("includeCode", include_code)]);
        let response = request.send().await?;
        handle_response(response).await
    }

    async fn get_transaction_receipt(
        &self,
        tx_hash: B256,
    ) -> Result<Option<TransactionReceiptResponse<N>>> {
        let url = self
            .base_url
            .join(&format!("eth/v1/proof/receipt/{tx_hash}"))
            .map_err(|e| eyre!("Failed to construct receipt URL: {}", e))?;
        let response = self.client.get(url.as_str()).send().await?;
        handle_response(response).await
    }

    async fn get_transaction(&self, tx_hash: B256) -> Result<Option<TransactionResponse<N>>> {
        let url = self
            .base_url
            .join(&format!("eth/v1/proof/transaction/{tx_hash}"))
            .map_err(|e| eyre!("Failed to construct transaction URL: {}", e))?;
        let response = self.client.get(url.as_str()).send().await?;
        handle_response(response).await
    }

    async fn get_transaction_by_location(
        &self,
        block_id: BlockId,
        index: u64,
    ) -> Result<Option<TransactionResponse<N>>> {
        let url = self
            .base_url
            .join(&format!(
                "eth/v1/proof/transaction/{}/{}",
                serialize_block_id(block_id),
                index
            ))
            .map_err(|e| eyre!("Failed to construct transaction by location URL: {}", e))?;
        let response = self.client.get(url.as_str()).send().await?;
        handle_response(response).await
    }

    async fn get_logs(&self, filter: &Filter) -> Result<LogsResponse<N>> {
        let url = self
            .base_url
            .join("eth/v1/proof/logs")
            .map_err(|e| eyre!("Failed to construct logs URL: {}", e))?;

        let mut request = self.client.get(url.as_str());
        if let Some(from_block) = filter.get_from_block() {
            request = request.query(&[("fromBlock", U256::from(from_block))]);
        }
        if let Some(to_block) = filter.get_to_block() {
            request = request.query(&[("toBlock", U256::from(to_block))]);
        }
        if let Some(block_hash) = filter.get_block_hash() {
            request = request.query(&[("blockHash", block_hash)]);
        }
        if let Some(address) = filter.address.to_value_or_array() {
            match address {
                ValueOrArray::Value(address) => {
                    request = request.query(&[("address", address)]);
                }
                ValueOrArray::Array(addresses) => {
                    for address in addresses {
                        request = request.query(&[("address", address)]);
                    }
                }
            }
        }
        for idx in 0..=3 {
            if let Some(topics) = filter.topics[idx].to_value_or_array() {
                match topics {
                    ValueOrArray::Value(topic) => {
                        request = request.query(&[(format!("topic{idx}"), topic)]);
                    }
                    ValueOrArray::Array(topics) => {
                        for topic in topics {
                            request = request.query(&[(format!("topic{idx}"), topic)]);
                        }
                    }
                }
            }
        }

        let response = request.send().await?;
        handle_response(response).await
    }

    async fn get_execution_hint(
        &self,
        tx: N::TransactionRequest,
        validate_tx: bool,
        block_id: Option<BlockId>,
    ) -> Result<ExtendedAccessListResponse> {
        let url = self
            .base_url
            .join("eth/v1/proof/getExecutionHint")
            .map_err(|e| eyre!("Failed to construct execution hint URL: {}", e))?;
        // One span covering the whole logical call: request build, send, retries,
        // body read and deserialise. vapi.http_attempt ends at response HEADERS
        // and there is one per retry, so no single span showed end-to-end client
        // cost -- it had to be reassembled from to_headers_ms + body_ms + parse_ms
        // every time, and any time outside those three was invisible. This is the
        // number to compare against the server's handler_ms.
        use tracing::Instrument;
        async {
            let response = self
                .client
                .post(url.as_str())
                .json(&ExtendedAccessListRequest::<N> {
                    tx,
                    validate_tx,
                    block: block_id,
                })
                .send()
                .await?;
            handle_response(response).await
        }
        .instrument(tracing::info_span!(
            "vapi.total_request",
            http.path = "/eth/v1/proof/getExecutionHint"
        ))
        .await
    }

    async fn chain_id(&self) -> Result<ChainIdResponse> {
        let url = self
            .base_url
            .join("eth/v1/chainId")
            .map_err(|e| eyre!("Failed to construct chain ID URL: {}", e))?;
        let response = self.client.get(url.as_str()).send().await?;
        handle_response(response).await
    }

    async fn get_block(
        &self,
        block_id: BlockId,
        full_tx: bool,
    ) -> Result<Option<N::BlockResponse>> {
        let url = self
            .base_url
            .join(&format!("eth/v1/block/{}", serialize_block_id(block_id)))
            .map_err(|e| eyre!("Failed to construct block URL: {}", e))?;

        let request = self
            .client
            .get(url.as_str())
            .query(&[("transactionDetailFlag", full_tx)]);

        let response = request.send().await?;

        handle_response(response).await
    }

    async fn get_block_receipts(
        &self,
        block_id: BlockId,
    ) -> Result<Option<Vec<N::ReceiptResponse>>> {
        let url = self
            .base_url
            .join(&format!(
                "eth/v1/block/{}/receipts",
                serialize_block_id(block_id)
            ))
            .map_err(|e| eyre!("Failed to construct block receipts URL: {}", e))?;
        let response = self.client.get(url.as_str()).send().await?;
        handle_response(response).await
    }

    async fn send_raw_transaction(&self, bytes: &[u8]) -> Result<SendRawTxResponse> {
        let url = self
            .base_url
            .join("eth/v1/sendRawTransaction")
            .map_err(|e| eyre!("Failed to construct send transaction URL: {}", e))?;
        let response = self
            .client
            .post(url.as_str())
            .json(&SendRawTxRequest {
                bytes: bytes.to_vec(),
            })
            .send()
            .await?;
        handle_response(response).await
    }
}

async fn handle_response<T: DeserializeOwned>(mut response: Response) -> Result<T> {
    // Runs AFTER vapi.http_attempt has closed -- that span ends when the
    // middleware chain returns, which is at response headers. Body transfer and
    // parsing therefore land outside every span we have, in time charged to the
    // caller (helios.vapi_get_account).
    //
    // Spans created in this file have never appeared in Tempo while spans from
    // trace.rs always do, and that is unexplained. So the timings are emitted as
    // EVENTS as well: an event attaches to whatever span is current -- here
    // helios.vapi_get_account, which does export -- and carries the same
    // numbers. The spans stay so they start working the moment the underlying
    // cause is found; the events mean the measurement does not wait for it.
    use tracing::Instrument;
    let status = response.status();
    if status.is_success() {
        let t0 = std::time::Instant::now();
        // Read chunk by chunk instead of response.bytes(), so a slow body is
        // attributable. response.bytes() is one opaque await: a 6-second read of
        // a 134 KB payload looks identical whether the server is slow to send,
        // the link is slow, or HTTP/2 flow control is stalling the sender
        // between WINDOW_UPDATEs. Time-to-first-chunk separates "waiting for the
        // server" from "transfer", and the largest inter-chunk gap is the
        // signature of a flow-control stall -- it shows up as a handful of long
        // pauses rather than uniformly slow throughput.
        let (bytes, first_chunk_ms, chunks, max_stall_ms) = async {
            let mut buf: Vec<u8> = Vec::with_capacity(256 * 1024);
            let mut first_chunk_ms = 0.0f64;
            let mut chunks = 0u32;
            let mut max_stall_ms = 0.0f64;
            let mut last = std::time::Instant::now();
            while let Some(chunk) = response.chunk().await? {
                let gap = last.elapsed().as_secs_f64() * 1000.0;
                if chunks == 0 {
                    first_chunk_ms = gap;
                } else if gap > max_stall_ms {
                    max_stall_ms = gap;
                }
                chunks += 1;
                buf.extend_from_slice(&chunk);
                last = std::time::Instant::now();
            }
            Ok::<_, reqwest::Error>((buf, first_chunk_ms, chunks, max_stall_ms))
        }
        .instrument(tracing::info_span!("vapi.body_read"))
        .await?;
        let body_ms = t0.elapsed().as_secs_f64() * 1000.0;

        let t1 = std::time::Instant::now();
        let out = {
            let span = tracing::info_span!("vapi.deserialize", bytes = bytes.len());
            let _g = span.enter(); // sync, no await inside -- safe to enter
            serde_json::from_slice(&bytes)
        };
        let parse_ms = t1.elapsed().as_secs_f64() * 1000.0;

        tracing::info!(
            body_ms,
            parse_ms,
            bytes = bytes.len(),
            first_chunk_ms,
            chunks,
            max_stall_ms,
            "vapi body read and parsed"
        );
        Ok(out?)
    } else {
        // The status alone was never enough: 26x 500 on /eth/v1/proof/account
        // and 19x 400 on getExecutionHint were measured in one 240-request run,
        // 25% of all attempts, with no indication of why. Read the body as text
        // first so the reason survives even when it is not the expected
        // ErrorResponse shape, then parse.
        let t0 = std::time::Instant::now();
        let text = async { response.text().await }
            .instrument(tracing::info_span!("vapi.body_read_err"))
            .await?;
        let body_ms = t0.elapsed().as_secs_f64() * 1000.0;

        let detail: String = text.chars().take(300).collect();
        tracing::warn!(
            http.status = status.as_u16(),
            body_ms,
            error_body = %detail,
            "vapi returned an error"
        );

        match serde_json::from_str::<ErrorResponse>(&text) {
            Ok(er) => Err(eyre!(er.error.to_string())),
            Err(_) => Err(eyre!("vapi {}: {}", status.as_u16(), detail)),
        }
    }
}

fn serialize_block_id(block_id: BlockId) -> String {
    match block_id {
        BlockId::Hash(hash) => hash.block_hash.to_string(),
        BlockId::Number(number) => serde_json::to_string(&number)
            .expect("Failed to serialize block number")
            .trim_matches('"')
            .to_string(),
    }
}
