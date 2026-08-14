//! Prometheus metrics for the verifiable-api server.
//!
//! Why this exists: this server had no metrics endpoint at all. The only way to
//! get its latency distribution was to grep `tower_http` log lines, and that
//! number is misleading -- tower-http compresses the response body lazily, as it
//! is polled, which happens AFTER the handler has returned. So the handler's own
//! timing said "max 282ms" while callers were measuring seconds for the same
//! requests, and reconciling the two took a wrong turn through the client, the
//! network and the block cache before landing here.
//!
//! `request_duration` below is recorded in `response_timing_layer`, which
//! materialises the body first, so it includes the encode cost the handler span
//! cannot see. `encode_duration` isolates that cost on its own.

use std::sync::LazyLock;

use prometheus::{
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry, HistogramVec,
    IntCounterVec, Registry, TextEncoder,
};

pub static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

/// Full server-side time, body materialised. This is the number that should
/// match what a caller observes, minus the network.
pub static REQUEST_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        "vapi_request_duration_seconds",
        "Total server-side request time including response body encoding",
        &["path", "status"],
        // getExecutionHint is the slow one and the tail is what matters, so the
        // buckets run out to 8s rather than the default 10ms..10s spread.
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0],
        REGISTRY
    )
    .expect("register vapi_request_duration_seconds")
});

/// Time spent materialising (and therefore compressing) the response body.
/// Invisible to the handler span; this is where brotli quality shows up.
pub static ENCODE_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        "vapi_encode_duration_seconds",
        "Time to materialise and compress the response body, excluded from handler timing",
        &["path"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0],
        REGISTRY
    )
    .expect("register vapi_encode_duration_seconds")
});

/// Compressed response size. Pairs with encode_duration to tell "big payload"
/// apart from "slow compression".
pub static RESPONSE_BYTES: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        "vapi_response_bytes",
        "Compressed response size in bytes",
        &["path"],
        vec![1e3, 4e3, 16e3, 64e3, 128e3, 256e3, 512e3, 1e6],
        REGISTRY
    )
    .expect("register vapi_response_bytes")
});

pub static REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        "vapi_requests_total",
        "Requests served, by path and status class",
        &["path", "status"],
        REGISTRY
    )
    .expect("register vapi_requests_total")
});

/// Collapse concrete paths to route templates so addresses and hashes do not
/// explode the label cardinality.
pub fn route_label(path: &str) -> &'static str {
    if path.ends_with("/getExecutionHint") {
        "getExecutionHint"
    } else if path.contains("/proof/account/") {
        "proof/account"
    } else if path.contains("/proof/receipt/") {
        "proof/receipt"
    } else if path.contains("/proof/transaction/") {
        "proof/transaction"
    } else if path.contains("/proof/logs") {
        "proof/logs"
    } else if path.contains("/block/") {
        "block"
    } else if path.ends_with("/chainId") {
        "chainId"
    } else if path.ends_with("/sendRawTransaction") {
        "sendRawTransaction"
    } else if path.ends_with("/ping") {
        "ping"
    } else {
        "other"
    }
}

/// Status class rather than the exact code, again for cardinality.
pub fn status_label(status: u16) -> &'static str {
    match status {
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    }
}

pub fn render() -> String {
    let mut buf = String::new();
    if let Err(err) = TextEncoder::new().encode_utf8(&REGISTRY.gather(), &mut buf) {
        tracing::warn!(error = %err, "failed to encode metrics");
    }
    buf
}
