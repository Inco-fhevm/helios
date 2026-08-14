use axum::{
    routing::{get, post},
    Router,
};
use tower_http::{
    compression::{CompressionLayer, CompressionLevel},
    trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer},
};

use helios_common::network_spec::NetworkSpec;
use tracing::Level;

use crate::{handlers, state::ApiState};

pub fn build_router<N: NetworkSpec>() -> Router<ApiState<N>> {
    Router::new()
        .route("/openapi.yaml", get(handlers::openapi))
        .route("/ping", get(handlers::ping))
        // Scrapeable server-side latency. Deliberately OUTSIDE the nested
        // proof routes so it is reachable even if those are failing.
        .route("/metrics", get(|| async { crate::metrics::render() }))
        .nest(
            "/eth/v1/proof",
            Router::new()
                .route("/account/{address}", get(handlers::get_account))
                .route("/transaction/{txHash}", get(handlers::get_transaction))
                .route(
                    "/transaction/{blockId}/{index}",
                    get(handlers::get_transaction_by_location),
                )
                .route("/receipt/{txHash}", get(handlers::get_transaction_receipt))
                .route("/logs", get(handlers::get_logs))
                .route("/getExecutionHint", post(handlers::get_execution_hint)),
        )
        .nest(
            "/eth/v1",
            Router::new()
                .route("/chainId", get(handlers::get_chain_id))
                .route("/block/{blockId}", get(handlers::get_block))
                .route(
                    "/block/{blockId}/receipts",
                    get(handlers::get_block_receipts),
                )
                .route("/sendRawTransaction", post(handlers::send_raw_transaction)),
        )
        // Fastest, not the default.
        //
        // "compression-full" enables brotli, and CompressionLayer's default
        // quality is brotli 11 -- the slowest level in the format, intended for
        // static assets compressed once and served many times. getExecutionHint
        // returns ~134 KB of Merkle proofs and was being compressed at that level
        // on every request, on a pod with a 500m CPU request.
        //
        // tower-http compresses lazily as the body is polled, i.e. AFTER the
        // response headers are already on the wire, so the cost is invisible to
        // the handler span: the server reported 2ms while the client waited up to
        // 1.6s for the FIRST body byte. Chunk timing settled it -- first chunk
        // 1601ms of a 1603ms read, then 34 chunks with 0.0ms of stalling, so it
        // was never transfer or flow control.
        //
        // Fastest is brotli 1 / gzip 1: an order of magnitude cheaper, and on an
        // internal link the ratio it gives up is worth far less than the latency.
        .layer(CompressionLayer::new().quality(CompressionLevel::Fastest))
        // Layer order matters twice over, and getting it wrong cost two rounds.
        //
        // Outside CompressionLayer, because that is the only place the encode
        // cost and the on-the-wire size are observable -- tower-http compresses
        // lazily as the body is polled, after the handler has returned.
        //
        // Inside trace_context_layer, because that is what extracts the caller's
        // traceparent. Registered outside it, vapi.encode had no parent context
        // and every span became its own trace root: the spans existed in Tempo
        // but never inside the request that produced them, so they were invisible
        // when reading a decrypt end to end.
        .layer(axum::middleware::from_fn(
            crate::telemetry::response_timing_layer,
        ))
        .layer(axum::middleware::from_fn(
            crate::telemetry::trace_context_layer,
        ))
        .layer(
            TraceLayer::new_for_http()
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
}
