//! W3C trace-context injection for outbound verifiable-api calls.
//!
//! Without this the verifiable-api server records its work as unrelated trace
//! roots, so the time it spends -- EVM execution, per-account proof fetches
//! against its own upstream -- cannot be tied back to the decrypt that caused
//! it. A single `helios.vapi_get_account` span was measured at 3.2s with
//! nothing underneath it; all of that work is on the far side of this call.

use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next, Result as MwResult};

use opentelemetry::propagation::Injector;
use tracing_opentelemetry::OpenTelemetrySpanExt;

struct HeaderInjector<'a>(&'a mut reqwest::header::HeaderMap);

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let (Ok(name), Ok(value)) = (
            reqwest::header::HeaderName::from_bytes(key.as_bytes()),
            reqwest::header::HeaderValue::from_str(&value),
        ) {
            self.0.insert(name, value);
        }
    }
}

/// Injects `traceparent` from the current span onto every outbound request.
pub struct TraceInjectMiddleware;

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Middleware for TraceInjectMiddleware {
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut http::Extensions,
        next: Next<'_>,
    ) -> MwResult<Response> {
        let cx = tracing::Span::current().context();
        opentelemetry::global::get_text_map_propagator(|prop| {
            prop.inject_context(&cx, &mut HeaderInjector(req.headers_mut()));
        });
        next.run(req, extensions).await
    }
}

/// One span per HTTP attempt, with the status and whether it is a retry.
///
/// Placed AFTER RetryTransientMiddleware in the stack, so it runs once per
/// attempt rather than once per logical call. Without it a retried request
/// collapses into a single client span: one `helios.vapi_get_account` was
/// measured at 1339ms containing three server responses of 1.3, 1.5 and 2.1ms,
/// with ~334ms and ~986ms of unexplained gap between them. This says whether
/// that gap is backoff, connection setup, or something else, and what status
/// drove the retry.
pub struct AttemptSpanMiddleware;

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Middleware for AttemptSpanMiddleware {
    async fn handle(
        &self,
        req: Request,
        extensions: &mut http::Extensions,
        next: Next<'_>,
    ) -> MwResult<Response> {
        let path = req.url().path().to_string();
        // Splits this span's metric into a bounded second dimension. One span
        // name covered two unrelated things: real hint/proof attempts, and the
        // every-10s keepalive HEAD the client spawns to keep the pool warm. Over
        // an idle window the counter rose by 142 with zero logical calls, so
        // "attempts per call" read 3.22 when the truth was ~1.02.
        let kind = if req.method() == http::Method::HEAD {
            "keepalive"
        } else if path.ends_with("/getExecutionHint") {
            "hint"
        } else if path.contains("/proof/") {
            "proof"
        } else {
            "other"
        };
        let span = tracing::info_span!(
            "vapi.http_attempt",
            metric_kind = kind,
            http.path = %path,
            http.status = tracing::field::Empty,
            outcome = tracing::field::Empty,
            // The peer that actually served this attempt. Two things fall out of
            // it that nothing else tells us: which verifiable-api replica
            // answered (so a slow one is attributable), and -- because a fresh
            // TCP connection to a load-balanced host can land anywhere -- an
            // address that changes between consecutive attempts is evidence the
            // pool did NOT reuse a connection.
            peer = tracing::field::Empty,
            // Duration up to response HEADERS. This span closes when the
            // middleware chain returns, which is at headers, not at end of body
            // -- measured 2845ms here against a 9ms server, so the cost is
            // before the body exists. Recorded explicitly so the split between
            // "to headers" and "body+parse" is readable without inferring it
            // from span nesting.
            to_headers_ms = tracing::field::Empty,
        );
        // .instrument(), never span.enter(): a sync guard held across an await
        // leaks the span when the future moves between runtime workers, and the
        // later span.record() then panics the worker with
        //   "tried to clone a span that already closed"
        // The server side of this crashed exactly that way (exitCode 139).
        use tracing::Instrument;
        async move {
            let t0 = std::time::Instant::now();
            let res = next.run(req, extensions).await;
            let to_headers = t0.elapsed().as_secs_f64() * 1000.0;
            let span = tracing::Span::current();
            span.record("to_headers_ms", to_headers);
            match &res {
                Ok(r) => {
                    span.record("http.status", r.status().as_u16());
                    span.record("outcome", "response");
                    if let Some(addr) = r.remote_addr() {
                        span.record("peer", tracing::field::display(addr));
                    }
                }
                Err(e) => {
                    span.record("outcome", format!("error: {e}").as_str());
                }
            }
            // Emitted from this file rather than http.rs on purpose: spans
            // created in http.rs (vapi.body_read, vapi.deserialize) never reach
            // Tempo while spans created here always do, and that difference is
            // unexplained. An event carries the same timing and rides on a span
            // that is known to export, so the measurement does not depend on
            // resolving that first.
            tracing::info!(
                to_headers_ms = to_headers,
                path = %path,
                "vapi attempt reached headers"
            );
            res
        }
        .instrument(span)
        .await
    }
}
