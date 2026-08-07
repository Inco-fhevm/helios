//! W3C trace-context extraction for the JSON-RPC server.
//!
//! jsonrpsee's `#[rpc]` macro gives method bodies no access to HTTP headers, so
//! `traceparent` has to be read at the HTTP layer and turned into the parent of
//! a span that wraps the whole request future. Everything the request then does,
//! including outbound RPC to the upstream, runs inside that span, which is what
//! lets a caller's trace continue through this process instead of restarting
//! here.

use std::{
    error::Error as StdError,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use opentelemetry::propagation::Extractor;
use tower::{Layer, Service};
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Reads W3C headers out of a hyper request.
struct HeaderExtractor<'a>(&'a hyper::HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TraceContextLayer;

impl<S> Layer<S> for TraceContextLayer {
    type Service = TraceContextService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TraceContextService { inner }
    }
}

#[derive(Clone, Debug)]
pub struct TraceContextService<S> {
    inner: S,
}

impl<S> Service<hyper::Request<hyper::Body>> for TraceContextService<S>
where
    S: Service<hyper::Request<hyper::Body>, Response = hyper::Response<hyper::Body>>,
    S::Error: Into<Box<dyn StdError + Send + Sync + 'static>>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: hyper::Request<hyper::Body>) -> Self::Future {
        let span = tracing::info_span!("helios.rpc");
        // An absent traceparent yields an empty context, leaving the span a local
        // root. set_parent errors only when no OpenTelemetry layer is installed,
        // i.e. when this process exports no traces, where a parent is moot.
        let parent = opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.extract(&HeaderExtractor(request.headers()))
        });
        let _ = span.set_parent(parent);

        Box::pin(self.inner.call(request).instrument(span))
    }
}
