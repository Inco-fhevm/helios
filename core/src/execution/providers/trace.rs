//! W3C trace-context injection for outbound execution RPC.
//!
//! An ACL check fans out into many `eth_getProof` calls against the upstream.
//! Without a `traceparent` on each one the upstream records them as unrelated
//! roots, so the time they account for cannot be tied back to the request that
//! issued them.
//!
//! Alloy reads outbound headers from a `HeaderMap` stored in the request's
//! extensions, and only for single (non-batched) requests — a batch is sent
//! without headers regardless of what is injected here.

use alloy::rpc::json_rpc::{RequestPacket, ResponsePacket};
use alloy::transports::{TransportError, TransportFut};
use http::HeaderMap;
use opentelemetry::propagation::Injector;
use std::task::{Context, Poll};
use tower::{Layer, Service};
use tracing_opentelemetry::OpenTelemetrySpanExt;

struct HeaderInjector<'a>(&'a mut HeaderMap);

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::from_bytes(key.as_bytes()),
            http::header::HeaderValue::from_str(&value),
        ) {
            self.0.insert(name, value);
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TraceInjectLayer;

impl<S> Layer<S> for TraceInjectLayer {
    type Service = TraceInjectService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TraceInjectService { inner }
    }
}

#[derive(Clone, Debug)]
pub struct TraceInjectService<S> {
    inner: S,
}

impl<S> Service<RequestPacket> for TraceInjectService<S>
where
    S: Service<
        RequestPacket,
        Response = ResponsePacket,
        Error = TransportError,
        Future = TransportFut<'static>,
    >,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: RequestPacket) -> Self::Future {
        let cx = tracing::Span::current().context();
        let mut headers = HeaderMap::new();
        opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.inject_context(&cx, &mut HeaderInjector(&mut headers))
        });

        // Empty whenever no span is active or no OpenTelemetry layer is installed,
        // in which case the request goes out exactly as it did before.
        if !headers.is_empty() {
            for request in req.requests_mut() {
                request.meta_mut().extensions_mut().insert(headers.clone());
            }
        }

        self.inner.call(req)
    }
}
