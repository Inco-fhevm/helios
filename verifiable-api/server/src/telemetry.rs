//! OTLP export and W3C trace-context extraction for the verifiable-api server.
//!
//! Without this the server is a black box: helios records one
//! `helios.vapi_get_account` span and everything the server does inside it --
//! EVM execution, per-account proof fetches against its own upstream -- is
//! invisible. A single such span was measured at 3.2s with no children.
//!
//! Two halves are needed and both matter:
//!   * extract: adopt the caller's traceparent so our spans join the decrypt's
//!     trace instead of forming orphan roots.
//!   * export:  ship them to the same collector everything else uses.
//!
//! Enabled only when OTLP_ENDPOINT is set, so the server keeps working
//! unchanged when it is not.

use std::collections::HashMap;

use axum::{extract::Request, middleware::Next, response::Response};
use opentelemetry::propagation::Extractor;
use tracing_opentelemetry::OpenTelemetrySpanExt;

struct HeaderExtractor<'a>(&'a axum::http::HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }
    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

/// Adopts the caller's trace context, so server spans hang off the decrypt that
/// triggered them rather than starting a new trace.
pub async fn trace_context_layer(req: Request, next: Next) -> Response {
    let parent = opentelemetry::global::get_text_map_propagator(|prop| {
        prop.extract(&HeaderExtractor(req.headers()))
    });
    let span = tracing::info_span!(
        "vapi.request",
        http.method = %req.method(),
        http.path = %req.uri().path(),
        http.status = tracing::field::Empty,
        accounts = tracing::field::Empty,
        // Recorded below, after the parent context is adopted. tracing's JSON
        // formatter emits span fields but knows nothing about OpenTelemetry, so
        // without this the log line carries no trace id and cannot be joined to
        // the trace that produced it -- logs and traces then exist side by side
        // with no way to get from one to the other.
        trace_id = tracing::field::Empty,
    );
    let _ = span.set_parent(parent);

    // Must come AFTER set_parent: before it, the span has no OTel context and the
    // trace id is the all-zero placeholder.
    {
        use opentelemetry::trace::TraceContextExt;
        let ctx = span.context();
        let sc = ctx.span().span_context().clone();
        if sc.is_valid() {
            span.record("trace_id", sc.trace_id().to_string().as_str());
        }
    }

    // MUST be .instrument(), not span.enter(). enter() returns a synchronous
    // guard; holding one across an await leaks the span across runtime workers
    // when the future is moved, and touching the span afterwards hits
    //   tracing-subscriber registry: "tried to clone a span that already closed"
    // which panics a tokio worker and takes the process down (exitCode 139).
    // Observed exactly that: the server segfaulted ~2min into load, Traefik then
    // served 503/502, helios discarded the failed hint (the result of
    // prefetch_state is dropped) and fell back to ~10 serial account fetches.
    // Recording the status inside the instrumented future keeps every touch of
    // the span on the same task.
    use tracing::Instrument;
    async move {
        let handler_t = std::time::Instant::now();
        let res = next.run(req).await;
        let handler_ms = handler_t.elapsed().as_secs_f64() * 1000.0;
        // Status matters as much as duration: a client seeing failures while we
        // answer in ~2ms means we return something it treats as retryable, and
        // only the status says which.
        tracing::Span::current().record("http.status", res.status().as_u16());
        tracing::info!(handler_ms, "vapi handler complete");
        res
    }
    .instrument(span)
    .await
}

/// Times what happens to the response AFTER the handler returns.
///
/// This must be layered OUTSIDE CompressionLayer. tower-http compresses lazily,
/// as the body is polled, which is after the handler span has already closed --
/// so that work was invisible on both ends: the server reported a 240ms handler
/// while the client waited 514ms for headers and a further 84-300ms for the
/// first body byte. ~274ms sat in a gap nothing measured.
///
/// Materialising the body here collects it through the compression layer, so the
/// elapsed time IS the encode cost and the resulting length IS the number of
/// bytes that go on the wire -- which also answers whether the 134 KB payload is
/// actually 134 KB once compressed.
pub async fn response_timing_layer(req: Request, next: Next) -> Response {
    use tracing::Instrument;

    let path = req.uri().path().to_string();

    // This layer sits outside trace_context_layer, so there is NO current span
    // here -- and tracing-opentelemetry drops events that have no span to attach
    // to. The first version of this emitted encode_ms into the void: the field
    // never appeared in Tempo once. It needs a span of its own, which also gives
    // the encode work a visible duration rather than only a logged number.
    let span = tracing::info_span!(
        "vapi.encode",
        http.path = %path,
        encode_ms = tracing::field::Empty,
        wire_bytes = tracing::field::Empty,
    );

    async move {
        // Timed from here so the histogram covers handler AND body encoding.
        // Traces alone were not enough: they are sampled and lossy, and during
        // one investigation the server span for a 3.9s client call was simply
        // absent from the trace, leaving no way to tell "the server was slow"
        // from "the request never arrived". A metric is always there.
        let started = std::time::Instant::now();

        let res = next.run(req).await;
        let status = res.status().as_u16();
        let (parts, body) = res.into_parts();

        let route = crate::metrics::route_label(&path);

        let t = std::time::Instant::now();
        let bytes = match axum::body::to_bytes(body, usize::MAX).await {
            Ok(b) => b,
            Err(err) => {
                tracing::warn!(error = %err, "response body failed to materialise");
                crate::metrics::REQUESTS_TOTAL
                    .with_label_values(&[route, "5xx"])
                    .inc();
                return Response::from_parts(parts, axum::body::Body::empty());
            }
        };
        let encode_ms = t.elapsed().as_secs_f64() * 1000.0;

        let cur = tracing::Span::current();
        cur.record("encode_ms", encode_ms);
        cur.record("wire_bytes", bytes.len());

        let class = crate::metrics::status_label(status);
        crate::metrics::REQUEST_DURATION
            .with_label_values(&[route, class])
            .observe(started.elapsed().as_secs_f64());
        crate::metrics::ENCODE_DURATION
            .with_label_values(&[route])
            .observe(encode_ms / 1000.0);
        crate::metrics::RESPONSE_BYTES
            .with_label_values(&[route])
            .observe(bytes.len() as f64);
        crate::metrics::REQUESTS_TOTAL
            .with_label_values(&[route, class])
            .inc();

        Response::from_parts(parts, axum::body::Body::from(bytes))
    }
    .instrument(span)
    .await
}

/// Installs the OTLP pipeline. No-op unless OTLP_ENDPOINT is set.
pub fn init(service_name: &str) {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::builder()
        .with_default_directive("info".parse().unwrap())
        .from_env_lossy();
    // JSON, no ANSI. Two reasons, both learned the hard way:
    //
    // The log shipper parses each line with parse_json and lifts level/message
    // and trace_id into fields. Colourised plain text fails that parse, so the
    // whole line -- escape codes and all -- lands in `message` and the trace id
    // stays buried in text. Logs then exist in Loki but a trace cannot be
    // followed into them, which is the only reason to ship them.
    //
    // `with_current_span`/`with_span_list` are what put the active span (and so
    // the request's identity) on the event, rather than the event standing alone.
    let fmt = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .json()
        .with_current_span(true)
        .with_span_list(false);

    let Ok(endpoint) = std::env::var("OTLP_ENDPOINT") else {
        tracing_subscriber::registry().with(filter).with(fmt).init();
        return;
    };

    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.clone())
        .build()
        .expect("otlp exporter");

    let mut attrs = HashMap::new();
    attrs.insert("service.name", service_name.to_string());
    if let Ok(env) = std::env::var("DEPLOYMENT_ENVIRONMENT") {
        attrs.insert("deployment.environment", env);
    }
    let resource = opentelemetry_sdk::Resource::builder()
        .with_attributes(
            attrs
                .into_iter()
                .map(|(k, v)| opentelemetry::KeyValue::new(k, v)),
        )
        .build();

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();
    let tracer = provider.tracer(service_name.to_string());
    opentelemetry::global::set_tracer_provider(provider);

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt)
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .init();

    tracing::info!(endpoint = %endpoint, "OTLP tracing enabled");
}
