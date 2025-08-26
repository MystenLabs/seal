// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    admin::ReqwestClient,
    config::LabelActions,
    consumer::{convert_to_remote_write, populate_labels},
    histogram_relay::HistogramRelay,
    middleware::LenDelimProtobuf,
    providers::BearerTokenProvider,
    register_metric, with_label,
};
use axum::{extract::Extension, http::StatusCode, middleware::Next, response::Response};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    typed_header::TypedHeader,
};
use once_cell::sync::Lazy;
use prometheus::{CounterVec, HistogramOpts, HistogramVec, Opts};
use std::sync::Arc;

static HANDLER_HITS: Lazy<CounterVec> = Lazy::new(|| {
    register_metric!(CounterVec::new(
        Opts::new("http_handler_hits", "Number of HTTP requests made.",),
        &["handler", "remote"]
    )
    .unwrap())
});

static HTTP_HANDLER_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    register_metric!(HistogramVec::new(
        HistogramOpts::new(
            "http_handler_duration_seconds",
            "The HTTP request latencies in seconds.",
        )
        .buckets(vec![
            1.0, 1.25, 1.5, 1.75, 2.0, 2.25, 2.5, 2.75, 3.0, 3.25, 3.5, 3.75, 4.0, 4.25, 4.5, 4.75,
            5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0
        ]),
        &["handler", "remote"]
    )
    .unwrap())
});

/// Middleware to extract client IP address from various headers and add it as an extension
pub async fn extract_client_ip(
    mut request: axum::extract::Request,
    next: Next,
) -> Result<Response, (StatusCode, &'static str)> {
    // Try to get IP from various headers in order of preference
    let client_ip = request
        .headers()
        .get("X-Forwarded-For")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            request
                .headers()
                .get("X-Real-IP")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
        })
        .or_else(|| {
            request
                .headers()
                .get("X-Client-IP")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
        })
        .or_else(|| {
            request
                .extensions()
                .get::<std::net::SocketAddr>()
                .map(|addr| addr.ip().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Add the client IP as an extension
    request.extensions_mut().insert(client_ip);

    Ok(next.run(request).await)
}

/// Publish handler which receives metrics from nodes.  Nodes will call us at
/// this endpoint and we relay them to the upstream tsdb. Clients will receive
/// a response after successfully relaying the metrics upstream
pub async fn publish_metrics(
    TypedHeader(req): TypedHeader<Authorization<Bearer>>,
    Extension(allower): Extension<Arc<BearerTokenProvider>>,
    Extension(label_actions): Extension<LabelActions>,
    Extension(remote_write_client): Extension<ReqwestClient>,
    Extension(relay): Extension<HistogramRelay>,
    Extension(client_ip): Extension<String>,
    LenDelimProtobuf(data): LenDelimProtobuf,
) -> (StatusCode, &'static str) {
    let node_name = allower.get_bearer_token_owner_name(req.token()).unwrap();
    with_label!(HANDLER_HITS, "publish_metrics", &node_name).inc();

    let timer = with_label!(HTTP_HANDLER_DURATION, "publish_metrics", &node_name).start_timer();

    let data = populate_labels(node_name, label_actions, data, client_ip);
    relay.submit(data.clone());
    let response = convert_to_remote_write(remote_write_client.clone(), data).await;

    timer.observe_duration();
    response
}
