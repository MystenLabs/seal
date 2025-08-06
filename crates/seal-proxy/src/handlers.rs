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
use axum::{extract::Extension, http::StatusCode};
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

/// Publish handler which receives metrics from nodes.  Nodes will call us at
/// this endpoint and we relay them to the upstream tsdb. Clients will receive
/// a response after successfully relaying the metrics upstream
pub async fn publish_metrics(
    TypedHeader(req): TypedHeader<Authorization<Bearer>>,
    Extension(allower): Extension<Arc<BearerTokenProvider>>,
    Extension(label_actions): Extension<LabelActions>,
    Extension(remote_write_client): Extension<ReqwestClient>,
    Extension(relay): Extension<HistogramRelay>,
    LenDelimProtobuf(data): LenDelimProtobuf,
) -> (StatusCode, &'static str) {
    let node_name = allower.get_bearer_token_owner_name(req.token()).unwrap();
    with_label!(HANDLER_HITS, "publish_metrics", &node_name).inc();

    let timer = with_label!(HTTP_HANDLER_DURATION, "publish_metrics", &node_name).start_timer();

    let data = populate_labels(node_name, label_actions, data);
    relay.submit(data.clone());
    let response = convert_to_remote_write(remote_write_client.clone(), data).await;

    timer.observe_duration();
    response
}
