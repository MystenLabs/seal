// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;

use anyhow::Result;
use rand::Rng;
use tokio::time::{sleep, Duration};
use seal_proxy::client::{start_prometheus_server, prometheus_push_task, MetricsPushConfig, EnableMetricsPush};
use tokio_util::sync::CancellationToken;
use std::collections::HashMap;
use prometheus::{Registry, IntGauge, IntGaugeVec, Histogram};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt().init();

    let metrics_address = SocketAddr::from(([0, 0, 0, 0], 9185));
    let cancel = CancellationToken::new();
    // let bearer_token = "1234567890";
    let bearer_token = "abcdefghijklmnopqrstuvwxyz";
    let config = EnableMetricsPush {
        cancel: cancel.child_token(),
        bearer_token: bearer_token.to_string(),
        config: MetricsPushConfig {
            push_url: "http://seal-proxy:8000/publish/metrics".to_string(),
            push_interval: Duration::from_secs(5),
            labels: Some(HashMap::from([("host".to_string(), "demo".to_string())])),
        },
    };
    let registry = start_prometheus_server(metrics_address);
    let metrics = create_metrics(&registry);
    let join_handle = prometheus_push_task(config, registry.clone(), None);

    tokio::spawn(async move {
        loop {
            generate_metrics(&metrics);
            sleep(Duration::from_secs(5)).await;
        }
    });

    join_handle.await?

}

struct Metrics {
    current_time: IntGauge,
    seal_build_info: IntGaugeVec,
    seal_request_duration: Histogram,
}

fn create_metrics(registry: &Registry) -> Metrics {
    let current_time_opts = prometheus::opts!("current_time", "Current time");
    let current_time = prometheus::register_int_gauge_with_registry!(
        current_time_opts,
        registry
    )
    .expect("metric registration should succeed");

    let build_info_opts = prometheus::opts!("seal_build_info", "Seal binary info");
    let seal_build_info = prometheus::register_int_gauge_vec_with_registry!(
        build_info_opts,
        &["version"],
        registry
    )
    .expect("metric registration should succeed");

    let histogram_opts = prometheus::HistogramOpts::new("seal_request_duration", "Seal request duration")
        .buckets(vec![0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]);
    let seal_request_duration = prometheus::register_histogram_with_registry!(histogram_opts, registry).expect("metric registration should succeed");

    Metrics {
        current_time,
        seal_build_info,
        seal_request_duration,
    }
}

// this function should post metrics to 127.0.0.1:9185/metrics
fn generate_metrics(metrics: &Metrics) {
    let timestamp = chrono::Utc::now().timestamp_millis();
    metrics.current_time.set(timestamp);

    tracing::info!("generating metrics: {}", timestamp);

    let version = "0.1.0";
    metrics
        .seal_build_info
        .with_label_values(&[version])
        .set(1);

    // populate histogram with random duration
    let duration = Duration::from_millis(rand::thread_rng().gen_range(1..10000));
    metrics.seal_request_duration.observe(duration.as_secs_f64());

}