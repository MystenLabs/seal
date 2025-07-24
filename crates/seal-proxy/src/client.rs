// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::metrics_push::{metrics, push_metrics_to_prometheus};
use axum::{extract::Extension, routing::get, Router};
use prometheus::Registry;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::DurationSeconds;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub const METRICS_ROUTE: &str = "/metrics";

#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct MetricsPushConfig {
    /// The interval of time we will allow to elapse before pushing metrics.
    #[serde_as(as = "DurationSeconds<u64>")]
    #[serde(
        rename = "push_interval_secs",
        default = "push_interval",
        skip_serializing_if = "is_push_interval_default"
    )]
    pub push_interval: Duration,
    /// The URL that we will push metrics to.
    pub push_url: String,
    /// Static labels to provide to the push process.
    #[serde(default, skip_serializing_if = "is_none")]
    pub labels: Option<HashMap<String, String>>,
}

#[derive(Clone, Debug)]
pub struct EnableMetricsPush {
    pub config: MetricsPushConfig,
    pub cancel: Option<CancellationToken>,
    pub bearer_token: String,
}

/// Configure the default push interval for metrics.
pub fn push_interval() -> Duration {
    Duration::from_secs(60)
}

/// Returns true if the `duration` is equal to the default push interval for metrics.
pub fn is_push_interval_default(duration: &Duration) -> bool {
    duration == &push_interval()
}

/// Returns true iff the value is `None` and we don't run in test mode.
pub fn is_none<T>(t: &Option<T>) -> bool {
    // The `cfg!(test)` check is there to allow serializing the full configuration, specifically
    // to generate the example configuration files.
    !cfg!(test) && t.is_none()
}

// Creates a new http server that has as a sole purpose to expose
// and endpoint that prometheus agent can use to poll for the metrics.
// A RegistryService is returned that can be used to get access in prometheus Registries.
pub fn start_prometheus_server(addr: SocketAddr) -> Registry {
    let registry = Registry::new();

    let app = Router::new()
        .route(METRICS_ROUTE, get(metrics))
        .layer(Extension(registry.clone()));

    tokio::spawn(async move {
        let listener = TcpListener::bind(&addr).await.unwrap();
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });

    registry
}

/// Create a task that periodically pushes metrics to Prometheus remote write endpoint
pub fn prometheus_push_task(
    mp_config: EnableMetricsPush,
    registry: Registry,
    external_labels: Option<HashMap<String, String>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(mp_config.config.push_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut client = create_push_client();

        tracing::info!(
            "starting prometheus remote write push to '{}'",
            &mp_config.config.push_url
        );

        // if mp_config.cancel is not None, we'll use it to cancel the task
        // otherwise, we'll use a default cancel token
        let cancel_token = mp_config.cancel.unwrap_or(CancellationToken::new());

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(error) = push_metrics_to_prometheus(
                        mp_config.config.push_url.clone(),
                        mp_config.bearer_token.clone(),
                        &client,
                        &registry,
                        external_labels.clone(),
                    ).await {
                        tracing::warn!(?error, "unable to push metrics to prometheus");
                        // Recreate client on error
                        client = create_push_client();
                    }
                }
                _ = cancel_token.cancelled() => {
                    tracing::info!("received cancellation request, shutting down prometheus push");
                }
            }
        }
    })
}

/// Create a request client builder that is used to push metrics to mimir.
fn create_push_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("unable to build client")
}
