// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use seal_proxy::client::create_push_client;
use seal_proxy::metrics_push::push_metrics_to_prometheus;
use seal_proxy::client::EnableMetricsPush;
use tokio::task::JoinHandle;
use prometheus::Registry;
use std::collections::HashMap;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Create a task that periodically pushes metrics to Prometheus remote write endpoint
pub fn metrics_push_handler(
    mp_config: EnableMetricsPush,
    registry: Registry,
    external_labels: Option<HashMap<String, String>>,
) -> JoinHandle<()> {
    info!("starting metrics push task, push_url: {}", mp_config.config.push_url);
    tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(mp_config.config.push_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut client = create_push_client();

        let cancel_token = CancellationToken::new().child_token();

        debug!("metrics push task started");
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
                        warn!(?error, "unable to push metrics to prometheus");
                        // Recreate client on error
                        client = create_push_client();
                    }
                }
                _ = cancel_token.cancelled() => {
                    info!("received cancellation request, shutting down prometheus push");
                }
            }
        }
    })
}