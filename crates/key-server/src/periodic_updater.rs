// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::sui_rpc_client::SuiRpcClient;
use std::time::{Duration, Instant};
use sui_sdk::error::SuiRpcResult;
use tokio::sync::watch::{channel, Receiver};
use tokio::task::JoinHandle;
use tracing::debug;

/// Helper function to spawn a thread that periodically fetches a value and sends it to a [Receiver].
/// If a subscriber is provided, it will be called when the value is updated.
/// If a duration_callback is provided, it will be called with the duration of each fetch operation.
/// Returns the [Receiver].
pub async fn spawn_periodic_updater<F, Fut, G, H, I>(
    client: &SuiRpcClient,
    update_interval: Duration,
    fetch_fn: F,
    value_name: &'static str,
    subscriber: Option<G>,
    duration_callback: Option<H>,
    success_callback: Option<I>,
) -> (Receiver<u64>, JoinHandle<()>)
where
    F: Fn(SuiRpcClient) -> Fut + Send + 'static,
    Fut: Future<Output = SuiRpcResult<u64>> + Send,
    G: Fn(u64) + Send + 'static,
    H: Fn(Duration) + Send + 'static,
    I: Fn(bool) + Send + 'static,
{
    let (sender, mut receiver) = channel(0);
    let local_client = client.clone();
    let mut interval = tokio::time::interval(update_interval);

    // In case of a missed tick due to a slow-responding full node, we don't need to
    // catch up but rather just delay the next tick.
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let handle = tokio::task::spawn(async move {
        loop {
            let now = Instant::now();
            let result = fetch_fn(local_client.clone()).await;
            if let Some(dcb) = &duration_callback {
                dcb(now.elapsed());
            }
            if let Some(scb) = &success_callback {
                scb(result.is_ok());
            }
            match result {
                Ok(new_value) => {
                    sender
                        .send(new_value)
                        .expect("Channel closed, this should never happen");
                    debug!("{} updated to: {:?}", value_name, new_value);
                    if let Some(subscriber) = &subscriber {
                        subscriber(new_value);
                    }
                }
                Err(e) => debug!("Failed to get {}: {:?}", value_name, e),
            }
            interval.tick().await;
        }
    });

    // This blocks until a value is fetched.
    // This is done to ensure that the server will be ready to serve requests immediately after starting.
    // If this is not possible, we cannot update the value and the server should not start.
    receiver
        .changed()
        .await
        .unwrap_or_else(|_| panic!("Failed to get {}", value_name));
    (receiver, handle)
}
