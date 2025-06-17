// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use prometheus::Registry;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing_test::traced_test;

use crate::externals::get_latest_checkpoint_timestamp;
use crate::metrics::Metrics;
use crate::start_server_background_tasks;
use crate::tests::SealTestCluster;

#[tokio::test]
async fn test_get_latest_checkpoint_timestamp() {
    let tc = SealTestCluster::new(0, 0).await;

    let tolerance = 20000;
    let timestamp = get_latest_checkpoint_timestamp(tc.sui_client.clone())
        .await
        .unwrap();

    let actual_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64;

    let diff = actual_timestamp - timestamp;
    assert!(diff < tolerance);
}

#[tokio::test]
async fn test_timestamp_updater() {
    let tc = SealTestCluster::new(1, 0).await;

    let mut receiver = tc
        .server()
        .spawn_latest_checkpoint_timestamp_updater(None)
        .await
        .0;

    let tolerance = 20000;

    let timestamp = *receiver.borrow_and_update();
    let actual_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64;

    let diff = actual_timestamp - timestamp;
    assert!(diff < tolerance);

    // Get a new timestamp
    receiver
        .changed()
        .await
        .expect("Failed to get latest timestamp");
    let new_timestamp = *receiver.borrow_and_update();
    assert!(new_timestamp >= timestamp);
}

#[traced_test]
#[tokio::test]
async fn test_rgp_updater() {
    let tc = SealTestCluster::new(1, 0).await;

    let mut receiver = tc.server().spawn_reference_gas_price_updater(None).await.0;

    let price = *receiver.borrow_and_update();
    assert_eq!(price, tc.cluster.get_reference_gas_price().await);

    receiver.changed().await.expect("Failed to get latest rgp");
}

// Tests that the server background task monitor can catch background task errors and panics.
#[tokio::test]
async fn test_server_background_task_monitor() {
    let tc = SealTestCluster::new(1, 0).await;

    let metrics_registry = Registry::default();
    let metrics = Arc::new(Metrics::new(&metrics_registry));

    let (latest_checkpoint_timestamp_receiver, _reference_gas_price_receiver, monitor_handle) =
        start_server_background_tasks(Arc::new(tc.server().clone()), metrics.clone()).await;

    // Drop the receiver to trigger the panic in the background
    // spawn_latest_checkpoint_timestamp_updater task.
    drop(latest_checkpoint_timestamp_receiver);

    // Wait for the monitor to exit with an error. This should happen in a timely manner.
    let result = tokio::time::timeout(std::time::Duration::from_secs(10), monitor_handle)
        .await
        .expect("Waiting for background monitor to exit timed out after 10 seconds");

    // Check that the result is a panic.
    assert!(result.is_err(), "Expected JoinError");
    let err = result.unwrap_err();
    assert!(err.is_panic(), "Expected JoinError::Panic");
}
