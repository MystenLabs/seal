// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing_test::traced_test;

use crate::externals::get_latest_checkpoint_timestamp;
use crate::tests::SealTestCluster;

#[tokio::test]
async fn test_get_latest_checkpoint_timestamp() {
    let tc = SealTestCluster::new(0, 0).await;

    let tolerance = 20000;
    let timestamp: u64 = get_latest_checkpoint_timestamp(tc.cluster.sui_client().clone())
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

    let update_interval = Duration::from_secs(1);

    let mut receiver = tc
        .server()
        .spawn_latest_checkpoint_timestamp_updater(update_interval, None)
        .await;

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

    let update_interval = Duration::from_secs(1);

    let mut receiver = tc
        .server()
        .spawn_reference_gas_price_updater(update_interval, None)
        .await;

    let price = *receiver.borrow_and_update();
    assert_eq!(price, tc.cluster.get_reference_gas_price().await);

    receiver.changed().await.expect("Failed to get latest rgp");
}
