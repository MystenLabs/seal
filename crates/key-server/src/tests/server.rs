// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing_test::traced_test;

use crate::externals::get_latest_checkpoint_timestamp;
use crate::tests::SealTestCluster;

use crate::key_server;
use crate::Network;
use crate::PACKAGE_VERSION;
use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use crypto::ibe::generate_key_pair;
use rand::thread_rng;
use sui_types::base_types::ObjectID;
use tower::{Service, ServiceExt};

#[tokio::test]
async fn test_http_response() {
    let master_key = generate_key_pair(&mut thread_rng()).0;
    let network = Network::Devnet;
    let object_id = ObjectID::from_single_byte(0); // Dummy value

    let mut app = key_server(master_key, network, object_id)
        .await
        .into_service();

    // No SDK version
    let request = Request::builder()
        .uri("/v1/service")
        .body(Body::empty())
        .unwrap();
    let response = ServiceExt::<Request<Body>>::ready(&mut app)
        .await
        .unwrap()
        .call(request)
        .await
        .unwrap();
    assert_eq!(
        PACKAGE_VERSION,
        response.headers().get("X-KeyServer-Version").unwrap()
    );
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Old SDK version
    let request = Request::builder()
        .uri("/v1/service")
        .header("Client-Sdk-Version", "0.1.0")
        .body(Body::empty())
        .unwrap();
    let response = ServiceExt::<Request<Body>>::ready(&mut app)
        .await
        .unwrap()
        .call(request)
        .await
        .unwrap();
    assert_eq!(
        PACKAGE_VERSION,
        response.headers().get("X-KeyServer-Version").unwrap()
    );
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Minimal SDK version
    let request = Request::builder()
        .uri("/v1/service")
        .header("Client-Sdk-Version", "0.3.5")
        .body(Body::empty())
        .unwrap();
    let response = ServiceExt::<Request<Body>>::ready(&mut app)
        .await
        .unwrap()
        .call(request)
        .await
        .unwrap();
    assert_eq!(
        PACKAGE_VERSION,
        response.headers().get("X-KeyServer-Version").unwrap()
    );
    assert_eq!(response.status(), StatusCode::OK);
}

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
