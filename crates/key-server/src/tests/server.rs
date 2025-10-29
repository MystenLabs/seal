// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use prometheus::Registry;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing_test::traced_test;

use crate::externals::get_latest_checkpoint_timestamp;
use crate::key_server_options::RetryConfig;
use crate::metrics::Metrics;
use crate::start_server_background_tasks;
use crate::sui_rpc_client::SuiRpcClient;
use crate::tests::SealTestCluster;

use crate::signed_message::signed_request;
use crate::{app, time, Certificate, DefaultEncoding, FetchKeyRequest};
use axum::body::Body;
use axum::extract::Request;
use crypto::elgamal;
use crypto::ibe;
use crypto::ibe::generate_key_pair;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::ed25519::Ed25519PrivateKey;
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::KeyPair;
use fastcrypto::traits::Signer;
use fastcrypto::traits::ToFromBytes;
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rand::thread_rng;
use seal_sdk::{signed_message, FetchKeyResponse};
use serde_json::from_slice;
use serde_json::json;
use serde_json::Value;
use shared_crypto::intent::Intent;
use shared_crypto::intent::IntentMessage;
use std::str::FromStr;
use sui_rpc::client::v2::Client as SuiGrpcClient;
use sui_types::base_types::{ObjectID, SuiAddress};
use sui_types::crypto::Signature;
use sui_types::signature::GenericSignature;
use tokio::net::TcpListener;

#[tokio::test]
async fn test_get_latest_checkpoint_timestamp() {
    let tc = SealTestCluster::new(0).await;

    let tolerance = 20000;
    let timestamp = get_latest_checkpoint_timestamp(SuiRpcClient::new(
        tc.cluster.sui_client().clone(),
        SuiGrpcClient::new(tc.cluster.fullnode_handle.rpc_url.clone())
            .expect("Failed to create gRPC client"),
        RetryConfig::default(),
        None,
    ))
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
    let mut tc = SealTestCluster::new(0).await;
    let (seal_package, _) = tc.publish("seal").await;
    tc.add_open_server(seal_package).await;

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
    let mut tc = SealTestCluster::new(0).await;

    let (seal_package, _) = tc.publish("seal").await;

    tc.add_open_server(seal_package).await;

    let mut receiver = tc.server().spawn_reference_gas_price_updater(None).await.0;

    let price = *receiver.borrow_and_update();
    assert_eq!(price, tc.cluster.get_reference_gas_price().await);

    receiver.changed().await.expect("Failed to get latest rgp");
}

// Tests that the server background task monitor can catch background task errors and panics.
#[tokio::test]
async fn test_server_background_task_monitor() {
    let mut tc = SealTestCluster::new(0).await;
    let (seal_package, _) = tc.publish("seal").await;

    tc.add_open_server(seal_package).await;

    let metrics_registry = Registry::default();
    let metrics = Arc::new(Metrics::new(&metrics_registry));

    let (latest_checkpoint_timestamp_receiver, _reference_gas_price_receiver, monitor_handle) =
        start_server_background_tasks(
            Arc::new(tc.server().clone()),
            metrics.clone(),
            metrics_registry.clone(),
        )
        .await;

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

#[tokio::test]
async fn test_service() {
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let key_server_object_id = ObjectID::random().to_hex_uncompressed();
    let vars = vec![
        ("KEY_SERVER_OBJECT_ID", Some(key_server_object_id.as_str())),
        (
            "MASTER_KEY",
            Some("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ),
    ];
    temp_env::async_with_vars(vars, async {
        let (_, app) = app().await.unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = Client::builder(TokioExecutor::new()).build_http();

        // Missing Client-Sdk-Version header. Should fail
        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{addr}/v1/service"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 400);

        // Valid request
        let response = client
            .request(
                Request::builder()
                    .uri(format!(
                        "http://{addr}/v1/service?service_id={}",
                        key_server_object_id.as_str()
                    ))
                    .header("Client-Sdk-Version", "0.4.11")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let response_bytes = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let response_json: Value = from_slice(&response_bytes).unwrap();
        assert_eq!(
            response_json.get("service_id").unwrap().as_str().unwrap(),
            &key_server_object_id
        );

        // If the service_id query param is NOT set, return error
        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{addr}/v1/service"))
                    .header("Client-Sdk-Version", "0.4.11")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 400);

        // Valid request with too large request body should be rejected
        let large_body = vec![0u8; 200 * 1024]; // 200KB body
        let response = client
            .request(
                Request::builder()
                    .uri(format!(
                        "http://{addr}/v1/service?service_id={}",
                        key_server_object_id.as_str()
                    ))
                    .header("Client-Sdk-Version", "0.4.11")
                    .body(Body::from(large_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 413); // Payload too Large
    })
    .await;
}

#[tokio::test]
async fn test_fetch_key() {
    // From ts-sdk integration tests
    let package_id =
        ObjectID::from_str("0x9709d4ee371488c2bc09f508e98e881bd1d5335e0805d7e6a99edd54a7027954")
            .unwrap();

    let whitelist_id =
        ObjectID::from_str("0xaae704d2280f2c3d24fc08972bb31f2ef1f1c968784935434c3296be5bfd9d5b")
            .unwrap();

    let user_secret_key = Ed25519PrivateKey::from_bytes(&[
        16, 38, 58, 130, 194, 133, 180, 117, 252, 32, 106, 49, 97, 22, 170, 130, 33, 59, 81, 63,
        132, 11, 246, 227, 58, 130, 18, 208, 130, 124, 49, 12,
    ])
    .unwrap();
    let keypair = Ed25519KeyPair::from(user_secret_key);
    let user =
        SuiAddress::from_str("0xb743cafeb5da4914cef0cf0a32400c9adfedc5cdb64209f9e740e56d23065100")
            .unwrap();

    // Setup key server
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let key_server_object_id = ObjectID::random();

    let mut rng = thread_rng();
    let (master_key, public_key) = generate_key_pair(&mut rng);

    // Generate a master seed for the first key server
    let key_server_object_id_string = key_server_object_id.to_hex_uncompressed();
    let master_key_string = DefaultEncoding::encode(master_key.to_byte_array());
    let vars = vec![
        ("KEY_SERVER_OBJECT_ID", Some(&key_server_object_id_string)),
        ("MASTER_KEY", Some(&master_key_string)),
    ];

    let ptb = crate::tests::whitelist::whitelist_create_ptb(
        package_id,
        whitelist_id,
        189000470, // initial shared version
    );

    // Generate session key and encryption key
    let (enc_secret, enc_key, enc_verification_key) = elgamal::genkey(&mut rng);
    let session = Ed25519KeyPair::generate(&mut rng);

    // Create certificate
    let creation_time = time::current_epoch_time();
    let ttl_min = 10;
    let message = signed_message(
        package_id.to_hex_uncompressed(),
        session.public(),
        creation_time,
        ttl_min,
    );
    let msg_with_intent = IntentMessage::new(Intent::personal_message(), message.clone());
    let signature = GenericSignature::Signature(Signature::new_secure(&msg_with_intent, &keypair));
    let certificate = Certificate {
        user,
        session_vk: session.public().clone(),
        creation_time,
        ttl_min,
        signature,
        mvr_name: None,
    };
    let request_message = signed_request(&ptb, &enc_key, &enc_verification_key);
    let request_signature = session.sign(&request_message);

    // Create the FetchKeyRequest
    let request = FetchKeyRequest {
        ptb: Base64::encode(bcs::to_bytes(&ptb).unwrap()),
        enc_key,
        enc_verification_key,
        request_signature,
        certificate,
    };

    // Run test
    temp_env::async_with_vars(vars, async {
        let (_, app) = app().await.unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = Client::builder(TokioExecutor::new()).build_http();

        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{addr}/v1/fetch_key",))
                    .method("POST")
                    .header("Client-Sdk-Version", "0.4.11")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!(request).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let response_bytes = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();

        let response: FetchKeyResponse =
            serde_json::from_slice(&response_bytes).expect("Failed to deserialize response");

        let user_secret_key =
            elgamal::decrypt(&enc_secret, &response.decryption_keys[0].encrypted_key);
        assert!(ibe::verify_user_secret_key(
            &user_secret_key,
            &response.decryption_keys[0].id,
            &public_key
        )
        .is_ok());
    })
    .await;
}
