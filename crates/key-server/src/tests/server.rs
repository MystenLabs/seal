// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::groups::bls12381::G2Element;
use fastcrypto::groups::GroupElement;
use prometheus::Registry;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
use tracing_test::traced_test;

use crate::key_server_options::{CommitteeState, ServerMode};
use crate::master_keys::MasterKeys;
use crate::metrics::KeyServerMetrics;
use crate::start_server_background_tasks;
use crate::tests::SealTestCluster;

use crate::common::{HEADER_CLIENT_SDK_TYPE, HEADER_CLIENT_SDK_VERSION, SDK_TYPE_AGGREGATOR};
use crate::errors::InternalError::Failure;
use crate::signed_message::signed_request;
use crate::tests::externals::get_key;
use crate::tests::test_utils::{
    build_partial_key_servers, create_committee_key_server_onchain, create_test_server,
    execute_programmable_transaction,
};
use crate::tests::whitelist::{add_user_to_whitelist, create_whitelist, whitelist_create_ptb};
use crate::{app, time, Certificate, DefaultEncoding, FetchKeyRequest};
use axum::body::Body;
use axum::extract::Request;
use crypto::ibe::generate_key_pair;
use crypto::ibe::{self, MasterKey, ProofOfPossession};
use crypto::{elgamal, DST_POP};
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::ed25519::Ed25519PrivateKey;
use fastcrypto::encoding::{Base64, Encoding, Hex};
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::{bls12381::G1Element, HashToGroupElement, Pairing};
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
use std::time::Duration;
use sui_rpc::client::Client as SuiGrpcClient;
use sui_sdk_types::Address;
use sui_types::base_types::{ObjectID, SuiAddress};
use sui_types::crypto::Signature;
use sui_types::signature::GenericSignature;
use tokio::net::TcpListener;

#[traced_test]
#[tokio::test]
async fn test_rgp_updater() {
    let mut tc = SealTestCluster::new(0, "seal").await;

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
    let mut tc = SealTestCluster::new(0, "seal").await;
    let (seal_package, _) = tc.publish("seal").await;

    tc.add_open_server(seal_package).await;

    let metrics_registry = Registry::default();
    let metrics = Arc::new(KeyServerMetrics::new(&metrics_registry));

    let (reference_gas_price_receiver, monitor_handle) = start_server_background_tasks(
        Arc::new(tc.server().clone()),
        metrics.clone(),
        metrics_registry.clone(),
    )
    .await;

    // Drop the receiver to trigger the panic in the background
    // spawn_latest_checkpoint_timestamp_updater task.
    drop(reference_gas_price_receiver);

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

        // Old client SDK version. Should fail with 426 Upgrade Required
        let response = client
            .request(
                Request::builder()
                    .uri(format!(
                        "http://{addr}/v1/service?service_id={}",
                        key_server_object_id.as_str()
                    ))
                    .header(HEADER_CLIENT_SDK_TYPE, "typescript")
                    .header(HEADER_CLIENT_SDK_VERSION, "0.3.0") // Too old (requires >=0.4.6)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 426); // Upgrade Required
        let error_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let error_json: Value = from_slice(&error_bytes).unwrap();
        assert_eq!(
            error_json.get("error").unwrap().as_str().unwrap(),
            "DeprecatedSDKVersion"
        );

        // Old aggregator version. Should fail with 426 Upgrade Required
        let response = client
            .request(
                Request::builder()
                    .uri(format!(
                        "http://{addr}/v1/service?service_id={}",
                        key_server_object_id.as_str()
                    ))
                    .header(HEADER_CLIENT_SDK_TYPE, SDK_TYPE_AGGREGATOR)
                    .header(HEADER_CLIENT_SDK_VERSION, "0.5.14") // Too old (requires >=0.5.15)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 426); // Upgrade Required
        let error_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let error_json: Value = from_slice(&error_bytes).unwrap();
        assert_eq!(
            error_json.get("error").unwrap().as_str().unwrap(),
            "DeprecatedSDKVersion"
        );

        // Valid request
        let response = client
            .request(
                Request::builder()
                    .uri(format!(
                        "http://{addr}/v1/service?service_id={}",
                        key_server_object_id.as_str()
                    ))
                    .header(HEADER_CLIENT_SDK_TYPE, "typescript")
                    .header(HEADER_CLIENT_SDK_VERSION, "0.4.11")
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
                    .header(HEADER_CLIENT_SDK_VERSION, "0.4.11")
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
                    .header(HEADER_CLIENT_SDK_VERSION, "0.4.11")
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
                    .header(HEADER_CLIENT_SDK_TYPE, "typescript")
                    .header(HEADER_CLIENT_SDK_VERSION, "0.4.11")
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

#[tokio::test]
async fn test_committee_server_hot_reload_and_verify_pop() {
    let tc = SealTestCluster::new(0, "seal_testnet").await;
    let (seal_package, _) = tc.publish("seal").await;
    let (package_id, _) = tc.registry;

    // Test data for master share before rotation, party 0.
    let master_share_0_bytes =
        Hex::decode("0x2c8e06a3ba09ff64b841d39df9534e35cee33605033003a634fe6ca2a90c216d").unwrap();
    let master_share_0 =
        MasterKey::from_byte_array(master_share_0_bytes.as_slice().try_into().unwrap()).unwrap();
    let partial_pk_0 = ibe::public_key_from_master_key(&master_share_0);
    let party_id_0 = 0;

    // New master share after rotation, party 0 becomes party 1.
    let master_share_1_bytes =
        Hex::decode("0x03899294f5e6551631fcbaea5583367fb565471adeccb220b769879c55e66ed9").unwrap();
    let master_share_1 =
        MasterKey::from_byte_array(master_share_1_bytes.as_slice().try_into().unwrap()).unwrap();
    let partial_pk_1 = ibe::public_key_from_master_key(&master_share_1);
    let party_id_1 = 1;

    let master_pk = G2Element::zero();
    let member_address = tc.test_cluster().get_address_0();

    // Create on-chain a committee mode KeyServer with one partial key server (party_id_0, partial_pk_0).
    let key_server_id = create_committee_key_server_onchain(
        tc.test_cluster(),
        package_id,
        member_address,
        &partial_pk_0,
        party_id_0,
        &master_pk,
        1, // threshold
    )
    .await;

    // Get object version and digest for later update.
    let key_server_obj = tc
        .test_cluster()
        .sui_client()
        .read_api()
        .get_object_with_options(
            key_server_id,
            sui_sdk::rpc_types::SuiObjectDataOptions::default(),
        )
        .await
        .unwrap();
    let key_server_version = key_server_obj.data.as_ref().unwrap().version;
    let key_server_digest = key_server_obj.data.as_ref().unwrap().digest;

    // Initialize a server with the ks object id, rotation mode (current=0, target=1), and v0 and v1 master shares.
    let server = create_test_server(
        tc.test_cluster().sui_client().clone(),
        SuiGrpcClient::new(&tc.test_cluster().fullnode_handle.rpc_url).unwrap(),
        seal_package,
        ServerMode::Committee {
            member_address: Address::new(member_address.to_inner()),
            key_server_obj_id: Address::new(key_server_id.into_bytes()),
            committee_state: CommitteeState::Rotation { target_version: 1 },
        },
        Some(0), // onchain_version starts at 0
        [
            ("MASTER_SHARE_V0", master_share_0_bytes.as_slice()),
            ("MASTER_SHARE_V1", master_share_1_bytes.as_slice()),
        ],
    )
    .await;

    // Extract current_version pointer.
    let current_version: Arc<AtomicU32> = if let MasterKeys::Committee {
        committee_version, ..
    } = &server.master_keys
    {
        Arc::clone(committee_version)
    } else {
        panic!("Expected Committee master keys");
    };

    // Current version is 0.
    assert_eq!(current_version.load(Ordering::Relaxed), 0);

    // Update partial key servers on-chain to new partial key server (party_id_1, partial_pk_1).
    let mut builder = ProgrammableTransactionBuilder::new();
    let partial_key_servers = build_partial_key_servers(
        &mut builder,
        package_id,
        member_address,
        &partial_pk_1,
        party_id_1,
    );

    let key_server_obj = builder
        .obj(sui_types::transaction::ObjectArg::ImmOrOwnedObject((
            key_server_id,
            key_server_version,
            key_server_digest,
        )))
        .unwrap();

    let threshold = builder.pure(1u16).unwrap();
    builder.programmable_move_call(
        package_id,
        sui_types::Identifier::new("key_server").unwrap(),
        sui_types::Identifier::new("update_partial_key_servers").unwrap(),
        vec![],
        vec![key_server_obj, threshold, partial_key_servers],
    );
    execute_programmable_transaction(&tc, member_address, builder.finish()).await;

    // Refresh server.
    server.refresh_committee_server().await;

    // Verify PoP for new partial key server (party_id_1, partial_pk_1).
    let pop_map = server.key_server_oid_to_pop.read().unwrap();
    let pop = pop_map.get(&key_server_id).unwrap();
    assert!(verify_pop(pop, &key_server_id, party_id_1, &partial_pk_1).is_ok());

    // Current version updated to 1 after refresh.
    assert_eq!(current_version.load(Ordering::Relaxed), 1);
}

/// Verify that a proof-of-possession is valid for a given public key, key server object ID, and party ID.
pub fn verify_pop(
    pop: &ProofOfPossession,
    key_server_obj_id: &ObjectID,
    party_id: u16,
    public_key: &G2Element,
) -> FastCryptoResult<()> {
    // Construct the PoP message: key_server_obj_id || party_id
    let mut pop_message = Vec::new();
    pop_message.extend_from_slice(key_server_obj_id.as_ref());
    pop_message.extend_from_slice(&party_id.to_le_bytes());

    // Reconstruct the full message that was signed
    let mut full_msg = DST_POP.to_vec();
    full_msg.extend(bcs::to_bytes(public_key).map_err(|_| InvalidInput)?);
    full_msg.extend(pop_message);

    // Verify pairing.
    if pop.pairing(&G2Element::generator())
        == G1Element::hash_to_group_element(&full_msg).pairing(public_key)
    {
        Ok(())
    } else {
        Err(InvalidInput)
    }
}

#[traced_test]
#[tokio::test]
async fn test_staleness_check() {
    let mut tc = SealTestCluster::new(1, "seal").await;
    let (seal_package, _) = tc.publish("seal").await;
    tc.add_open_server_with_allowed_staleness(seal_package, Duration::from_secs(2))
        .await;

    let (examples_package_id, _) = tc.publish("patterns").await;
    let (whitelist, cap, initial_shared_version) =
        create_whitelist(tc.test_cluster(), examples_package_id).await;

    // Create test users
    let user_address = tc.users[0].address;
    add_user_to_whitelist(
        tc.test_cluster(),
        examples_package_id,
        whitelist,
        cap,
        user_address,
    )
    .await;

    let ptb = whitelist_create_ptb(examples_package_id, whitelist, initial_shared_version);

    // Calling get_key should work
    assert!(get_key(
        tc.server(),
        &examples_package_id,
        ptb.clone(),
        &tc.users[0].keypair,
    )
    .await
    .is_ok());

    // But if we stop validators and wait a few seconds, the fullnode will be stale
    tc.cluster.stop_all_validators().await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    assert_eq!(
        get_key(
            tc.server(),
            &examples_package_id,
            ptb.clone(),
            &tc.users[0].keypair,
        )
        .await,
        Err(Failure("Fullnode is stale".to_string()))
    );
}
