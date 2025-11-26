// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::errors::InternalError::UnsupportedPackageId;
use crate::key_server_options::{ClientConfig, ClientKeyType, CommitteeState};
use crate::master_keys::MasterKeys;
use crate::tests::externals::get_key;
use crate::tests::test_utils::{create_committee_servers, create_server};
use crate::tests::whitelist::{add_user_to_whitelist, create_whitelist, whitelist_create_ptb};
use crate::tests::SealTestCluster;
use crypto::elgamal::encrypt;
use crypto::ibe::{extract, generate_seed, public_key_from_master_key, UserSecretKey};
use crypto::{
    create_full_id, ibe, seal_decrypt, seal_encrypt, EncryptedObject, EncryptionInput,
    IBEPublicKeys, IBEUserSecretKeys,
};
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::groups::bls12381::G1Element;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto_tbls::{
    tbls::{PartialSignature, ThresholdBls},
    types::ThresholdBls12381MinSig,
};
use futures::future::join_all;
use rand::seq::SliceRandom;
use rand::thread_rng;
use seal_sdk::types::{DecryptionKey, FetchKeyResponse};
use seal_sdk::{decrypt_seal_responses, genkey, seal_decrypt_object};
use std::collections::HashMap;
use std::num::NonZeroU16;
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use sui_rpc::client::Client as SuiGrpcClient;
use sui_sdk_types::Address as NewObjectID;
use sui_types::base_types::ObjectID;
use sui_types::crypto::get_key_pair_from_rng;
use test_cluster::TestClusterBuilder;
use tracing_test::traced_test;

#[traced_test]
#[tokio::test]
async fn test_e2e() {
    let mut tc = SealTestCluster::new(1, "seal").await;
    let (seal_package, _) = tc.publish("seal").await;
    tc.add_open_servers(3, seal_package).await;

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

    // Read the public keys from the service objects
    let services = tc.get_services();
    let services_ids = services
        .clone()
        .into_iter()
        .map(|id| NewObjectID::new(id.into_bytes()))
        .collect::<Vec<_>>();
    let pks = IBEPublicKeys::BonehFranklinBLS12381(tc.get_public_keys(&services).await);

    // Encrypt a message
    let message = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
    let encryption = seal_encrypt(
        NewObjectID::new(examples_package_id.into_bytes()),
        whitelist.to_vec(),
        services_ids.clone(),
        &pks,
        2,
        EncryptionInput::Aes256Gcm {
            data: message.to_vec(),
            aad: None,
        },
    )
    .unwrap()
    .0;

    // Get keys from two key servers
    let ptb = whitelist_create_ptb(examples_package_id, whitelist, initial_shared_version);
    let usks = join_all(tc.servers[..2].iter().map(async |(_, server)| {
        get_key(
            server,
            &examples_package_id,
            ptb.clone(),
            &tc.users[0].keypair,
        )
        .await
        .unwrap()
    }))
    .await;

    // Decrypt the message
    let decryption = seal_decrypt(
        &encryption,
        &IBEUserSecretKeys::BonehFranklinBLS12381(services_ids.into_iter().zip(usks).collect()),
        Some(&pks),
    )
    .unwrap();

    assert_eq!(decryption, message);
}

#[traced_test]
#[tokio::test]
async fn test_e2e_decrypt_all_objects() {
    let mut tc = SealTestCluster::new(1, "seal").await;
    let (examples_package_id, _) = tc.publish("patterns").await;
    let (seal_package, _) = tc.publish("seal").await;

    tc.add_open_servers(3, seal_package).await;

    let (whitelist, cap, _initial_shared_version) =
        create_whitelist(tc.test_cluster(), examples_package_id).await;

    let user_address = tc.users[0].address;
    add_user_to_whitelist(
        tc.test_cluster(),
        examples_package_id,
        whitelist,
        cap,
        user_address,
    )
    .await;

    let services = tc.get_services();
    let services_ids = services
        .clone()
        .into_iter()
        .map(|id| NewObjectID::new(id.into_bytes()))
        .collect::<Vec<_>>();
    let pks = IBEPublicKeys::BonehFranklinBLS12381(tc.get_public_keys(&services).await);

    let message1 = b"First message";
    let message2 = b"Second message";

    let id1 = vec![1, 2, 3, 4];
    let id2 = vec![5, 6, 7, 8];

    let encryption1 = seal_encrypt(
        NewObjectID::new(examples_package_id.into_bytes()),
        id1.clone(),
        services_ids.clone(),
        &pks,
        2,
        EncryptionInput::Aes256Gcm {
            data: message1.to_vec(),
            aad: None,
        },
    )
    .unwrap()
    .0;

    let encryption2 = seal_encrypt(
        NewObjectID::new(examples_package_id.into_bytes()),
        id2.clone(),
        services_ids.clone(),
        &pks,
        2,
        EncryptionInput::Aes256Gcm {
            data: message2.to_vec(),
            aad: None,
        },
    )
    .unwrap()
    .0;

    let eg_keys = genkey::<UserSecretKey, crypto::ibe::PublicKey, _>(&mut thread_rng());
    let (eg_sk, eg_pk, _) = eg_keys;

    let full_id1 = create_full_id(&examples_package_id.into_bytes(), &id1);
    let full_id2 = create_full_id(&examples_package_id.into_bytes(), &id2);

    let mut seal_responses = Vec::new();
    let mut server_pk_map = HashMap::new();

    for (service_id, server) in tc.servers.iter() {
        let master_keys = &server.master_keys;
        let master_key = master_keys.get_key_for_key_server(service_id).unwrap();

        let usk1 = extract(master_key, &full_id1);
        let usk2 = extract(master_key, &full_id2);

        let enc_usk1 = encrypt(&mut thread_rng(), &usk1, &eg_pk);
        let enc_usk2 = encrypt(&mut thread_rng(), &usk2, &eg_pk);

        let response = FetchKeyResponse {
            decryption_keys: vec![
                DecryptionKey {
                    id: full_id1.clone(),
                    encrypted_key: enc_usk1,
                },
                DecryptionKey {
                    id: full_id2.clone(),
                    encrypted_key: enc_usk2,
                },
            ],
        };

        let service_id_sdk = NewObjectID::new(service_id.into_bytes());
        seal_responses.push((service_id_sdk, response));

        let public_key = public_key_from_master_key(master_key);
        server_pk_map.insert(service_id_sdk, public_key);
    }

    let encrypted_objects = vec![encryption1, encryption2];

    // Decrypt all keys from all servers at once
    let cached_keys = decrypt_seal_responses(&eg_sk, &seal_responses, &server_pk_map).unwrap();

    // Decrypt each object using the cached keys
    let decrypted1 =
        seal_decrypt_object(&encrypted_objects[0], &cached_keys, &server_pk_map).unwrap();
    let decrypted2 =
        seal_decrypt_object(&encrypted_objects[1], &cached_keys, &server_pk_map).unwrap();

    assert_eq!(decrypted1, message1);
    assert_eq!(decrypted2, message2);
}

#[traced_test]
#[tokio::test]
async fn test_e2e_decrypt_all_objects_missing_servers() {
    let mut tc = SealTestCluster::new(1, "seal").await;
    let (seal_package, _) = tc.publish("seal").await;
    tc.add_open_servers(3, seal_package).await;

    let (examples_package_id, _) = tc.publish("patterns").await;

    let (whitelist, cap, _initial_shared_version) =
        create_whitelist(tc.test_cluster(), examples_package_id).await;

    let user_address = tc.users[0].address;
    add_user_to_whitelist(
        tc.test_cluster(),
        examples_package_id,
        whitelist,
        cap,
        user_address,
    )
    .await;

    let services = tc.get_services();
    let services_ids = services
        .clone()
        .into_iter()
        .map(|id| NewObjectID::new(id.into_bytes()))
        .collect::<Vec<_>>();
    let pks = IBEPublicKeys::BonehFranklinBLS12381(tc.get_public_keys(&services).await);

    let message1 = b"First message";
    let message2 = b"Second message";

    let id1 = vec![1, 2, 3, 4];
    let id2 = vec![5, 6, 7, 8];

    let encryption1 = seal_encrypt(
        NewObjectID::new(examples_package_id.into_bytes()),
        id1.clone(),
        services_ids.clone(),
        &pks,
        2,
        EncryptionInput::Aes256Gcm {
            data: message1.to_vec(),
            aad: None,
        },
    )
    .unwrap()
    .0;

    let encryption2 = seal_encrypt(
        NewObjectID::new(examples_package_id.into_bytes()),
        id2.clone(),
        services_ids.clone(),
        &pks,
        2,
        EncryptionInput::Aes256Gcm {
            data: message2.to_vec(),
            aad: None,
        },
    )
    .unwrap()
    .0;

    let eg_keys = genkey::<UserSecretKey, crypto::ibe::PublicKey, _>(&mut thread_rng());
    let (eg_sk, eg_pk, _) = eg_keys;

    let full_id1 = create_full_id(&examples_package_id.into_bytes(), &id1);
    let full_id2 = create_full_id(&examples_package_id.into_bytes(), &id2);

    let mut seal_responses = Vec::new();
    let mut server_pk_map = HashMap::new();

    for (service_id, server) in tc.servers.iter() {
        let master_keys = &server.master_keys;
        let master_key = master_keys.get_key_for_key_server(service_id).unwrap();

        let usk1 = extract(master_key, &full_id1);
        let usk2 = extract(master_key, &full_id2);

        let enc_usk1 = encrypt(&mut thread_rng(), &usk1, &eg_pk);
        let enc_usk2 = encrypt(&mut thread_rng(), &usk2, &eg_pk);

        let response = FetchKeyResponse {
            decryption_keys: vec![
                DecryptionKey {
                    id: full_id1.clone(),
                    encrypted_key: enc_usk1,
                },
                DecryptionKey {
                    id: full_id2.clone(),
                    encrypted_key: enc_usk2,
                },
            ],
        };

        let service_id_sdk = NewObjectID::new(service_id.into_bytes());
        seal_responses.push((service_id_sdk, response));

        let public_key = public_key_from_master_key(master_key);
        server_pk_map.insert(service_id_sdk, public_key);
    }

    // Scenario A - One server is missing, but threshold (=2) is still reached
    seal_responses.remove(0);

    let encrypted_objects = vec![encryption1.clone(), encryption2.clone()];

    // Decrypt all keys from remaining servers at once
    let cached_keys = decrypt_seal_responses(&eg_sk, &seal_responses, &server_pk_map).unwrap();

    // Decrypt each object using the cached keys
    let decrypted1 =
        seal_decrypt_object(&encrypted_objects[0], &cached_keys, &server_pk_map).unwrap();
    let decrypted2 =
        seal_decrypt_object(&encrypted_objects[1], &cached_keys, &server_pk_map).unwrap();

    assert_eq!(decrypted1, message1);
    assert_eq!(decrypted2, message2);

    // Scenario B - A second server is missing, threshold no longer reached
    seal_responses.remove(0);

    let encrypted_objects = vec![encryption1, encryption2];

    // Only 1 server remaining - not enough for threshold=2
    let cached_keys = decrypt_seal_responses(&eg_sk, &seal_responses, &server_pk_map).unwrap();

    // Try to decrypt object - should fail due to insufficient keys (threshold=2 but only 1 server)
    let decrypted_result = seal_decrypt_object(&encrypted_objects[0], &cached_keys, &server_pk_map);

    assert!(decrypted_result.is_err());
}

#[traced_test]
#[tokio::test]
async fn test_e2e_permissioned() {
    // e2e test with two key servers, each with two clients

    // TODO: Use test framework

    // Create a test cluster
    let cluster = TestClusterBuilder::new()
        .with_num_validators(1)
        .build()
        .await;
    let grpc_client = SuiGrpcClient::new(&cluster.fullnode_handle.rpc_url).unwrap();
    // Publish the patterns package
    let package_id = SealTestCluster::publish_internal(&cluster, "patterns")
        .await
        .0;
    let seal_package = SealTestCluster::publish_internal(&cluster, "seal").await.0;

    // Generate a master seed for the first key server
    let mut rng = thread_rng();
    let seed = generate_seed(&mut rng);

    // Sample random key server object id.
    let key_server_object_id = ObjectID::random();

    // The client handles two package ids, one per client
    let server1 = create_server(
        cluster.sui_client().clone(),
        grpc_client.clone(),
        seal_package,
        vec![
            ClientConfig {
                name: "Client 1 on server 1".to_string(),
                client_master_key: ClientKeyType::Derived {
                    derivation_index: 0,
                },
                key_server_object_id,
                package_ids: vec![ObjectID::random(), (*package_id).into()],
            },
            ClientConfig {
                name: "Client 2 on server 1".to_string(),
                client_master_key: ClientKeyType::Derived {
                    derivation_index: 1,
                },
                key_server_object_id: ObjectID::random(),
                package_ids: vec![ObjectID::random()],
            },
        ],
        [("MASTER_KEY", seed.as_slice())],
    )
    .await;

    // The client on the second server has a single (random) package id
    let server2 = create_server(
        cluster.sui_client().clone(),
        grpc_client,
        seal_package,
        vec![ClientConfig {
            name: "Client on server 2".to_string(),
            client_master_key: ClientKeyType::Derived {
                derivation_index: 0,
            },
            key_server_object_id: ObjectID::random(),
            package_ids: vec![ObjectID::random()],
        }],
        [("MASTER_KEY", [0u8; 32].as_slice())],
    )
    .await;

    // Create test user
    let (address, user_keypair) = get_key_pair_from_rng(&mut rng);

    // Create a whitelist for the first package and add the user
    let (whitelist, cap, initial_shared_version) = create_whitelist(&cluster, package_id).await;
    add_user_to_whitelist(&cluster, package_id, whitelist, cap, address).await;

    // Since the key server is not registered on-chain, we derive the master key from the key pair
    let derived_master_key = ibe::derive_master_key(&seed, 0);
    let pk = public_key_from_master_key(&derived_master_key);
    let pks = IBEPublicKeys::BonehFranklinBLS12381(vec![pk]);

    // This is encrypted using just the client on the first server
    let services = vec![key_server_object_id];
    let services_ids = services
        .clone()
        .into_iter()
        .map(|id| NewObjectID::new(id.into_bytes()))
        .collect::<Vec<_>>();
    // Encrypt a message
    let message = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
    let encryption = seal_encrypt(
        NewObjectID::new(package_id.into_bytes()),
        whitelist.to_vec(),
        services_ids.to_vec(),
        &pks,
        1,
        EncryptionInput::Aes256Gcm {
            data: message.to_vec(),
            aad: None,
        },
    )
    .unwrap()
    .0;

    // Requesting a user secret key on the second server should fail
    let ptb = whitelist_create_ptb(package_id, whitelist, initial_shared_version);
    assert!(get_key(&server2, &package_id, ptb.clone(), &user_keypair)
        .await
        .is_err_and(|e| e == UnsupportedPackageId));

    // But from the first server it should succeed
    let usk = get_key(&server1, &package_id, ptb.clone(), &user_keypair)
        .await
        .unwrap();

    // Decrypt the message
    let decryption = seal_decrypt(
        &encryption,
        &IBEUserSecretKeys::BonehFranklinBLS12381(services_ids.into_iter().zip([usk]).collect()),
        Some(&pks),
    )
    .unwrap();

    assert_eq!(decryption, message);
}

#[traced_test]
#[tokio::test]
async fn test_e2e_imported_key() {
    // Test import/export of a derived key:
    // 1. Encrypt using a derived key from Server 1. Check that decrypting using Server 1 works.
    // 2. Import the derived key into Server 2. Check that decrypting using Server 2 works.
    // 3. Create a Server 3 which is a copy of Server 1, but with the derived key marked as exported. Check that decrypting using Server 3 fails.

    // TODO: Use test framework

    // Create a test cluster
    let cluster = TestClusterBuilder::new()
        .with_num_validators(1)
        .build()
        .await;
    let grpc_client = SuiGrpcClient::new(&cluster.fullnode_handle.rpc_url).unwrap();
    // Publish the patterns two times.
    let package_id = SealTestCluster::publish_internal(&cluster, "patterns")
        .await
        .0;
    let seal_package = SealTestCluster::publish_internal(&cluster, "seal").await.0;

    // Generate a key pair for the key server
    let mut rng = thread_rng();
    let seed = generate_seed(&mut rng);

    // Sample random key server object ids. Note that the key servers are not registered on-chain in this test.
    let key_server_object_id = ObjectID::random();

    // Server has a single client with a single package id (the one published above)
    let server1 = create_server(
        cluster.sui_client().clone(),
        grpc_client.clone(),
        seal_package,
        vec![ClientConfig {
            name: "Key server client 1".to_string(),
            client_master_key: ClientKeyType::Derived {
                derivation_index: 0u64,
            },
            key_server_object_id,
            package_ids: vec![package_id],
        }],
        [("MASTER_KEY", seed.as_slice())],
    )
    .await;

    // Create test user
    let (address, user_keypair) = get_key_pair_from_rng(&mut rng);

    // Create a whitelist for the first package and add the user
    let (whitelist, cap, initial_shared_version) = create_whitelist(&cluster, package_id).await;
    add_user_to_whitelist(&cluster, package_id, whitelist, cap, address).await;

    // Since the key servers are not registered on-chain, we derive the master key from the key pair
    let derived_master_key = ibe::derive_master_key(&seed, 0);
    let pk = public_key_from_master_key(&derived_master_key);
    let pks = IBEPublicKeys::BonehFranklinBLS12381(vec![pk]);

    // This is encrypted using just the first client
    let services = vec![key_server_object_id];
    let services_ids = services
        .clone()
        .into_iter()
        .map(|id| NewObjectID::new(id.into_bytes()))
        .collect::<Vec<_>>();
    // Encrypt a message
    let message = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
    let encryption = seal_encrypt(
        NewObjectID::new(package_id.into_bytes()),
        whitelist.to_vec(),
        services_ids.clone().to_vec(),
        &pks,
        1,
        EncryptionInput::Aes256Gcm {
            data: message.to_vec(),
            aad: None,
        },
    )
    .unwrap()
    .0;

    // Construct PTB
    let ptb = whitelist_create_ptb(package_id, whitelist, initial_shared_version);

    // Decrypting should succeed
    let usk = get_key(&server1, &package_id, ptb.clone(), &user_keypair)
        .await
        .unwrap();

    // Decrypt the message
    let decryption = seal_decrypt(
        &encryption,
        &IBEUserSecretKeys::BonehFranklinBLS12381(
            services_ids.clone().into_iter().zip([usk]).collect(),
        ),
        Some(&pks),
    )
    .unwrap();

    assert_eq!(decryption, message);

    // Import the master key for a client into a second server
    let server2 = create_server(
        cluster.sui_client().clone(),
        grpc_client.clone(),
        seal_package,
        vec![ClientConfig {
            name: "Key server client 2".to_string(),
            client_master_key: ClientKeyType::Imported {
                env_var: "IMPORTED_MASTER_KEY".to_string(),
            },
            key_server_object_id: ObjectID::random(),
            package_ids: vec![package_id],
        }],
        [
            (
                "IMPORTED_MASTER_KEY",
                derived_master_key.to_byte_array().as_slice(),
            ),
            ("MASTER_KEY", [0u8; 32].as_slice()),
        ],
    )
    .await;

    // Getting a key from server 2 should now succeed
    let usk = get_key(&server2, &package_id, ptb.clone(), &user_keypair)
        .await
        .unwrap();

    // Decrypt the message
    let decryption = seal_decrypt(
        &encryption,
        &IBEUserSecretKeys::BonehFranklinBLS12381(services_ids.into_iter().zip([usk]).collect()),
        Some(&pks),
    )
    .unwrap();

    assert_eq!(decryption, message);

    // Create a new key server where the derived key is marked as exported
    let server3 = create_server(
        cluster.sui_client().clone(),
        grpc_client,
        seal_package,
        vec![
            ClientConfig {
                name: "Key server client 3.0".to_string(),
                client_master_key: ClientKeyType::Exported {
                    deprecated_derivation_index: 0,
                },
                key_server_object_id,
                package_ids: vec![package_id],
            },
            ClientConfig {
                name: "Key server client 3.1".to_string(),
                client_master_key: ClientKeyType::Derived {
                    derivation_index: 1,
                },
                key_server_object_id: ObjectID::random(),
                package_ids: vec![ObjectID::random()],
            },
        ],
        [("MASTER_KEY", seed.as_slice())],
    )
    .await;

    assert!(get_key(&server3, &package_id, ptb.clone(), &user_keypair)
        .await
        .is_err_and(|e| e == UnsupportedPackageId));
}

#[traced_test]
#[tokio::test]
async fn test_e2e_committee_mode_with_rotation() {
    // Create a test cluster.
    let cluster = TestClusterBuilder::new()
        .with_num_validators(1)
        .build()
        .await;
    let grpc_client = SuiGrpcClient::new(&cluster.fullnode_handle.rpc_url).unwrap();

    // Publish the patterns package.
    let package_id = SealTestCluster::publish_internal(&cluster, "patterns")
        .await
        .0;
    let seal_package = SealTestCluster::publish_internal(&cluster, "seal").await.0;

    // Fresh DKG shares from parties 0, 1, 2 (t=2).
    let master_shares = [
        "0x2c8e06a3ba09ff64b841d39df9534e35cee33605033003a634fe6ca2a90c216d",
        "0x69802da036d15184daa8e444a97e2390d2ab370d94a37f29209006546d61be0d",
        "0x3284ad4989fb265cc9d61ce3500720e682b5941326189ead0c21a00731b75aac",
    ];

    // Rotated shares for parties 0, 1, 3, 4 (t=3 after rotation). Party 2 is leaving.
    let next_master_shares = [
        Some("0x03899294f5e6551631fcbaea5583367fb565471adeccb220b769879c55e66ed9"),
        Some("0x11761fd7d8719dc4297418768ffd3578ecc348e516cbbe2d9de36b6965353182"),
        None,
        Some("0x39c3df31bf3e5082e2ae825aa35c53f478bed3a0c9bdbffb95ff2788b6ca3cd3"),
        Some("0x40375e5b0adc12c2084f96bf6fe6b5d1e3124a73d7a08bbf39a44b2f87e09b6f"),
    ];

    // Committee member addresses for parties 0, 1, 2, 3, 4.
    let member_addresses = [
        "0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d",
        "0xe6a37ff5cd968b6a666fb033d85eabc674449f44f9fc2b600e55e27354211ed6",
        "0x223762117ab21a439f0f3f3b0577e838b8b26a37d9a1723a4be311243f4461b9",
        "0x5c8a9a87b0f84c6e92d3f1a4b7e0c6d3f2a9e8b5c4d1a0f7e9b2c3d5a6f8e1b4",
        "0x7d9b8e6a5c4f3d2e1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8",
    ]
    .map(|addr| NewObjectID::from_str(addr).unwrap());

    // Key server aggregated public key finalized from DKG.
    let aggregated_pk_bytes = Hex::decode("0x95a35c03681de93032e9a0544b9b8533ffd7fabe1e70b29a844030237e84789c0c34c0e5a5b12a33e345599ba90f096f17ddd3a8586a4a0de28c13e249c3767026a4bbdb4343885b50115931f8e8a77d735d269ac5a5eca05787d0b91c4a5ffb").unwrap();
    let aggregated_pk =
        ibe::PublicKey::from_byte_array(&aggregated_pk_bytes.try_into().unwrap()).unwrap();
    let pks = IBEPublicKeys::BonehFranklinBLS12381(vec![aggregated_pk]);

    // Use a test key server object id.
    let key_server_object_id = NewObjectID::new(ObjectID::random().into_bytes());

    // Create test user and add to whitelist.
    let (address, user_keypair) = get_key_pair_from_rng(&mut thread_rng());
    let user_keypair = Arc::new(user_keypair);
    let (whitelist, cap, initial_shared_version) = create_whitelist(&cluster, package_id).await;
    add_user_to_whitelist(&cluster, package_id, whitelist, cap, address).await;
    let ptb = whitelist_create_ptb(package_id, whitelist, initial_shared_version);

    // Encrypt a message with key server pk.
    let message = b"Hello, world!";
    let encryption = seal_encrypt(
        NewObjectID::new(package_id.into_bytes()),
        whitelist.to_vec(),
        vec![key_server_object_id],
        &pks,
        1, // Always use 1 for committee mode.
        EncryptionInput::Aes256Gcm {
            data: message.to_vec(),
            aad: None,
        },
    )
    .unwrap()
    .0;

    // Create initial committee servers (parties 0, 1, 2).
    let mut servers = Vec::new();

    // Parties 0, 1: rotation in progress (current=0, target=1), both have two shares.
    servers.extend(
        create_committee_servers(
            cluster.sui_client().clone(),
            grpc_client.clone(),
            seal_package,
            key_server_object_id,
            member_addresses[0..2].to_vec(),
            vec![
                vec![
                    ("MASTER_SHARE_V0", Hex::decode(master_shares[0]).unwrap()),
                    (
                        "MASTER_SHARE_V1",
                        Hex::decode(next_master_shares[0].unwrap()).unwrap(),
                    ),
                ],
                vec![
                    ("MASTER_SHARE_V0", Hex::decode(master_shares[1]).unwrap()),
                    (
                        "MASTER_SHARE_V1",
                        Hex::decode(next_master_shares[1].unwrap()).unwrap(),
                    ),
                ],
            ],
            0, // onchain_version
            CommitteeState::Rotation { target_version: 1 },
        )
        .await,
    );

    // Party 2: Active mode at version 0 (leaving committee, just v0 share).
    servers.extend(
        create_committee_servers(
            cluster.sui_client().clone(),
            grpc_client.clone(),
            seal_package,
            key_server_object_id,
            vec![member_addresses[2]],
            vec![vec![(
                "MASTER_SHARE_V0",
                Hex::decode(master_shares[2]).unwrap(),
            )]],
            0, // onchain_version
            CommitteeState::Active,
        )
        .await,
    );

    // Fresh DKG committee: parties 0, 1, 2.
    let committee = [&servers[0], &servers[1], &servers[2]];

    // Randomly select 2 out of 3 parties.
    let mut rng = thread_rng();
    let party_ids: Vec<u8> = vec![0, 1, 2];
    let selected_party_ids: Vec<u8> = party_ids.choose_multiple(&mut rng, 2).copied().collect();

    // Fetch keys from selected parties.
    let usks_with_party_ids: Vec<(u8, G1Element)> =
        join_all(selected_party_ids.iter().map(|&party_id| {
            let ptb = ptb.clone();
            let user_keypair = Arc::clone(&user_keypair);
            let server = committee[party_id as usize];
            async move {
                let usk = get_key(server, &package_id, ptb, &user_keypair)
                    .await
                    .unwrap();
                (party_id, usk)
            }
        }))
        .await;

    // Decrypt ok with 2 out of 3 servers.
    let decryption = decrypt_with_threshold_and_party_ids(
        2,
        usks_with_party_ids,
        key_server_object_id,
        &encryption,
        &pks,
    );
    assert_eq!(decryption, message);

    // Manually update current version = target version for party 0 and 1 servers.
    servers.iter().for_each(|server| {
        if let MasterKeys::Committee {
            committee_version, ..
        } = &server.master_keys
        {
            committee_version.store(1, Ordering::Relaxed);
        }
    });

    // Add party 3 and 4 with only MASTER_SHARE_V1 from the dkg rotation.
    let new_servers = create_committee_servers(
        cluster.sui_client().clone(),
        grpc_client.clone(),
        seal_package,
        key_server_object_id,
        vec![member_addresses[3], member_addresses[4]],
        vec![
            vec![(
                "MASTER_SHARE_V1",
                Hex::decode(next_master_shares[3].unwrap()).unwrap(),
            )],
            vec![(
                "MASTER_SHARE_V1",
                Hex::decode(next_master_shares[4].unwrap()).unwrap(),
            )],
        ],
        1, // onchain_version
        CommitteeState::Active,
    )
    .await;

    // Set up new committee. Parties 0,1 from old committee (swapped), parties 3,4 new, all at version 1.
    let new_committee = [&servers[1], &servers[0], &new_servers[0], &new_servers[1]];

    // Randomly select 3 out of 4 parties.
    let selected_new_party_ids: Vec<u8> =
        [0, 1, 2, 3].choose_multiple(&mut rng, 3).copied().collect();

    // Fetch keys from selected parties.
    let new_usks_with_party_ids: Vec<(u8, G1Element)> =
        join_all(selected_new_party_ids.iter().map(|&party_id| {
            let ptb = ptb.clone();
            let user_keypair = Arc::clone(&user_keypair);
            let server = new_committee[party_id as usize];
            async move {
                let usk = get_key(server, &package_id, ptb, &user_keypair)
                    .await
                    .unwrap();
                (party_id, usk)
            }
        }))
        .await;

    // Decrypt works with new committee.
    let new_decryption = decrypt_with_threshold_and_party_ids(
        3,
        new_usks_with_party_ids,
        key_server_object_id,
        &encryption,
        &pks,
    );
    assert_eq!(new_decryption, message);
}

/// Helper function to perform threshold aggregation and decryption with party IDs.
fn decrypt_with_threshold_and_party_ids(
    threshold: u16,
    usks_with_party_ids: Vec<(u8, G1Element)>,
    key_server_object_id: NewObjectID,
    encryption: &EncryptedObject,
    pks: &IBEPublicKeys,
) -> Vec<u8> {
    let mut partial_usks = Vec::new();
    for (party_id, usk) in usks_with_party_ids.iter() {
        partial_usks.push(PartialSignature::<G1Element> {
            index: NonZeroU16::new((party_id + 1) as u16).unwrap(),
            value: *usk,
        });
    }

    let aggregated_usk =
        ThresholdBls12381MinSig::aggregate(threshold, partial_usks.iter()).unwrap();

    let usks_map: HashMap<_, _> = vec![(key_server_object_id, aggregated_usk)]
        .into_iter()
        .collect();

    seal_decrypt(
        encryption,
        &IBEUserSecretKeys::BonehFranklinBLS12381(usks_map),
        Some(pks),
    )
    .unwrap()
}
