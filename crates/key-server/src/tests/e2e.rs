// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::errors::InternalError::UnsupportedPackageId;
use crate::key_server_options::{
    ClientConfig, ClientKeyType, KeyServerOptions, RetryConfig, RpcConfig, ServerMode,
};
use crate::master_keys::MasterKeys;
use crate::sui_rpc_client::SuiRpcClient;
use crate::tests::externals::get_key;
use crate::tests::whitelist::{add_user_to_whitelist, create_whitelist, whitelist_create_ptb};
use crate::tests::SealTestCluster;
use crate::time::from_mins;
use crate::types::Network;
use crate::{DefaultEncoding, Server};
use crypto::elgamal::encrypt;
use crypto::ibe::{extract, generate_seed, public_key_from_master_key, UserSecretKey};
use crypto::{
    create_full_id, ibe, seal_decrypt, seal_encrypt, EncryptionInput, IBEPublicKeys,
    IBEUserSecretKeys,
};
use fastcrypto::encoding::Encoding;
use fastcrypto::serde_helpers::ToFromByteArray;
use futures::future::join_all;
use rand::thread_rng;
use seal_sdk::types::{DecryptionKey, FetchKeyResponse};
use seal_sdk::{genkey, seal_decrypt_all_objects};
use semver::VersionReq;
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;
use sui_rpc::client::v2::Client as SuiGrpcClient;
use sui_sdk::SuiClient;
use sui_sdk_types::Address as NewObjectID;
use sui_types::base_types::ObjectID;
use sui_types::crypto::get_key_pair_from_rng;
use test_cluster::TestClusterBuilder;
use tracing_test::traced_test;

#[traced_test]
#[tokio::test]
async fn test_e2e() {
    let mut tc = SealTestCluster::new(1).await;
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
    let mut tc = SealTestCluster::new(1).await;

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

    let decrypted =
        seal_decrypt_all_objects(&eg_sk, &seal_responses, &encrypted_objects, &server_pk_map)
            .unwrap();

    assert_eq!(decrypted.len(), 2);
    assert_eq!(decrypted[0], message1);
    assert_eq!(decrypted[1], message2);
}

#[traced_test]
#[tokio::test]
async fn test_e2e_decrypt_all_objects_missing_servers() {
    let mut tc = SealTestCluster::new(1).await;
    tc.add_open_servers(3).await;

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

    // Scenario A - One server is missing, but threshold is reached
    seal_responses.remove(0);

    let encrypted_objects = vec![encryption1.clone(), encryption2.clone()];

    let decrypted =
        seal_decrypt_all_objects(&eg_sk, &seal_responses, &encrypted_objects, &server_pk_map)
            .unwrap();

    assert_eq!(decrypted.len(), 2);
    assert_eq!(decrypted[0], message1);
    assert_eq!(decrypted[1], message2);

    // Scenario B - A second server is missing, threshold no longer reached

    seal_responses.remove(0);

    let encrypted_objects = vec![encryption1, encryption2];

    let decrypted_result =
        seal_decrypt_all_objects(&eg_sk, &seal_responses, &encrypted_objects, &server_pk_map);

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
        seal_package,
    )
    .await;

    // The client on the second server has a single (random) package id
    let server2 = create_server(
        cluster.sui_client().clone(),
        grpc_client,
        vec![ClientConfig {
            name: "Client on server 2".to_string(),
            client_master_key: ClientKeyType::Derived {
                derivation_index: 0,
            },
            key_server_object_id: ObjectID::random(),
            package_ids: vec![ObjectID::random()],
        }],
        [("MASTER_KEY", [0u8; 32].as_slice())],
        seal_package,
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
        vec![ClientConfig {
            name: "Key server client 1".to_string(),
            client_master_key: ClientKeyType::Derived {
                derivation_index: 0u64,
            },
            key_server_object_id,
            package_ids: vec![package_id],
        }],
        [("MASTER_KEY", seed.as_slice())],
        seal_package,
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
        seal_package,
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
        seal_package,
    )
    .await;

    assert!(get_key(&server3, &package_id, ptb.clone(), &user_keypair)
        .await
        .is_err_and(|e| e == UnsupportedPackageId));
}

async fn create_server(
    sui_client: SuiClient,
    sui_grpc_client: SuiGrpcClient,
    client_configs: Vec<ClientConfig>,
    vars: impl AsRef<[(&str, &[u8])]>,
    seal_package: ObjectID,
) -> Server {
    let options = KeyServerOptions {
        network: Network::TestCluster,
        server_mode: ServerMode::Permissioned { client_configs },
        metrics_host_port: 0,
        rgp_update_interval: Duration::from_secs(60),
        sdk_version_requirement: VersionReq::from_str(">=0.4.6").unwrap(),
        allowed_staleness: Duration::from_secs(120),
        session_key_ttl_max: from_mins(30),
        rpc_config: RpcConfig::default(),
        metrics_push_config: None,
        seal_package,
    };

    let vars = vars
        .as_ref()
        .iter()
        .map(|(k, v)| (k.to_string(), Some(DefaultEncoding::encode(v))))
        .collect::<Vec<_>>();

    Server {
        sui_rpc_client: SuiRpcClient::new(
            sui_client,
            sui_grpc_client,
            RetryConfig::default(),
            None,
        ),
        master_keys: temp_env::with_vars(vars, || MasterKeys::load(&options)).unwrap(),
        key_server_oid_to_pop: HashMap::new(),
        options,
    }
}
