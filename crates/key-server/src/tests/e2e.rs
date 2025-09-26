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
use crate::tests::{SealCommittee, SealTestCluster};
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
use fastcrypto::groups::bls12381::{G1Element, G2Element};
use fastcrypto::groups::GroupElement;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto_tbls::tbls::PartialSignature;
use fastcrypto_tbls::tbls::ThresholdBls;
use fastcrypto_tbls::types::ThresholdBls12381MinSig;
use futures::future::join_all;
use rand::thread_rng;
use seal_sdk::types::{DecryptionKey, FetchKeyResponse};
use seal_sdk::{genkey, seal_decrypt_all_objects};
use semver::VersionReq;
use std::collections::HashMap;
use std::num::NonZeroU16;
use std::str::FromStr;
use std::time::Duration;
use sui_sdk::SuiClient;
use sui_types::base_types::ObjectID;
use sui_types::crypto::get_key_pair_from_rng;
use test_cluster::TestClusterBuilder;
use tracing_test::traced_test;

#[traced_test]
#[tokio::test]
async fn test_e2e() {
    let mut tc = SealTestCluster::new(1, "seal").await;
    tc.add_open_servers(3).await;

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
        .map(|id| sui_sdk_types::ObjectId::new(id.into_bytes()))
        .collect::<Vec<_>>();
    let pks = IBEPublicKeys::BonehFranklinBLS12381(tc.get_public_keys(&services).await);

    // Encrypt a message
    let message = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
    let encryption = seal_encrypt(
        sui_sdk_types::ObjectId::new(examples_package_id.into_bytes()),
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
        .map(|id| sui_sdk_types::ObjectId::new(id.into_bytes()))
        .collect::<Vec<_>>();
    let pks = IBEPublicKeys::BonehFranklinBLS12381(tc.get_public_keys(&services).await);

    let message1 = b"First message";
    let message2 = b"Second message";

    let id1 = vec![1, 2, 3, 4];
    let id2 = vec![5, 6, 7, 8];

    let encryption1 = seal_encrypt(
        sui_sdk_types::ObjectId::new(examples_package_id.into_bytes()),
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
        sui_sdk_types::ObjectId::new(examples_package_id.into_bytes()),
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

        let service_id_sdk = sui_sdk_types::ObjectId::new(service_id.into_bytes());
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
async fn test_e2e_permissioned() {
    // e2e test with two key servers, each with two clients

    // TODO: Use test framework

    // Create a test cluster
    let cluster = TestClusterBuilder::new()
        .with_num_validators(1)
        .build()
        .await;

    // Publish the patterns package
    let package_id = SealTestCluster::publish_internal(&cluster, "patterns")
        .await
        .0;

    // Generate a master seed for the first key server
    let mut rng = thread_rng();
    let seed = generate_seed(&mut rng);

    // Sample random key server object id.
    let key_server_object_id = ObjectID::random();

    // The client handles two package ids, one per client
    let server1 = create_server(
        cluster.sui_client().clone(),
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
        .map(|id| sui_sdk_types::ObjectId::new(id.into_bytes()))
        .collect::<Vec<_>>();
    // Encrypt a message
    let message = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
    let encryption = seal_encrypt(
        sui_sdk_types::ObjectId::new(package_id.into_bytes()),
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

    // Publish the patterns two times.
    let package_id = SealTestCluster::publish_internal(&cluster, "patterns")
        .await
        .0;
    // Generate a key pair for the key server
    let mut rng = thread_rng();
    let seed = generate_seed(&mut rng);

    // Sample random key server object ids. Note that the key servers are not registered on-chain in this test.
    let key_server_object_id = ObjectID::random();

    // Server has a single client with a single package id (the one published above)
    let server1 = create_server(
        cluster.sui_client().clone(),
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
        .map(|id| sui_sdk_types::ObjectId::new(id.into_bytes()))
        .collect::<Vec<_>>();
    // Encrypt a message
    let message = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
    let encryption = seal_encrypt(
        sui_sdk_types::ObjectId::new(package_id.into_bytes()),
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
async fn test_e2e_mpc() {
    use crate::tests::KeyServerType::MPC;
    use fastcrypto::encoding::Hex;

    // create a test cluster with 2 funded user addresses
    let mut tc = SealTestCluster::new(2, "seal_testnet").await;

    // run 2 out of 3 servers with valid partial master keys and aggregated pk from dkg finalization
    let agg_pk = G2Element::from_byte_array(&Hex::decode("0x94d64ca6b2e72d1b83202bb4b0f483928e6b53e2392e510db24e879a54a12095c951cb8fd9362966f76069ee3af1ed0d0ab1011127436ddcc505d51b46d672537ebce6ef2ed498401e44669cb770e983d43134167a6e21d2e7931b6e7cb7ab56").unwrap().try_into().unwrap()).unwrap();
    let msks = vec![
        "0x7159148266a389a2da7056acb4a322a49ad40d32597963f02994c1cc8b5b779e",
        "0x09e0c1f70b9974f19930a83a8ed30f47fb09ab6ddd7f5d3990171f8911353d69",
        "0x165616beda2cdd888b2ad1d072a4d3f0aefcedac6183b281f6997d44970f0335",
    ]
    .into_iter()
    .map(|msk| MasterKey::from_byte_array(&Hex::decode(msk).unwrap().try_into().unwrap()).unwrap())
    .collect::<Vec<_>>();

    // set up the 2 out of 3 committee and its key server and partial key server objects
    // Initial committee uses parties 0, 1, 2
    let ordered_members = vec![
        tc.cluster.get_addresses()[0],
        tc.cluster.get_addresses()[1],
        tc.cluster.get_addresses()[2],
    ];
    let ordered_partial_pks = msks
        .iter()
        .map(|msk| public_key_from_master_key(msk).to_byte_array().to_vec())
        .collect::<Vec<_>>();
    let SealCommittee {
        key_server_id,
        partial_key_server_field_ids,
        committee_id,
        committee_package_id,
    } = tc
        .set_up_committee_server(
            ordered_members.clone(),
            ordered_partial_pks.clone(),
            agg_pk,
            2,
        )
        .await;

    // add servers to the test cluster
    for (i, msk) in msks.iter().enumerate() {
        tc.add_server(
            MPC(*msk),
            &format!("Server {}", i + 1),
            Some(partial_key_server_field_ids[i]),
        )
        .await;
    }

    // publish the package and set up the whitelist user
    let (examples_package_id, _) = tc.publish("patterns").await;
    let (whitelist, cap, initial_shared_version) =
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

    // encrypt a message
    let message = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
    let encryption = crypto::seal_encrypt(
        sui_sdk_types::ObjectId::new(examples_package_id.into_bytes()),
        whitelist.to_vec(),
        vec![sui_sdk_types::ObjectId::new(key_server_id.into_bytes())],
        &IBEPublicKeys::BonehFranklinBLS12381(vec![agg_pk]),
        1,
        EncryptionInput::Aes256Gcm {
            data: message.to_vec(),
            aad: None,
        },
    )
    .unwrap()
    .0;

    // do a bad encryption with a zero aggregated pk
    let bad_encryption = crypto::seal_encrypt(
        sui_sdk_types::ObjectId::new(examples_package_id.into_bytes()),
        whitelist.to_vec(),
        vec![sui_sdk_types::ObjectId::new(key_server_id.into_bytes())],
        &IBEPublicKeys::BonehFranklinBLS12381(vec![G2Element::zero()]),
        1,
        EncryptionInput::Aes256Gcm {
            data: message.to_vec(),
            aad: None,
        },
    )
    .unwrap()
    .0;

    // fetch partial keys from both committee member servers
    let ptb = whitelist_create_ptb(examples_package_id, whitelist, initial_shared_version);
    let mut partial_user_keys = Vec::new();

    // fetch partial keys from 2 out of 3 servers
    for i in [0, 1] {
        let partial_user_key = get_key(
            &tc.servers[i].1,
            &examples_package_id,
            ptb.clone(),
            &tc.users[0].keypair,
        )
        .await
        .unwrap();
        partial_user_keys.push(PartialSignature::<G1Element> {
            index: NonZeroU16::new(i as u16 + 1).unwrap(),
            value: partial_user_key,
        });
    }
    // aggregate with threshold 2
    let aggregated_sk = ThresholdBls12381MinSig::aggregate(2, partial_user_keys.iter()).unwrap();
    let usks = IBEUserSecretKeys::BonehFranklinBLS12381(HashMap::from([(
        sui_sdk_types::ObjectId::new(key_server_id.into_bytes()),
        aggregated_sk,
    )]));

    // decrypt the message using MPC decryption with aggregated sk
    let decryption = crypto::seal_decrypt(
        &encryption,
        &usks,
        Some(&IBEPublicKeys::BonehFranklinBLS12381(vec![agg_pk])),
    );
    assert_eq!(&decryption.unwrap(), message);

    // wrong threshold fails decryption
    let bad_aggregated_sk =
        ThresholdBls12381MinSig::aggregate(1, partial_user_keys.iter()).unwrap();
    let usks = IBEUserSecretKeys::BonehFranklinBLS12381(HashMap::from([(
        sui_sdk_types::ObjectId::new(key_server_id.into_bytes()),
        bad_aggregated_sk,
    )]));

    // decrypt the message using MPC decryption with aggregated sk
    let decryption = crypto::seal_decrypt(
        &encryption,
        &usks,
        Some(&IBEPublicKeys::BonehFranklinBLS12381(vec![agg_pk])),
    );
    assert!(decryption.is_err());

    // wrong aggregated pk fails decryption
    let decryption = crypto::seal_decrypt(
        &bad_encryption,
        &usks,
        Some(&IBEPublicKeys::BonehFranklinBLS12381(vec![agg_pk])),
    );
    assert!(decryption.is_err());

    // key rotation: new commitee 3 out of 4, new_msks derived from dkg cli for key rotation
    let new_msks = vec![
        "0x6124e4bda6b01644c10aa64457c2587c7a416d87b41eea00e37001b3c1a9e215",
        "0x00c40e198861c58e0693064d0e54b77962b099ad5fa207fe7fd3e2c807044efd",
        "0x2a3d4dad76229b577e2f84e49034b8f5325a5a79d2f0a0b1ede6c0d735726b17",
        "0x43e8978f49f44f56a475523dcaef88ee3276a889bc13e40f9f382030625dea05",
    ]
    .into_iter()
    .map(|msk| MasterKey::from_byte_array(&Hex::decode(msk).unwrap().try_into().unwrap()).unwrap())
    .collect::<Vec<_>>();

    // new committee members: [ADDRESS_1, ADDRESS_0, ADDRESS_3, ADDRESS_4]
    let new_ordered_members = vec![
        tc.cluster.get_addresses()[1],
        tc.cluster.get_addresses()[0],
        tc.cluster.get_addresses()[3],
        tc.cluster.get_addresses()[4],
    ];
    let new_ordered_partial_pks = new_msks
        .iter()
        .map(|msk| {
            public_key_from_master_key(
                &MasterKey::from_byte_array(&msk.to_byte_array().to_vec().try_into().unwrap())
                    .unwrap(),
            )
            .to_byte_array()
            .to_vec()
        })
        .collect();
    // run rotate committee onchain steps: init for rotation, register, propose and approve.
    let (_, rotated_partial_key_server_ids) = tc
        .rotate_committee(
            new_ordered_members.clone(),
            new_ordered_partial_pks,
            3,
            committee_id,
            committee_package_id,
            key_server_id,
        )
        .await;

    // add servers to the test cluster
    for (party_id, msk) in new_msks.iter().enumerate() {
        tc.add_server(
            MPC(*msk),
            &format!("Rotated Server {}", party_id),
            Some(rotated_partial_key_server_ids[party_id]),
        )
        .await;
    }

    // fetch partial keys from first 3 out of 4 servers, decrypt works
    let threshold_indices = [1, 0, 2, 3];
    let mut partial_user_keys = Vec::new();
    for i in [0, 1, 2] {
        let partial_user_key = get_key(
            &tc.servers[i].1,
            &examples_package_id,
            ptb.clone(),
            &tc.users[0].keypair,
        )
        .await
        .unwrap();

        partial_user_keys.push(PartialSignature::<G1Element> {
            index: NonZeroU16::new(threshold_indices[i] + 1).unwrap(),
            value: partial_user_key,
        });
    }

    let decryption = decrypt_message(&encryption, key_server_id, partial_user_keys, agg_pk);
    assert_eq!(&decryption, message);

    // fetch from the last 3 servers, decrypt works
    let mut partial_user_keys = Vec::new();
    for i in [0, 2, 3] {
        let partial_user_key = get_key(
            &tc.servers[i].1,
            &examples_package_id,
            ptb.clone(),
            &tc.users[0].keypair,
        )
        .await
        .unwrap();

        partial_user_keys.push(PartialSignature::<G1Element> {
            index: NonZeroU16::new(threshold_indices[i] + 1).unwrap(),
            value: partial_user_key,
        });
    }

    let decryption_alt = decrypt_message(&encryption, key_server_id, partial_user_keys, agg_pk);
    assert_eq!(&decryption_alt, message);
}

fn decrypt_message(
    encryption: &EncryptedObject,
    key_server_id: ObjectID,
    partial_user_keys: Vec<PartialSignature<G1Element>>,
    agg_pk: G2Element,
) -> Vec<u8> {
    let aggregated_sk = ThresholdBls12381MinSig::aggregate(3, partial_user_keys.iter()).unwrap();
    crypto::seal_decrypt(
        encryption,
        &IBEUserSecretKeys::BonehFranklinBLS12381(HashMap::from([(
            sui_sdk_types::ObjectId::new(key_server_id.into_bytes()),
            aggregated_sk,
        )])),
        Some(&IBEPublicKeys::BonehFranklinBLS12381(vec![agg_pk])),
    )
    .unwrap()
}

async fn create_server(
    sui_client: SuiClient,
    client_configs: Vec<ClientConfig>,
    vars: impl AsRef<[(&str, &[u8])]>,
) -> Server {
    let options = KeyServerOptions {
        network: Network::TestCluster,
        server_mode: ServerMode::Permissioned { client_configs },
        metrics_host_port: 0,
        checkpoint_update_interval: Duration::from_secs(10),
        rgp_update_interval: Duration::from_secs(60),
        sdk_version_requirement: VersionReq::from_str(">=0.4.6").unwrap(),
        allowed_staleness: Duration::from_secs(120),
        session_key_ttl_max: from_mins(30),
        rpc_config: RpcConfig::default(),
        metrics_push_config: None,
    };

    let vars = vars
        .as_ref()
        .iter()
        .map(|(k, v)| (k.to_string(), Some(DefaultEncoding::encode(v))))
        .collect::<Vec<_>>();

    Server {
        sui_rpc_client: SuiRpcClient::new(sui_client, RetryConfig::default(), None),
        master_keys: temp_env::with_vars(vars, || MasterKeys::load(&options)).unwrap(),
        key_server_oid_to_pop: HashMap::new(),
        options,
    }
}
