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
use crypto::ibe::{generate_seed, public_key_from_master_key, MasterKey};
use crypto::{ibe, seal_decrypt, seal_encrypt, EncryptionInput, IBEPublicKeys, IBEUserSecretKeys};
use fastcrypto::encoding::Encoding;
use fastcrypto::groups::bls12381::G1Element;
use fastcrypto::groups::GroupElement;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto_tbls::tbls::PartialSignature;
use fastcrypto_tbls::tbls::ThresholdBls;
use fastcrypto_tbls::types::ThresholdBls12381MinSig;
use futures::future::join_all;
use rand::thread_rng;
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
    let mut tc = SealTestCluster::new(1).await;
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
    let mut tc = SealTestCluster::new(2).await;

    // run 2 out of 3 servers with valid partial master keys from dkg finalization
    // # All parties' local output should all contain the key server pk and all partial pks.
    // KEY_SERVER_PK=0x94d64ca6b2e72d1b83202bb4b0f483928e6b53e2392e510db24e879a54a12095c951cb8fd9362966f76069ee3af1ed0d0ab1011127436ddcc505d51b46d672537ebce6ef2ed498401e44669cb770e983d43134167a6e21d2e7931b6e7cb7ab56
    // PARTY_0_PARTIAL_PK=0x856fb1a010d474fa1b8dda76dde2147971c926d531edd22c637b24a782efa190341104dc9de98f0d2dfd500dec4ea8af112082c2ac8b5cf42e217c3633b4e57b9bc69bf07cfacc51275e60b92f7e7f21ca764a0c186dc9e8256f2c44f2300427
    // PARTY_1_PARTIAL_PK=0xae5d3589de5651c18f829b0d4aa8b1b3f644031a3c2bce5e29201e05f091cf7cb2edac09c628c21fce964268f43f903a038f99ad059a422bd3f9803f6e94410da4c2ce367ef8016b23cc32f140547b1a37ba68db35a976ce1f518ccb50ca4397
    // PARTY_2_PARTIAL_PK=0x98d21682abc4759619ebd6d679617cdacf2083bd746047277ec099e06ca96321dcd793135b82cb4180778a0b551fbb191543913545682f728d9ff4bd907396e9128210863bc15b1fe06bfa98f5909223399aff74630383f38ac99a82b940bc00

    // # Each party's output contains their own partial secret key.
    // PARTY_0_SK=0x7159148266a389a2da7056acb4a322a49ad40d32597963f02994c1cc8b5b779e
    // PARTY_1_SK=0x09e0c1f70b9974f19930a83a8ed30f47fb09ab6ddd7f5d3990171f8911353d69
    // PARTY_2_SK=0x165616beda2cdd888b2ad1d072a4d3f0aefcedac6183b281f6997d44970f0335

    let msk1 = MasterKey::from_byte_array(
        &Hex::decode("0x7159148266a389a2da7056acb4a322a49ad40d32597963f02994c1cc8b5b779e")
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();

    let msk2 = MasterKey::from_byte_array(
        &Hex::decode("0x09e0c1f70b9974f19930a83a8ed30f47fb09ab6ddd7f5d3990171f8911353d69")
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let msk3 = MasterKey::from_byte_array(
        &Hex::decode("0x165616beda2cdd888b2ad1d072a4d3f0aefcedac6183b281f6997d44970f0335")
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    use fastcrypto::groups::bls12381::G2Element;
    let agg_pk_bytes = Hex::decode("0x94d64ca6b2e72d1b83202bb4b0f483928e6b53e2392e510db24e879a54a12095c951cb8fd9362966f76069ee3af1ed0d0ab1011127436ddcc505d51b46d672537ebce6ef2ed498401e44669cb770e983d43134167a6e21d2e7931b6e7cb7ab56").unwrap();
    let agg_pk_array: [u8; 96] = agg_pk_bytes.try_into().unwrap();
    let agg_pk = G2Element::from_byte_array(&agg_pk_array).unwrap();

    // set up the committee, key server, partial key server objects, 2 out of 3
    let mut partial_pks = HashMap::new();
    partial_pks.insert(
        tc.cluster.get_address_0(),
        public_key_from_master_key(&msk1),
    );
    partial_pks.insert(
        tc.cluster.get_address_1(),
        public_key_from_master_key(&msk2),
    );
    partial_pks.insert(
        tc.cluster.get_address_2(),
        public_key_from_master_key(&msk3),
    );
    let (key_server_id, partial_key_server_field_ids) = tc
        .set_up_committee_server(partial_pks.clone(), agg_pk, 2)
        .await;

    // add servers to the test cluster
    tc.add_server(MPC(msk1), "Server 1", Some(partial_key_server_field_ids[0]))
        .await;
    tc.add_server(MPC(msk2), "Server 2", Some(partial_key_server_field_ids[1]))
        .await;
    tc.add_server(MPC(msk3), "Server 3", Some(partial_key_server_field_ids[2]))
        .await;

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
    let encryption = crypto::seal_encrypt_mpc(
        sui_sdk_types::ObjectId::new(examples_package_id.into_bytes()),
        whitelist.to_vec(),
        sui_sdk_types::ObjectId::new(key_server_id.into_bytes()),
        &agg_pk,
        EncryptionInput::Aes256Gcm {
            data: message.to_vec(),
            aad: None,
        },
    )
    .unwrap()
    .0;

    // do a bad encryption with a zero aggregated pk
    let bad_encryption = crypto::seal_encrypt_mpc(
        sui_sdk_types::ObjectId::new(examples_package_id.into_bytes()),
        whitelist.to_vec(),
        sui_sdk_types::ObjectId::new(key_server_id.into_bytes()),
        &G2Element::zero(),
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
    for (i, (_field_id, server)) in tc.servers[..2].iter().enumerate() {
        let partial_user_key = get_key(
            server,
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

    // decrypt the message using MPC decryption with aggregated sk
    let decryption = crypto::seal_decrypt_mpc(&encryption, &aggregated_sk, Some(&agg_pk));
    assert_eq!(&decryption.unwrap(), message);

    // wrong threshold fails decryption
    let bad_aggregated_sk =
        ThresholdBls12381MinSig::aggregate(1, partial_user_keys.iter()).unwrap();
    let decryption = crypto::seal_decrypt_mpc(&encryption, &bad_aggregated_sk, Some(&agg_pk));
    assert!(decryption.is_err());

    // wrong aggregated pk fails decryption
    let decryption = crypto::seal_decrypt_mpc(&bad_encryption, &aggregated_sk, Some(&agg_pk));
    assert!(decryption.is_err());
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
