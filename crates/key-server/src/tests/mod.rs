// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::externals::{add_latest, add_package};
use crate::types::Network;
use crate::Server;
use crypto::ibe;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::groups::bls12381::G1Element;
use fastcrypto::groups::GroupElement;
use fastcrypto::serde_helpers::ToFromByteArray;
use rand::thread_rng;
use semver::VersionReq;
use serde_json::json;
use std::path::PathBuf;
use std::str::FromStr;
use sui_move_build::BuildConfig;
use sui_sdk::json::SuiJsonValue;
use sui_sdk::rpc_types::{ObjectChange, SuiData, SuiObjectDataOptions};
use sui_types::base_types::{ObjectID, SuiAddress};
use sui_types::crypto::get_key_pair_from_rng;
use sui_types::move_package::UpgradePolicy;
use test_cluster::{TestCluster, TestClusterBuilder};

mod e2e;
mod externals;
mod pd;
mod tle;
mod whitelist;

mod server;

/// Wrapper for Sui test cluster with some Seal specific functionality.
pub(crate) struct SealTestCluster {
    cluster: TestCluster,
    pub(crate) servers: Vec<SealKeyServer>,
    pub(crate) users: Vec<SealUser>,
}

pub(crate) struct SealKeyServer {
    server: Server,
    public_key: ibe::PublicKey,
}

pub(crate) struct SealUser {
    address: SuiAddress,
    keypair: Ed25519KeyPair,
}

impl SealTestCluster {
    /// Create a new SealTestCluster with the given number of servers and users.
    /// Key servers are not registered by default. Use `register_key_server` to register them.
    pub async fn new(servers: usize, users: usize) -> Self {
        let cluster = TestClusterBuilder::new().build().await;

        let mut rng = thread_rng();

        // TODO: We could publish the seal module and register key servers on-chain, but no tests need this right now so to speed up tests we don't do it.
        let servers = (0..servers)
            .map(|_| ibe::generate_key_pair(&mut rng))
            .map(|(master_key, public_key)| SealKeyServer {
                server: Server {
                    sui_client: cluster.sui_client().clone(),
                    network: Network::TestCluster,
                    master_key,
                    key_server_object_id: ObjectID::ZERO,
                    key_server_object_id_sig: G1Element::generator(),
                    sdk_version_requirement: VersionReq::STAR,
                },
                public_key,
            })
            .collect();

        let users = (0..users)
            .map(|_| get_key_pair_from_rng(&mut rng))
            .map(|(address, keypair)| SealUser { address, keypair })
            .collect();

        Self {
            cluster,
            servers,
            users,
        }
    }

    /// Get a mutable reference to the [TestCluster].
    pub fn get_mut(&mut self) -> &mut TestCluster {
        &mut self.cluster
    }

    /// Get a reference to the first server. Panics if there are no servers.
    pub fn server(&self) -> &Server {
        &self.servers[0].server
    }

    /// Publish the Move module in /move/<module> and return the package id and upgrade cap.
    pub async fn publish(&mut self, module: &str) -> (ObjectID, ObjectID) {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.extend(["..", "..", "move", module]);
        let compiled_package = BuildConfig::new_for_testing().build(&path).unwrap();

        // Publish package
        let builder = self.cluster.sui_client().transaction_builder();
        let tx = builder
            .publish(
                self.cluster.get_address_0(),
                compiled_package.get_package_bytes(true),
                compiled_package.get_dependency_storage_package_ids(),
                None,
                40_000_000_000,
            )
            .await
            .unwrap();
        let response = self.cluster.sign_and_execute_transaction(&tx).await;
        assert!(response.status_ok().unwrap());

        let changes = response.object_changes.unwrap();

        // Return the package id of the first (and only) published package
        let package_id = changes
            .iter()
            .find_map(|d| match d {
                ObjectChange::Published { package_id, .. } => Some(*package_id),
                _ => None,
            })
            .unwrap();

        let upgrade_cap = changes
            .iter()
            .find_map(|d| match d {
                ObjectChange::Created { object_id, .. } => Some(*object_id),
                _ => None,
            })
            .unwrap();

        add_package(package_id);

        (package_id, upgrade_cap)
    }

    /// Upgrade the package with the given package id and return the new package id.
    pub async fn upgrade(
        &mut self,
        package_id: ObjectID,
        upgrade_cap: ObjectID,
        module: &str,
    ) -> ObjectID {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.extend(["..", "..", "move", module]);
        let compiled_package = BuildConfig::new_for_testing().build(&path).unwrap();

        // Publish package
        let builder = self.cluster.sui_client().transaction_builder();

        let tx = builder
            .upgrade(
                self.cluster.get_address_0(),
                package_id,
                compiled_package.get_package_bytes(true),
                compiled_package.get_dependency_storage_package_ids(),
                upgrade_cap,
                UpgradePolicy::COMPATIBLE,
                compiled_package.get_package_digest(true).to_vec(),
                None,
                40_000_000_000,
            )
            .await
            .unwrap();
        let response = self.cluster.sign_and_execute_transaction(&tx).await;
        assert!(response.status_ok().unwrap());

        let changes = response.object_changes.unwrap();

        let new_package_id = *changes
            .iter()
            .find_map(|d| match d {
                ObjectChange::Published { package_id, .. } => Some(package_id),
                _ => None,
            })
            .unwrap();

        // Add new package id to internal registry
        add_latest(package_id, new_package_id);

        new_package_id
    }

    /// Register a key server with the given package id, description, url, and public key.
    /// Return the Object ID of the registered key server.
    pub async fn register_key_server(
        &mut self,
        package_id: ObjectID,
        description: &str,
        url: &str,
        pk: ibe::PublicKey,
    ) -> ObjectID {
        let tx = self
            .cluster
            .sui_client()
            .transaction_builder()
            .move_call(
                self.cluster.get_address_0(),
                package_id,
                "key_server",
                "register_and_transfer",
                vec![],
                vec![
                    SuiJsonValue::from_str(description).unwrap(),
                    SuiJsonValue::from_str(url).unwrap(), // Dummy url, not used in this test
                    SuiJsonValue::from_str(&0u8.to_string()).unwrap(), // Fix to BF-IBE
                    SuiJsonValue::new(json!(pk.to_byte_array().to_vec())).unwrap(),
                ],
                None,
                50_000_000,
                None,
            )
            .await
            .unwrap();
        let response = self.cluster.sign_and_execute_transaction(&tx).await;

        let service_objects = response
            .object_changes
            .unwrap()
            .into_iter()
            .filter_map(|d| match d {
                ObjectChange::Created {
                    object_type,
                    object_id,
                    ..
                } => Some((object_type.name, object_id)),
                _ => None,
            })
            .filter(|(name, _)| name.as_str() == "KeyServer")
            .collect::<Vec<_>>();
        assert_eq!(service_objects.len(), 1);
        service_objects[0].1
    }

    /// Get the public keys of the key servers with the given Object IDs.
    pub async fn get_public_keys(&self, object_ids: &[ObjectID]) -> Vec<ibe::PublicKey> {
        let objects = self
            .cluster
            .sui_client()
            .read_api()
            .multi_get_object_with_options(
                object_ids.to_vec(),
                SuiObjectDataOptions::full_content(),
            )
            .await
            .unwrap();

        objects
            .into_iter()
            .map(|o| {
                o.data
                    .unwrap()
                    .content
                    .unwrap()
                    .try_as_move()
                    .unwrap()
                    .fields
                    .field_value("pk")
                    .unwrap()
                    .to_json_value()
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_u64().unwrap() as u8)
                    .collect::<Vec<_>>()
            })
            .map(|v| ibe::PublicKey::from_byte_array(&v.try_into().unwrap()).unwrap())
            .collect()
    }
}

#[tokio::test]
async fn test_pkg_upgrade() {
    let mut setup = SealTestCluster::new(1, 1).await;
    let (package_id, upgrade_cap) = setup.publish("patterns").await;
    let new_package_id = setup.upgrade(package_id, upgrade_cap, "patterns").await;
    assert_ne!(package_id, new_package_id);
}
