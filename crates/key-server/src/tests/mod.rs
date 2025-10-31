// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::externals::{add_package, add_upgraded_package};
use crate::key_server_options::{KeyServerOptions, RetryConfig, RpcConfig, ServerMode};
use crate::master_keys::MasterKeys;
use crate::sui_rpc_client::SuiRpcClient;
use crate::tests::KeyServerType::Open;
use crate::time::from_mins;
use crate::types::Network;
use crate::{DefaultEncoding, Server};
use crypto::ibe;
use crypto::ibe::public_key_from_master_key;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::encoding::Encoding;
use fastcrypto::serde_helpers::ToFromByteArray;
use futures::future::join_all;
use rand::thread_rng;
use semver::VersionReq;
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use sui_move_build::BuildConfig;
use sui_rpc::client::v2::Client as SuiGrpcClient;
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
pub(crate) mod whitelist;

mod server;

/// Wrapper for Sui test cluster with some Seal specific functionality.
pub(crate) struct SealTestCluster {
    cluster: TestCluster,
    #[allow(dead_code)]
    pub(crate) registry: (ObjectID, ObjectID),
    pub(crate) servers: Vec<(ObjectID, Server)>,
    pub(crate) users: Vec<SealUser>,
}

pub(crate) struct SealUser {
    address: SuiAddress,
    keypair: Ed25519KeyPair,
}

/// Key server types allowed in tests
pub enum KeyServerType {
    Open(ibe::MasterKey),
    Permissioned {
        seed: Vec<u8>,
        package_ids: Vec<ObjectID>,
    },
}

impl SealTestCluster {
    /// Create a new SealTestCluster with the given number users. To add servers, use the `add_server` method.
    pub async fn new(users: usize) -> Self {
        let cluster = TestClusterBuilder::new()
            .with_num_validators(1)
            .build()
            .await;
        let registry = Self::publish_internal(&cluster, "seal").await;
        Self {
            cluster,
            servers: vec![],
            registry,
            users: (0..users)
                .map(|_| {
                    let (address, keypair) = get_key_pair_from_rng(&mut thread_rng());
                    SealUser { address, keypair }
                })
                .collect(),
        }
    }

    pub fn get_services(&self) -> Vec<ObjectID> {
        self.servers.iter().map(|(id, _)| *id).collect()
    }

    /// Get a mutable reference to the [TestCluster].
    pub fn test_cluster(&self) -> &TestCluster {
        &self.cluster
    }

    pub async fn add_open_server(&mut self, seal_package: ObjectID) {
        let master_key = ibe::generate_key_pair(&mut thread_rng()).0;
        let name = DefaultEncoding::encode(public_key_from_master_key(&master_key).to_byte_array());
        self.add_server(Open(master_key), &name, seal_package).await;
    }

    pub async fn add_open_servers(&mut self, num_servers: usize, seal_package: ObjectID) {
        for _ in 0..num_servers {
            self.add_open_server(seal_package).await;
        }
    }

    pub async fn add_server(&mut self, server: KeyServerType, name: &str, seal_package: ObjectID) {
        match server {
            Open(master_key) => {
                let key_server_object_id = self
                    .register_key_server(
                        name,
                        "http://localhost:8080", // Dummy URL, not used in this test
                        public_key_from_master_key(&master_key),
                    )
                    .await;
                let server = Server {
                    sui_rpc_client: SuiRpcClient::new(
                        self.cluster.sui_client().clone(),
                        SuiGrpcClient::new(self.cluster.fullnode_handle.rpc_url.clone())
                            .expect("Failed to create gRPC client"),
                        RetryConfig::default(),
                        None,
                    ),
                    master_keys: MasterKeys::Open { master_key },
                    key_server_oid_to_pop: HashMap::new(),
                    options: KeyServerOptions {
                        network: Network::TestCluster,
                        server_mode: ServerMode::Open {
                            key_server_object_id,
                        },
                        metrics_host_port: 0,
                        rgp_update_interval: Duration::from_secs(60),
                        sdk_version_requirement: VersionReq::from_str(">=0.4.6").unwrap(),
                        allowed_staleness: Duration::from_secs(120),
                        session_key_ttl_max: from_mins(30),
                        rpc_config: RpcConfig::default(),
                        metrics_push_config: None,
                        seal_package,
                    },
                };
                self.servers.push((key_server_object_id, server));
            }
            _ => panic!(),
        };
    }

    pub fn server(&self) -> &Server {
        &self.servers[0].1
    }

    /// Publish the Move module in /move/<module> and return the package id and upgrade cap.
    pub async fn publish(&self, module: &str) -> (ObjectID, ObjectID) {
        Self::publish_internal(&self.cluster, module).await
    }

    pub async fn publish_internal(cluster: &TestCluster, module: &str) -> (ObjectID, ObjectID) {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.extend(["..", "..", "move", module]);
        Self::publish_path_internal(cluster, path).await
    }

    pub async fn publish_path(&self, path: PathBuf) -> (ObjectID, ObjectID) {
        Self::publish_path_internal(&self.cluster, path).await
    }

    async fn publish_path_internal(cluster: &TestCluster, path: PathBuf) -> (ObjectID, ObjectID) {
        let compiled_package = BuildConfig::new_for_testing().build(&path).unwrap();
        // Publish package
        let builder = cluster.sui_client().transaction_builder();
        let tx = builder
            .publish(
                cluster.get_address_0(),
                compiled_package.get_package_bytes(true),
                compiled_package.get_dependency_storage_package_ids(),
                None,
                40_000_000_000,
            )
            .await
            .unwrap();
        let response = cluster.sign_and_execute_transaction(&tx).await;
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
        path: PathBuf,
    ) -> ObjectID {
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
        add_upgraded_package(package_id, new_package_id);

        new_package_id
    }

    /// Register a key server with the given package id, description, url, and public key.
    /// Return the Object ID of the registered key server.
    async fn register_key_server(
        &self,
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
                self.registry.0,
                "key_server",
                "create_and_transfer_v1",
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

    /// Get the public keys of the key servers v1 with the given Object IDs.
    pub async fn get_public_keys(&self, object_ids: &[ObjectID]) -> Vec<ibe::PublicKey> {
        let futures = object_ids.iter().map(|id| {
            self.cluster
                .sui_client()
                .read_api()
                .get_dynamic_fields(*id, None, None)
        });

        let res = join_all(futures).await;

        // filter df that has type KeyServerV1
        let object_ids = res
            .into_iter()
            .filter_map(|page| {
                page.ok().and_then(|p| {
                    p.data
                        .into_iter()
                        .find(|df| df.object_type.ends_with("::key_server::KeyServerV1"))
                        .map(|df| df.object_id)
                })
            })
            .collect::<Vec<_>>();
        let objects = self
            .cluster
            .sui_client()
            .read_api()
            .multi_get_object_with_options(object_ids, SuiObjectDataOptions::full_content())
            .await
            .unwrap();
        objects
            .into_iter()
            .map(|o| {
                let value = o
                    .data
                    .unwrap()
                    .content
                    .unwrap()
                    .try_as_move()
                    .unwrap()
                    .fields
                    .field_value("value")
                    .unwrap()
                    .to_json_value();
                let pk = value
                    .as_object()
                    .unwrap()
                    .get("pk")
                    .unwrap()
                    .as_array()
                    .unwrap();
                pk.iter()
                    .map(|v| v.as_u64().unwrap() as u8)
                    .collect::<Vec<_>>()
            })
            .map(|v| ibe::PublicKey::from_byte_array(&v.try_into().unwrap()).unwrap())
            .collect()
    }
}

#[tokio::test]
async fn test_pkg_upgrade() {
    let mut setup = SealTestCluster::new(0).await;
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/tests/whitelist_v1");
    let (package_id, upgrade_cap) = setup.publish_path(path).await;
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/tests/whitelist_v2");
    let new_package_id = setup.upgrade(package_id, upgrade_cap, path).await;
    assert_ne!(package_id, new_package_id);
}
