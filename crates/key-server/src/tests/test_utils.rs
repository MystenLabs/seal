// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    key_server_options::{
        ClientConfig, CommitteeState, KeyServerOptions, RetryConfig, RpcConfig, ServerMode,
    },
    master_keys::MasterKeys,
    sui_rpc_client::SuiRpcClient,
    time::from_mins,
    types::Network,
    DefaultEncoding, Server,
};
use fastcrypto::encoding::Encoding;
use semver::VersionReq;
use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, RwLock},
    time::Duration,
};
use sui_rpc::client::Client as SuiGrpcClient;
use sui_sdk::SuiClient;
use sui_sdk_types::Address;
use sui_types::base_types::ObjectID;

/// Helper function to create a test server with any ServerMode.
pub(crate) async fn create_test_server(
    sui_client: SuiClient,
    sui_grpc_client: SuiGrpcClient,
    seal_package: ObjectID,
    server_mode: ServerMode,
    onchain_version: Option<u32>,
    vars: impl AsRef<[(&str, &[u8])]>,
) -> Server {
    let options = KeyServerOptions {
        network: Network::TestCluster { seal_package },
        node_url: None,
        server_mode,
        metrics_host_port: 0,
        rgp_update_interval: Duration::from_secs(60),
        ts_sdk_version_requirement: VersionReq::from_str(">=0.4.6").unwrap(),
        aggregator_version_requirement: VersionReq::from_str(">=0.5.15").unwrap(),
        allowed_staleness: Duration::from_secs(120),
        session_key_ttl_max: from_mins(30),
        rpc_config: RpcConfig::default(),
        metrics_push_config: None,
    };

    let sui_rpc_client = SuiRpcClient::new(
        sui_client,
        sui_grpc_client.clone(),
        RetryConfig::default(),
        None,
    );

    // Use MasterKeys::load() for all modes.
    let vars_encoded = vars
        .as_ref()
        .iter()
        .map(|(k, v)| (k.to_string(), Some(DefaultEncoding::encode(v))))
        .collect::<Vec<_>>();

    let master_keys =
        temp_env::with_vars(vars_encoded, || MasterKeys::load(&options, onchain_version)).unwrap();

    Server {
        sui_rpc_client,
        master_keys,
        key_server_oid_to_pop: Arc::new(RwLock::new(HashMap::new())),
        options,
    }
}

/// Helper function to create a permissioned server.
pub(crate) async fn create_server(
    sui_client: SuiClient,
    sui_grpc_client: SuiGrpcClient,
    seal_package: ObjectID,
    client_configs: Vec<ClientConfig>,
    vars: impl AsRef<[(&str, &[u8])]>,
) -> Server {
    create_test_server(
        sui_client,
        sui_grpc_client,
        seal_package,
        ServerMode::Permissioned { client_configs },
        None,
        vars,
    )
    .await
}

/// Helper function to create a list of committee mode servers.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_committee_servers(
    sui_client: SuiClient,
    sui_grpc_client: SuiGrpcClient,
    seal_package: ObjectID,
    key_server_obj_id: Address,
    member_addresses: Vec<Address>,
    vars_list: Vec<Vec<(&str, Vec<u8>)>>,
    onchain_version: u32,
    committee_state: CommitteeState,
) -> Vec<Server> {
    let mut servers = Vec::new();

    for (member_address, vars) in member_addresses.into_iter().zip(vars_list.into_iter()) {
        let vars_refs: Vec<(&str, &[u8])> = vars.iter().map(|(k, v)| (*k, v.as_slice())).collect();
        let server = create_test_server(
            sui_client.clone(),
            sui_grpc_client.clone(),
            seal_package,
            ServerMode::Committee {
                member_address,
                key_server_obj_id,
                committee_state: committee_state.clone(),
                server_name: "test_committee_server".to_string(),
            },
            Some(onchain_version),
            vars_refs,
        )
        .await;
        servers.push(server);
    }
    servers
}
