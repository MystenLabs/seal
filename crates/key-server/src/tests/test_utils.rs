// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    key_server_options::{ClientConfig, KeyServerOptions, RetryConfig, RpcConfig, ServerMode},
    master_keys::MasterKeys,
    sui_rpc_client::SuiRpcClient,
    tests::SealTestCluster,
    time::from_mins,
    types::Network,
    DefaultEncoding, Server,
};
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::groups::bls12381::G2Element;
use fastcrypto::serde_helpers::ToFromByteArray;
use move_core_types::language_storage::StructTag;
use semver::VersionReq;
use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, RwLock},
    time::Duration,
};
use sui_rpc::client::v2::Client as SuiGrpcClient;
use sui_sdk::rpc_types::{ObjectChange, SuiTransactionBlockResponse};
use sui_sdk::SuiClient;
use sui_sdk_types::Address;
use sui_types::base_types::{ObjectID, SuiAddress};
use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
use sui_types::transaction::{Argument, ProgrammableTransaction};
use sui_types::{Identifier, TypeTag};
use test_cluster::TestCluster;

/// Helper function to create a test server with any ServerMode.
pub(crate) async fn create_test_server(
    sui_client: SuiClient,
    sui_grpc_client: SuiGrpcClient,
    server_mode: ServerMode,
    onchain_version: Option<u32>,
    vars: impl AsRef<[(&str, &[u8])]>,
) -> Server {
    let options = KeyServerOptions {
        network: Network::TestCluster,
        server_mode,
        metrics_host_port: 0,
        checkpoint_update_interval: Duration::from_secs(10),
        rgp_update_interval: Duration::from_secs(60),
        sdk_version_requirement: VersionReq::from_str(">=0.4.6").unwrap(),
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
    client_configs: Vec<ClientConfig>,
    vars: impl AsRef<[(&str, &[u8])]>,
) -> Server {
    create_test_server(
        sui_client,
        sui_grpc_client,
        ServerMode::Permissioned { client_configs },
        None,
        vars,
    )
    .await
}

/// Helper function to create a list of committee mode servers.
pub(crate) async fn create_committee_servers(
    sui_client: SuiClient,
    sui_grpc_client: SuiGrpcClient,
    key_server_obj_id: Address,
    member_addresses: Vec<Address>,
    vars_list: Vec<Vec<(&str, Vec<u8>)>>,
    onchain_version: u32,
    target_key_server_version: u32,
) -> Vec<Server> {
    let mut servers = Vec::new();

    for (member_address, vars) in member_addresses.into_iter().zip(vars_list.into_iter()) {
        let vars_refs: Vec<(&str, &[u8])> = vars.iter().map(|(k, v)| (*k, v.as_slice())).collect();
        let server = create_test_server(
            sui_client.clone(),
            sui_grpc_client.clone(),
            ServerMode::Committee {
                member_address,
                key_server_obj_id,
                target_key_server_version,
            },
            Some(onchain_version),
            vars_refs,
        )
        .await;
        servers.push(server);
    }
    servers
}

/// Helper function to execute a programmable transaction and assert success.
pub(crate) async fn execute_programmable_transaction(
    tc: &SealTestCluster,
    sender: SuiAddress,
    pt: ProgrammableTransaction,
) -> SuiTransactionBlockResponse {
    let tx_data = tc
        .test_cluster()
        .test_transaction_builder_with_sender(sender)
        .await
        .programmable(pt)
        .build();

    let response = tc
        .test_cluster()
        .sign_and_execute_transaction(&tx_data)
        .await;

    assert!(response.status_ok().unwrap());
    response
}

/// Helper function to create a VecMap of one member (address, partial_pk, url, party_id).
pub(crate) fn build_partial_key_servers(
    builder: &mut ProgrammableTransactionBuilder,
    package_id: ObjectID,
    member_address: SuiAddress,
    partial_pk: &G2Element,
    party_id: u16,
) -> Argument {
    let partial_pk_hex = Hex::encode(partial_pk.to_byte_array());
    let partial_pk_str = format!("x\"{partial_pk_hex}\"");
    let partial_pk_bytes = builder.pure(partial_pk_str.as_bytes().to_vec()).unwrap();
    let url_arg = builder.pure("testurl.com".to_string()).unwrap();
    let party_id_arg = builder.pure(party_id).unwrap();

    let partial_key_server_arg = builder.programmable_move_call(
        package_id,
        Identifier::new("key_server").unwrap(),
        Identifier::new("create_partial_key_server").unwrap(),
        vec![],
        vec![partial_pk_bytes, url_arg, party_id_arg],
    );

    let vec_map_module = ObjectID::from_hex_literal("0x2").unwrap();
    let partial_key_server_type = TypeTag::Struct(Box::new(StructTag {
        address: package_id.into(),
        module: Identifier::new("key_server").unwrap(),
        name: Identifier::new("PartialKeyServer").unwrap(),
        type_params: vec![],
    }));

    // Create a vecmap and insert the member.
    let vec_map = builder.programmable_move_call(
        vec_map_module,
        Identifier::new("vec_map").unwrap(),
        Identifier::new("empty").unwrap(),
        vec![TypeTag::Address, partial_key_server_type.clone()],
        vec![],
    );
    let member_addr_arg = builder.pure(member_address).unwrap();
    builder.programmable_move_call(
        vec_map_module,
        Identifier::new("vec_map").unwrap(),
        Identifier::new("insert").unwrap(),
        vec![TypeTag::Address, partial_key_server_type],
        vec![vec_map, member_addr_arg, partial_key_server_arg],
    );
    vec_map
}

/// Helper function to create a committee KeyServer on-chain and return its ObjectID.
pub(crate) async fn create_committee_key_server_onchain(
    cluster: &TestCluster,
    package_id: ObjectID,
    member_address: SuiAddress,
    partial_pk: &G2Element,
    party_id: u16,
    master_pk: &G2Element,
    threshold: u16,
) -> ObjectID {
    let mut builder = ProgrammableTransactionBuilder::new();
    let partial_key_servers = build_partial_key_servers(
        &mut builder,
        package_id,
        member_address,
        partial_pk,
        party_id,
    );

    let name = builder.pure("test_committee".to_string()).unwrap();
    let threshold_arg = builder.pure(threshold).unwrap();
    let master_pk_bytes = builder.pure(master_pk.to_byte_array().to_vec()).unwrap();
    let key_server = builder.programmable_move_call(
        package_id,
        Identifier::new("key_server").unwrap(),
        Identifier::new("create_committee_v2").unwrap(),
        vec![],
        vec![name, threshold_arg, master_pk_bytes, partial_key_servers],
    );
    builder.transfer_arg(member_address, key_server);

    let tx_data = cluster
        .test_transaction_builder_with_sender(member_address)
        .await
        .programmable(builder.finish())
        .build();

    let response = cluster.sign_and_execute_transaction(&tx_data).await;
    assert!(response.status_ok().unwrap());

    // Extract the created KeyServer object ID.
    response
        .object_changes
        .unwrap()
        .into_iter()
        .find_map(|change| {
            if let ObjectChange::Created {
                object_type,
                object_id,
                ..
            } = change
            {
                if object_type.name.as_str() == "KeyServer" {
                    return Some(object_id);
                }
            }
            None
        })
        .expect("KeyServer object not found in transaction response")
}
