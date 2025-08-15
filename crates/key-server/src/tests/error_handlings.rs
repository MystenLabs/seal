// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::externals::get_key;
use crate::tests::SealTestCluster;
use serde_json::json;
use std::path::PathBuf;
use move_core_types::language_storage::TypeTag;
use sui_sdk::{json::SuiJsonValue, rpc_types::ObjectChange};
use sui_types::{
    base_types::{ObjectID, SuiAddress},
    programmable_transaction_builder::ProgrammableTransactionBuilder,
    transaction::{ObjectArg, ProgrammableTransaction},
    Identifier,
};
use test_cluster::TestCluster;
use tracing_test::traced_test;

#[traced_test]
#[tokio::test]
async fn test_no_id() {
    let mut tc = SealTestCluster::new(2).await;
    tc.add_open_server().await;
    tc.add_open_server().await;

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.extend(["src", "tests", "invalid_policies"]);
    let (package_id, _) = tc.publish_path(path).await;

    let mut builder = ProgrammableTransactionBuilder::new();
    let id = builder.pure(vec![0u8, 1u8, 2u8, 3u8]).unwrap();
    builder.programmable_move_call(
        package_id,
        Identifier::new("policy1").unwrap(),
        Identifier::new("seal_approve").unwrap(),
        vec![TypeTag::Vector(Box::new(TypeTag::U8))],
        vec![id],
    );

    let ptb = builder.finish();

    println!("{:?}", get_key(tc.server(), &package_id, ptb, &tc.users[0].keypair)
        .await);
}
