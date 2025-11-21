// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::externals::get_key;
use crate::tests::SealTestCluster;
use serde_json::json;
use std::path::PathBuf;
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
async fn test_whitelist() {
    let mut tc = SealTestCluster::new(2, "seal").await;
    tc.add_open_server().await;
    tc.add_open_server().await;

    let (package_id, _) = tc.publish("patterns").await;

    let (whitelist, cap, initial_shared_version) =
        create_whitelist(tc.test_cluster(), package_id).await;

    let user_address = tc.users[0].address;
    add_user_to_whitelist(tc.test_cluster(), package_id, whitelist, cap, user_address).await;

    let ptb = whitelist_create_ptb(package_id, whitelist, initial_shared_version);
    assert!(
        get_key(tc.server(), &package_id, ptb.clone(), &tc.users[0].keypair)
            .await
            .is_ok()
    );
    assert!(get_key(tc.server(), &package_id, ptb, &tc.users[1].keypair)
        .await
        .is_err());

    let ptb = whitelist_create_ptb(package_id, whitelist, initial_shared_version);
    assert!(get_key(tc.server(), &package_id, ptb, &tc.users[1].keypair)
        .await
        .is_err());
}

#[traced_test]
#[tokio::test]
async fn test_whitelist_with_upgrade() {
    let mut tc = SealTestCluster::new(1, "seal").await;
    tc.add_open_server().await;

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/tests/whitelist_v1");
    let (package_id_1, upgrade_cap) = tc.publish_path(path).await;
    println!("Old pkg: {package_id_1}");

    let (whitelist, cap, initial_shared_version) =
        create_whitelist(tc.test_cluster(), package_id_1).await;
    let user_address = tc.users[0].address;
    add_user_to_whitelist(
        tc.test_cluster(),
        package_id_1,
        whitelist,
        cap,
        user_address,
    )
    .await;

    // Succeeds with initial version
    let ptb = whitelist_create_ptb(package_id_1, whitelist, initial_shared_version);
    assert!(get_key(
        tc.server(),
        &package_id_1,
        ptb.clone(),
        &tc.users[0].keypair
    )
    .await
    .is_ok());

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/tests/whitelist_v2");
    let package_id_2 = tc.upgrade(package_id_1, upgrade_cap, path).await;

    // Succeeds with old package id (since we didn't upgrade)
    let ptb = whitelist_create_ptb(package_id_1, whitelist, initial_shared_version);
    assert!(get_key(
        tc.server(),
        &package_id_1,
        ptb.clone(),
        &tc.users[0].keypair
    )
    .await
    .is_ok());

    // But fails with new version
    let ptb = whitelist_create_ptb(package_id_2, whitelist, initial_shared_version);
    assert!(get_key(
        tc.server(),
        &package_id_1,
        ptb.clone(),
        &tc.users[0].keypair
    )
    .await
    .is_err());

    // upgrade version
    upgrade_whitelist(tc.test_cluster(), package_id_2, whitelist, cap).await;

    // Succeeds with new package
    let ptb = whitelist_create_ptb(package_id_2, whitelist, initial_shared_version);
    assert!(get_key(
        tc.server(),
        &package_id_1,
        ptb.clone(),
        &tc.users[0].keypair
    )
    .await
    .is_ok());

    // But fails with old version
    let ptb = whitelist_create_ptb(package_id_1, whitelist, initial_shared_version);
    assert!(get_key(
        tc.server(),
        &package_id_1,
        ptb.clone(),
        &tc.users[0].keypair
    )
    .await
    .is_err());
}

// TODO: fix next test (as the router was modified)
// #[traced_test]
// #[tokio::test]
// async fn test_whitelist_router() {
//     let (addr, kp) = create_user(0);
//     let (id, ptb) = whitelist_create_ptb(addr.clone());
//     let ptb_str = Hex::encode(bcs::to_bytes(&ptb).unwrap());
//     let eg_pk = elgamal::genkey(&mut thread_rng()).1;
//     let msg_to_sign = signed_message(&id, &ptb_str, &eg_pk);
//     let personal_msg = PersonalMessage {
//         message: msg_to_sign.as_bytes().to_vec(),
//     };
//     let msg_with_intent = IntentMessage::new(Intent::personal_message(), personal_msg.clone());
//     let sig = GenericSignature::Signature(Signature::new_secure(&msg_with_intent, &kp));
//
//     let bcs_bytes = Hex::encode(bcs::to_bytes(&ptb).unwrap());
//     let srd = serde_json::to_string(&FetchKeyRequest {
//         enc_key: eg_pk,
//         signature: sig,
//         active_subscription: ObjectID::ZERO,
//         ptb: bcs_bytes,
//     })
//     .unwrap();
//     let s = Server::new(fixed_key(), Network::Devnet).await;
//     let app = get_router(s.into());
//     let res = app
//         .oneshot(
//             Request::get("/v1/fetch_key")
//                 .header("Content-Type", "application/json")
//                 .body(Body::from(srd))
//                 .unwrap(),
//         )
//         .await
//         .unwrap();
//     assert_eq!(res.status(), 200);
// }

pub fn whitelist_create_ptb(
    package_id: ObjectID,
    whitelist_id: ObjectID,
    initial_shared_version: u64,
) -> ProgrammableTransaction {
    let mut builder = ProgrammableTransactionBuilder::new();
    // the prefix of id should be the object id
    let ids = builder.pure(whitelist_id.to_vec()).unwrap();
    let list = builder
        .obj(ObjectArg::SharedObject {
            id: whitelist_id,
            initial_shared_version: initial_shared_version.into(),
            mutable: false,
        })
        .unwrap();

    builder.programmable_move_call(
        package_id,
        Identifier::new("whitelist").unwrap(),
        Identifier::new("seal_approve").unwrap(),
        vec![],
        vec![ids, list],
    );

    builder.finish()
}

pub(crate) async fn create_whitelist(
    cluster: &TestCluster,
    package_id: ObjectID,
) -> (ObjectID, ObjectID, u64) {
    // Create new whitelist
    let tx = cluster
        .sui_client()
        .transaction_builder()
        .move_call(
            cluster.get_address_0(),
            package_id,
            "whitelist",
            "create_whitelist_entry",
            vec![],
            vec![],
            None,
            50_000_000,
            None,
        )
        .await
        .unwrap();
    let response = cluster.sign_and_execute_transaction(&tx).await;

    // Read the id of the Whitelist and Cap objects
    let mut whitelist: Option<ObjectID> = None;
    let mut cap: Option<ObjectID> = None;
    let mut initial_version: Option<u64> = None;
    for created in response.object_changes.unwrap() {
        if let ObjectChange::Created {
            object_type,
            object_id,
            version,
            ..
        } = created
        {
            initial_version.replace(version.value());
            match object_type.name.as_str() {
                "Whitelist" => whitelist.replace(object_id),
                "Cap" => cap.replace(object_id),
                _ => None,
            };
        }
    }
    (whitelist.unwrap(), cap.unwrap(), initial_version.unwrap())
}

pub(crate) async fn add_user_to_whitelist(
    cluster: &TestCluster,
    package_id: ObjectID,
    whitelist: ObjectID,
    cap: ObjectID,
    user: SuiAddress,
) {
    // Add the first user to the whitelist
    let tx = cluster
        .sui_client()
        .transaction_builder()
        .move_call(
            cluster.get_address_0(),
            package_id,
            "whitelist",
            "add",
            vec![],
            vec![
                SuiJsonValue::from_object_id(whitelist),
                SuiJsonValue::from_object_id(cap),
                SuiJsonValue::new(json!(user)).unwrap(),
            ],
            None,
            50_000_000,
            None,
        )
        .await
        .unwrap();
    let response = cluster.sign_and_execute_transaction(&tx).await;
    assert!(response.status_ok().unwrap());
}

pub(crate) async fn upgrade_whitelist(
    cluster: &TestCluster,
    package_id: ObjectID,
    whitelist: ObjectID,
    cap: ObjectID,
) {
    // Add the first user to the whitelist
    let tx = cluster
        .sui_client()
        .transaction_builder()
        .move_call(
            cluster.get_address_0(),
            package_id,
            "whitelist",
            "upgrade_version",
            vec![],
            vec![
                SuiJsonValue::from_object_id(whitelist),
                SuiJsonValue::from_object_id(cap),
            ],
            None,
            50_000_000,
            None,
        )
        .await
        .unwrap();
    let response = cluster.sign_and_execute_transaction(&tx).await;
    assert!(response.status_ok().unwrap());
}
