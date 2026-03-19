// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::tests::externals::get_key;
use crate::tests::{ExecutedTransactionTestExt, SealTestCluster};
use sui_sdk::json::SuiJsonValue;
use sui_types::base_types::{ObjectDigest, SequenceNumber};
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
async fn test_pd() {
    let mut tc = SealTestCluster::new(2, "seal").await;

    let (seal_package, _) = tc.publish("seal").await;
    let (package_id, _) = tc
        .publish_with_deps("patterns", vec![("seal", seal_package)])
        .await;

    tc.add_open_server(seal_package).await;

    // create PrivateData with nonce=package_id, owned by addr1
    let (pd, version, digest) =
        create_private_data(tc.users[0].address, tc.test_cluster(), package_id).await;

    // addr1 should have access
    let ptb = pd_create_ptb(
        tc.test_cluster(),
        package_id,
        package_id,
        pd,
        version,
        digest,
    )
    .await;
    assert!(
        get_key(tc.server(), &package_id, ptb.clone(), &tc.users[0].keypair)
            .await
            .is_ok()
    );
    // addr2 should not have access
    assert!(get_key(tc.server(), &package_id, ptb, &tc.users[1].keypair)
        .await
        .is_err());

    // addr1 should not have access to a different nonce
    let ptb = pd_create_ptb(
        &tc.cluster,
        package_id,
        ObjectID::random(),
        pd,
        version,
        digest,
    )
    .await;
    assert!(
        get_key(tc.server(), &package_id, ptb.clone(), &tc.users[0].keypair)
            .await
            .is_err()
    );
}

pub(crate) async fn create_private_data(
    user: SuiAddress,
    cluster: &TestCluster,
    package_id: ObjectID,
) -> (ObjectID, SequenceNumber, ObjectDigest) {
    let builder = cluster.grpc_client().transaction_builder();
    let tx = builder
        .move_call(
            cluster.get_address_0(),
            package_id,
            "private_data",
            "store_entry",
            vec![],
            vec![
                SuiJsonValue::from_object_id(package_id),
                SuiJsonValue::from_object_id(package_id),
            ],
            None,
            50_000_000,
            None,
        )
        .await
        .unwrap();
    let response = cluster.sign_and_execute_transaction(&tx).await;

    let pd = response
        .find_created_object_by_type("PrivateData")
        .expect("PrivateData object should be created");

    let builder = cluster.grpc_client().transaction_builder();
    let tx = builder
        .transfer_object(cluster.get_address_0(), pd, None, 50_000_000, user)
        .await
        .unwrap();
    let response = cluster.sign_and_execute_transaction(&tx).await;
    assert!(response.status_ok().unwrap());

    let (id, version, digest_bytes) = response
        .find_mutated_object_by_type("PrivateData")
        .expect("should have found the pd object");

    // Reconstruct ObjectDigest from bytes
    let digest = ObjectDigest::new(digest_bytes);
    (id, version, digest)
}

async fn pd_create_ptb(
    cluster: &TestCluster,
    package_id: ObjectID,
    nonce: ObjectID,
    pd: ObjectID,
    version: SequenceNumber,
    digest: ObjectDigest,
) -> ProgrammableTransaction {
    let mut builder = ProgrammableTransactionBuilder::new();
    // the id = creator || nonce which in this case is the package_id
    let id = [
        bcs::to_bytes(&cluster.get_address_0()).unwrap(),
        bcs::to_bytes(&nonce).unwrap(),
    ]
    .concat();
    let id = builder.pure(id).unwrap();
    let pd = builder
        .obj(ObjectArg::ImmOrOwnedObject((pd, version, digest)))
        .unwrap();

    builder.programmable_move_call(
        package_id,
        Identifier::new("private_data").unwrap(),
        Identifier::new("seal_approve").unwrap(),
        vec![],
        vec![id, pd],
    );
    builder.finish()
}
