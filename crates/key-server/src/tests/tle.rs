// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::tests::externals::sign;
use crate::tests::SealTestCluster;
use crate::valid_ptb::ValidPtb;
use crate::{current_epoch_time, InternalError};
use crypto::elgamal;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::KeyPair;
use rand::thread_rng;
use sui_types::{
    base_types::ObjectID,
    programmable_transaction_builder::ProgrammableTransactionBuilder,
    transaction::{ObjectArg, ProgrammableTransaction},
    Identifier, SUI_CLOCK_OBJECT_ID,
};
use tracing_test::traced_test;

#[traced_test]
#[tokio::test]
async fn test_tle_policy() {
    let mut tc = SealTestCluster::new(1, 1).await;
    let (package_id, _) = tc.publish("patterns").await;

    {
        // old time
        let ptb = tle_create_ptb(package_id, 1);
        let (_, pk, vk) = elgamal::genkey(&mut thread_rng());
        let (cert, req_sig) = sign(
            &package_id,
            &ptb,
            &pk,
            &vk,
            &tc.users[0].keypair,
            current_epoch_time(),
            1,
        );

        let result = tc
            .server()
            .check_request(
                &ValidPtb::try_from(ptb).unwrap(),
                &pk,
                &vk,
                &req_sig,
                &cert,
                1000,
                None,
                None,
            )
            .await;
        assert!(result.is_ok());
        let key_ids = result.unwrap();
        assert_eq!(key_ids.len(), 2);
        assert_ne!(key_ids[0], key_ids[1]);
    }
    {
        // future time
        let ptb = tle_create_ptb(package_id, u64::MAX);
        let (_, pk, vk) = elgamal::genkey(&mut thread_rng());
        let (cert, req_sig) = sign(
            &package_id,
            &ptb,
            &pk,
            &vk,
            &tc.users[0].keypair,
            current_epoch_time(),
            1,
        );

        let result = tc
            .server()
            .check_request(
                &ValidPtb::try_from(ptb).unwrap(),
                &pk,
                &vk,
                &req_sig,
                &cert,
                1000,
                None,
                None,
            )
            .await;
        assert_eq!(result, Err(InternalError::NoAccess));
    }
}

#[traced_test]
#[tokio::test]
async fn test_tle_certificate() {
    let mut tc = SealTestCluster::new(1, 1).await;
    let (package_id, _) = tc.publish("patterns").await;

    let ptb = tle_create_ptb(package_id, 1);
    let (_, pk, vk) = elgamal::genkey(&mut thread_rng());
    let (cert, req_sig) = sign(
        &package_id,
        &ptb,
        &pk,
        &vk,
        &tc.users[0].keypair,
        current_epoch_time(),
        5,
    );

    let valid_ptb = ValidPtb::try_from(ptb.clone()).unwrap();

    // valid cert should work
    let result = tc
        .server()
        .check_request(&valid_ptb, &pk, &vk, &req_sig, &cert, 1000, None, None)
        .await;
    assert!(result.is_ok());

    // invalid certs should fail
    let mut invalid_cert = cert.clone();
    invalid_cert.creation_time = cert.creation_time - 1000;
    let result = tc
        .server()
        .check_request(
            &valid_ptb,
            &pk,
            &vk,
            &req_sig,
            &invalid_cert,
            1000,
            None,
            None,
        )
        .await;
    assert_eq!(result.err(), Some(InternalError::InvalidSignature));

    let mut invalid_cert = cert.clone();
    invalid_cert.ttl_min += 1;
    let result = tc
        .server()
        .check_request(
            &valid_ptb,
            &pk,
            &vk,
            &req_sig,
            &invalid_cert,
            1000,
            None,
            None,
        )
        .await;
    assert_eq!(result.err(), Some(InternalError::InvalidSignature));

    let mut invalid_cert = cert.clone();
    invalid_cert.session_vk = Ed25519KeyPair::generate(&mut thread_rng()).public().clone();
    let result = tc
        .server()
        .check_request(
            &valid_ptb,
            &pk,
            &vk,
            &req_sig,
            &invalid_cert,
            1000,
            None,
            None,
        )
        .await;
    assert_eq!(result.err(), Some(InternalError::InvalidSignature));

    // old cert should fail
    let (_, pk, vk) = elgamal::genkey(&mut thread_rng());
    let (cert, req_sig) = sign(&package_id, &ptb, &pk, &vk, &tc.users[0].keypair, 1, 1);
    let result = tc
        .server()
        .check_request(&valid_ptb, &pk, &vk, &req_sig, &cert, 1000, None, None)
        .await;
    assert_eq!(result.err(), Some(InternalError::InvalidCertificate));

    // cert with large ttl should fail
    let (_, pk, vk) = elgamal::genkey(&mut thread_rng());
    let (cert, req_sig) = sign(
        &package_id,
        &ptb,
        &pk,
        &vk,
        &tc.users[0].keypair,
        current_epoch_time(),
        100,
    );
    let result = tc
        .server()
        .check_request(&valid_ptb, &pk, &vk, &req_sig, &cert, 1000, None, None)
        .await;
    assert_eq!(result.err(), Some(InternalError::InvalidCertificate));
}

#[traced_test]
#[tokio::test]
async fn test_tle_signed_request() {
    let mut tc = SealTestCluster::new(1, 1).await;
    let (package_id, _) = tc.publish("patterns").await;

    let ptb = tle_create_ptb(package_id, 1);
    let (_, pk, vk) = elgamal::genkey(&mut thread_rng());
    let (cert, req_sig) = sign(
        &package_id,
        &ptb,
        &pk,
        &vk,
        &tc.users[0].keypair,
        current_epoch_time(),
        1,
    );

    let valid_ptb = ValidPtb::try_from(ptb).unwrap();
    let result = tc
        .server()
        .check_request(&valid_ptb, &pk, &vk, &req_sig, &cert, 1000, None, None)
        .await;
    assert!(result.is_ok());

    let (_, pk2, vk2) = elgamal::genkey(&mut thread_rng());
    let result = tc
        .server()
        .check_request(&valid_ptb, &pk2, &vk2, &req_sig, &cert, 1000, None, None)
        .await;
    assert_eq!(result.err(), Some(InternalError::InvalidSessionSignature));
}

fn get_tle_id(time: u64) -> Vec<u8> {
    bcs::to_bytes(&time).unwrap()
}

fn tle_create_ptb(package_id: ObjectID, time: u64) -> ProgrammableTransaction {
    let mut builder = ProgrammableTransactionBuilder::new();
    let id = builder.pure(get_tle_id(time)).unwrap();
    let id_0 = builder.pure(get_tle_id(0)).unwrap(); // used to test ptb with 2 commands
    let clock = builder
        .obj(ObjectArg::SharedObject {
            id: SUI_CLOCK_OBJECT_ID,
            initial_shared_version: 1.into(),
            mutable: false,
        })
        .unwrap();

    builder.programmable_move_call(
        package_id,
        Identifier::new("tle").unwrap(),
        Identifier::new("seal_approve").unwrap(),
        vec![],
        vec![id, clock],
    );
    builder.programmable_move_call(
        package_id,
        Identifier::new("tle").unwrap(),
        Identifier::new("seal_approve").unwrap(),
        vec![],
        vec![id_0, clock],
    );

    builder.finish()
}
