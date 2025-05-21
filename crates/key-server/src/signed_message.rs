// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::types::{ElGamalPublicKey, ElgamalVerificationKey};
use chrono::{DateTime, Utc};
use fastcrypto::ed25519::Ed25519PublicKey;
use serde::{Deserialize, Serialize};
use sui_types::transaction::ProgrammableTransaction;
use tracing::debug;

/// The format of the personal message shown to the user.
pub fn signed_message(
    package_name: String, // should use the original package id
    vk: &Ed25519PublicKey,
    creation_time: u64,
    ttl_min: u16,
) -> String {
    let res = format!(
        "Accessing keys of package {} for {} mins from {}, session key {}",
        package_name,
        ttl_min,
        DateTime::<Utc>::from_timestamp((creation_time / 1000) as i64, 0) // convert to seconds
            .expect("tested that in the future"),
        vk,
    );
    debug!("Signed message: {}", res.clone());
    res
}

#[derive(Serialize, Deserialize)]
struct RequestFormat {
    ptb: Vec<u8>,
    enc_key: Vec<u8>,
    enc_verification_key: Vec<u8>,
}

pub fn signed_request(
    ptb: &ProgrammableTransaction,
    enc_key: &ElGamalPublicKey,
    enc_verification_key: &ElgamalVerificationKey,
) -> Vec<u8> {
    let req = RequestFormat {
        ptb: bcs::to_bytes(&ptb).expect("should serialize"),
        enc_key: bcs::to_bytes(&enc_key).expect("should serialize"),
        enc_verification_key: bcs::to_bytes(&enc_verification_key).expect("should serialize"),
    };
    bcs::to_bytes(&req).expect("should serialize")
}

#[cfg(test)]
mod tests {
    use crate::signed_message::{signed_message, signed_request};
    use crypto::elgamal::genkey;
    use fastcrypto::ed25519::Ed25519KeyPair;
    use fastcrypto::traits::KeyPair;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::str::FromStr;
    use sui_types::base_types::ObjectID;
    use sui_types::crypto::deterministic_random_account_key;
    use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
    use sui_types::Identifier;

    #[test]
    fn test_signed_message_regression() {
        let pkg_id =
            ObjectID::from_str("0xc457b42d48924087ea3f22d35fd2fe9afdf5bdfe38cc51c0f14f3282f6d5")
                .unwrap();
        let (_, kp): (_, Ed25519KeyPair) = deterministic_random_account_key();
        let creation_time = 1622548800; // Fixed timestamp
        let ttl_min = 30;

        let expected_output = "Accessing keys of package 0x0000c457b42d48924087ea3f22d35fd2fe9afdf5bdfe38cc51c0f14f3282f6d5 for 30 mins from 1970-01-19 18:42:28 UTC, session key DX2rNYyNrapO+gBJp1sHQ2VVsQo2ghm7aA9wVxNJ13U=";

        let result = signed_message(
            pkg_id.to_hex_uncompressed(),
            kp.public(),
            creation_time,
            ttl_min,
        );
        assert_eq!(result, expected_output);
    }

    #[test]
    fn test_signed_message_mvr_regression() {
        let (_, kp): (_, Ed25519KeyPair) = deterministic_random_account_key();
        let creation_time = 1622548800; // Fixed timestamp
        let ttl_min = 30;

        let expected_output = "Accessing keys of package @my/package for 30 mins from 1970-01-19 18:42:28 UTC, session key DX2rNYyNrapO+gBJp1sHQ2VVsQo2ghm7aA9wVxNJ13U=";

        let result = signed_message(
            "@my/package".to_string(),
            kp.public(),
            creation_time,
            ttl_min,
        );
        assert_eq!(result, expected_output);
    }

    #[test]
    fn test_signed_request_regression() {
        let mut builder = ProgrammableTransactionBuilder::new();
        let pkg_id = ObjectID::from_str(
            "0xd92bc457b42d48924087ea3f22d35fd2fe9afdf5bdfe38cc51c0f14f3282f6d5",
        )
        .unwrap();
        builder.programmable_move_call(
            pkg_id,
            Identifier::new("bla").unwrap(),
            Identifier::new("seal_approve_x").unwrap(),
            vec![],
            vec![],
        );
        let ptb = builder.finish();
        let eg_keys = genkey(&mut StdRng::from_seed([0; 32]));

        let expected_output = "38000100d92bc457b42d48924087ea3f22d35fd2fe9afdf5bdfe38cc51c0f14f3282f6d503626c610e7365616c5f617070726f76655f7800003085946cd4134ecb8f7739bbd3522d1c8fab793c6c431a8b0b77b4f1885d4c096aafab755e7b8bce8688410cee9908fb29608faaf686c0dcbe3f65f1130e8be538d7ea009347d397f517188dfa14417618887a0412e404fff56efbafb63d1fc4970a1187b4ccb6e767a91822312e533fa53dee69f77ef5130be095e147ff3d40e96e8ddc4bf554dae3bcc34048fe9330cccf";

        let result = signed_request(&ptb, &eg_keys.1, &eg_keys.2);
        assert_eq!(hex::encode(result), expected_output);
    }
}
