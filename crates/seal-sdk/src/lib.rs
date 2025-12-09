// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub mod types;

use crate::types::{ElGamalPublicKey, ElgamalVerificationKey};
use chrono::{DateTime, Utc};
use crypto::create_full_id;
use crypto::elgamal;
use crypto::elgamal::decrypt as elgamal_decrypt;
use crypto::ibe::UserSecretKey;
use crypto::ibe::{verify_encrypted_signature, verify_user_secret_key};
use crypto::{seal_decrypt, IBEPublicKeys, IBEUserSecretKeys, ObjectID};
use fastcrypto::ed25519::Ed25519PublicKey;
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::error::FastCryptoError;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::bls12381::G2Element;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sui_sdk_types::ProgrammableTransaction;
use tracing::{debug, info, warn};

// Re-exported for seal_sdk
pub use crypto::elgamal::genkey;
pub use crypto::ibe::PublicKey as IBEPublicKey;
pub use crypto::{seal_encrypt, EncryptedObject};
pub use types::{Certificate, DecryptionKey, ElGamalSecretKey, FetchKeyRequest, FetchKeyResponse};

pub fn signed_message(
    package_name: String,
    vk: &Ed25519PublicKey,
    creation_time: u64,
    ttl_min: u16,
) -> String {
    let res = format!(
        "Accessing keys of package {} for {} mins from {}, session key {}",
        package_name,
        ttl_min,
        DateTime::<Utc>::from_timestamp((creation_time / 1000) as i64, 0)
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

/// Given the ElGamalSecretKey, elgamal decrypt and verify all user secret keys from multiple seal
/// responses. Returns a nested map: full_id -> (server_id -> UserSecretKey).
pub fn decrypt_seal_responses(
    enc_secret: &ElGamalSecretKey,
    seal_responses: &[(ObjectID, FetchKeyResponse)],
    server_pk_map: &HashMap<ObjectID, IBEPublicKey>,
) -> FastCryptoResult<HashMap<Vec<u8>, HashMap<ObjectID, UserSecretKey>>> {
    let mut cached_keys: HashMap<Vec<u8>, HashMap<ObjectID, UserSecretKey>> = HashMap::new();

    for (server_id, seal_response) in seal_responses.iter() {
        let public_key = server_pk_map.get(server_id).ok_or_else(|| {
            FastCryptoError::GeneralError(format!(
                "No public key configured for server {server_id}"
            ))
        })?;

        for decryption_key in seal_response.decryption_keys.iter() {
            let user_secret_key = elgamal_decrypt(enc_secret, &decryption_key.encrypted_key);
            verify_user_secret_key(&user_secret_key, &decryption_key.id, public_key)?;

            cached_keys
                .entry(decryption_key.id.clone())
                .or_default()
                .insert(*server_id, user_secret_key);
        }
    }

    Ok(cached_keys)
}

/// Decrypt a single encrypted object using cached user secret keys from multiple servers.
/// The cached_keys should be the result from decrypt_seal_responses.
pub fn seal_decrypt_object(
    encrypted_object: &EncryptedObject,
    cached_keys: &HashMap<Vec<u8>, HashMap<ObjectID, UserSecretKey>>,
    server_pk_map: &HashMap<ObjectID, IBEPublicKey>,
) -> FastCryptoResult<Vec<u8>> {
    // Compute the full_id for this encrypted object
    let full_id = create_full_id(
        &encrypted_object.package_id.into_inner(),
        &encrypted_object.id,
    );

    // Get the keys for this full_id
    let keys_for_id = cached_keys.get(&full_id).ok_or_else(|| {
        FastCryptoError::GeneralError(format!(
            "No keys available for object with full_id {}",
            Hex::encode(&full_id)
        ))
    })?;

    let mut usks = HashMap::new();
    let mut pks = Vec::with_capacity(encrypted_object.services.len());

    // Iterate through the services in the encrypted object to maintain correct order
    for (server_id, _index) in encrypted_object.services.iter() {
        if let Some(user_secret_key) = keys_for_id.get(server_id) {
            usks.insert(*server_id, *user_secret_key);
        }

        let pk = server_pk_map.get(server_id).ok_or_else(|| {
            FastCryptoError::GeneralError(format!(
                "No public key configured for server {server_id}"
            ))
        })?;
        pks.push(*pk);
    }

    if usks.len() < encrypted_object.threshold as usize {
        return Err(FastCryptoError::GeneralError(format!(
            "Insufficient keys for object: have {}, threshold requires {}",
            usks.len(),
            encrypted_object.threshold
        )));
    }

    seal_decrypt(
        encrypted_object,
        &IBEUserSecretKeys::BonehFranklinBLS12381(usks),
        Some(&IBEPublicKeys::BonehFranklinBLS12381(pks)),
    )
}

/// Aggregate encrypted partial keys from committee members using homomorphic Lagrange interpolation.
///
/// This function takes encrypted key shares from multiple committee members and aggregates them.
/// It computes Enc(Σ λᵢ * sᵢ) directly from the encrypted shares, where λᵢ are Lagrange coefficients
/// and returns FetchKeyResponse containing aggregated encrypted keys that can be decrypted by the
/// client using their ephemeral secret key.
pub fn aggregate_encrypted_responses(
    threshold: u16,
    responses: Vec<(u16, FetchKeyResponse)>,
) -> FastCryptoResult<FetchKeyResponse> {
    if responses.is_empty() {
        return Err(FastCryptoError::GeneralError(
            "No responses to aggregate".to_string(),
        ));
    }

    let first_response = &responses[0].1;
    if first_response.decryption_keys.is_empty() {
        return Err(FastCryptoError::GeneralError(
            "No decryption keys in response".to_string(),
        ));
    }

    // For each decryption key ID, aggregate across committee members
    let mut aggregated_keys = Vec::new();

    for key_idx in 0..first_response.decryption_keys.len() {
        let expected_key_id = &first_response.decryption_keys[key_idx].id;

        // Collect (party_id, encrypted_key) pairs for this key ID
        // Validate that all responses have matching key IDs at this index
        let encrypted_shares: Vec<(u16, elgamal::Encryption<_>)> = responses
            .iter()
            .filter_map(|(party_id, response)| {
                response.decryption_keys.get(key_idx).map(|dk| {
                    // Validate key ID matches
                    if dk.id != *expected_key_id {
                        return None;
                    }
                    Some((*party_id, dk.encrypted_key.clone()))
                })
            })
            .flatten()
            .collect();

        if encrypted_shares.len() < threshold as usize {
            return Err(FastCryptoError::GeneralError(format!(
                "Insufficient partial keys for key_idx {}: got {}, need {}",
                key_idx,
                encrypted_shares.len(),
                threshold
            )));
        }

        let aggregated_encrypted =
            elgamal::aggregate_encrypted(threshold, encrypted_shares.into_iter())?;

        let key_id = expected_key_id.clone();
        aggregated_keys.push(DecryptionKey {
            id: key_id,
            encrypted_key: aggregated_encrypted,
        });
    }

    Ok(FetchKeyResponse {
        decryption_keys: aggregated_keys,
    })
}

/// Verify encrypted signatures for all decryption keys from a committee member.
///
/// Filters out any keys that fail verification and logs warnings.
/// Returns an error if all keys fail verification.
pub fn verify_decryption_keys(
    decryption_keys: &[DecryptionKey],
    partial_pk: &G2Element,
    ephemeral_vk: &ElgamalVerificationKey,
    party_id: u16,
) -> Result<Vec<DecryptionKey>, String> {
    let mut verified_keys = Vec::new();

    for dk in decryption_keys {
        match verify_encrypted_signature(&dk.encrypted_key, ephemeral_vk, partial_pk, &dk.id) {
            Ok(()) => {
                verified_keys.push(dk.clone());
            }
            Err(e) => {
                warn!(
                    "Verification failed for party {} key_id={}: {}",
                    party_id,
                    Hex::encode(&dk.id),
                    e
                );
            }
        }
    }

    if verified_keys.is_empty() && !decryption_keys.is_empty() {
        return Err(format!(
            "All {} decryption keys from party {} failed verification",
            decryption_keys.len(),
            party_id
        ));
    }

    info!(
        "Verified {}/{} decryption keys from party {}",
        verified_keys.len(),
        decryption_keys.len(),
        party_id
    );

    Ok(verified_keys)
}

#[cfg(test)]
mod tests {
    use crate::{signed_message, signed_request};
    use crypto::elgamal::genkey;
    use fastcrypto::ed25519::Ed25519KeyPair;
    use fastcrypto::encoding::Encoding;
    use fastcrypto::encoding::Hex;
    use fastcrypto::traits::KeyPair;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::str::FromStr;
    use sui_sdk_types::Address as NewObjectID;
    use sui_sdk_types::ProgrammableTransaction as NewProgrammableTransaction;
    use sui_types::crypto::deterministic_random_account_key;
    #[test]
    fn test_signed_message_regression() {
        let pkg_id =
            NewObjectID::from_str("0xc457b42d48924087ea3f22d35fd2fe9afdf5bdfe38cc51c0f14f3282f6d5")
                .unwrap();
        let (_, kp): (_, Ed25519KeyPair) = deterministic_random_account_key();
        let creation_time = 1622548800;
        let ttl_min = 30;

        let expected_output = "Accessing keys of package 0x0000c457b42d48924087ea3f22d35fd2fe9afdf5bdfe38cc51c0f14f3282f6d5 for 30 mins from 1970-01-19 18:42:28 UTC, session key DX2rNYyNrapO+gBJp1sHQ2VVsQo2ghm7aA9wVxNJ13U=";

        let result = signed_message(pkg_id.to_string(), kp.public(), creation_time, ttl_min);
        assert_eq!(result, expected_output);
    }

    #[test]
    fn test_signed_message_mvr_regression() {
        let (_, kp): (_, Ed25519KeyPair) = deterministic_random_account_key();
        let creation_time = 1622548800;
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
        let pkg_id = NewObjectID::from_str(
            "0xd92bc457b42d48924087ea3f22d35fd2fe9afdf5bdfe38cc51c0f14f3282f6d5",
        )
        .unwrap();

        let move_call = sui_sdk_types::Command::MoveCall(sui_sdk_types::MoveCall {
            package: pkg_id,
            module: sui_sdk_types::Identifier::from_str("bla").unwrap(),
            function: sui_sdk_types::Identifier::from_str("seal_approve_x").unwrap(),
            type_arguments: vec![],
            arguments: vec![],
        });

        let ptb = NewProgrammableTransaction {
            inputs: vec![],
            commands: vec![move_call],
        };

        let eg_keys = genkey(&mut StdRng::from_seed([0; 32]));

        let expected_output = "38000100d92bc457b42d48924087ea3f22d35fd2fe9afdf5bdfe38cc51c0f14f3282f6d503626c610e7365616c5f617070726f76655f7800003085946cd4134ecb8f7739bbd3522d1c8fab793c6c431a8b0b77b4f1885d4c096aafab755e7b8bce8688410cee9908fb29608faaf686c0dcbe3f65f1130e8be538d7ea009347d397f517188dfa14417618887a0412e404fff56efbafb63d1fc4970a1187b4ccb6e767a91822312e533fa53dee69f77ef5130be095e147ff3d40e96e8ddc4bf554dae3bcc34048fe9330cccf";

        let result = signed_request(&ptb, &eg_keys.1, &eg_keys.2);
        assert_eq!(Hex::encode(result), expected_output);
    }
}
