// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::errors::InternalError;
use crate::valid_ptb::ValidPtb;
use crypto::{elgamal, ibe::verify_encrypted_signature};
use fastcrypto::{
    encoding::{Encoding, Hex},
    error::{FastCryptoError, FastCryptoResult},
    groups::bls12381::G2Element,
};
use seal_committee::fetch_first_pkg_id;
use seal_sdk::{
    types::{DecryptionKey, ElgamalEncryption, ElgamalVerificationKey},
    FetchKeyResponse,
};
use std::collections::{HashMap, HashSet};
use sui_rpc::client::Client as SuiGrpcClient;
use sui_sdk_types::Address;
use tracing::info;

/// Parse PTB, resolve its pkg id to the first pkg id via grpc, and return the set of full key ids.
pub async fn get_expected_full_ids(
    grpc_client: &mut SuiGrpcClient,
    ptb_b64: &str,
) -> Result<HashSet<Vec<u8>>, InternalError> {
    let valid_ptb = ValidPtb::try_from_base64(ptb_b64)?;
    let first_pkg_id = fetch_first_pkg_id(
        grpc_client,
        &Address::new(valid_ptb.pkg_id().into_bytes()),
    )
    .await
    .map_err(|_| InternalError::InvalidPackage)?;
    Ok(valid_ptb.full_ids(&first_pkg_id).into_iter().collect())
}

/// Aggregate verified encrypted responses into a single response. Each response is expected to have
/// keys for all key ids, so each key id has the same threshold of shares and aggregates ok.
pub fn aggregate_verified_encrypted_responses(
    threshold: u16,
    responses: Vec<(u16, FetchKeyResponse)>, // (party_id, response)
) -> FastCryptoResult<FetchKeyResponse> {
    if responses.len() != threshold as usize {
        return Err(FastCryptoError::InvalidInput);
    }

    // Build map: key_id -> Vec<(party_id, encrypted_key)>.
    let mut shares_by_key_id: HashMap<Vec<u8>, Vec<(u16, ElgamalEncryption)>> = HashMap::new();
    for (party_id, response) in responses {
        for dk in response.decryption_keys {
            shares_by_key_id
                .entry(dk.id)
                .or_default()
                .push((party_id, dk.encrypted_key));
        }
    }

    let mut decryption_keys = Vec::with_capacity(shares_by_key_id.len());
    for (key_id, encrypted_shares) in shares_by_key_id {
        let aggregated_encrypted = elgamal::aggregate_encrypted(threshold, &encrypted_shares)?;
        decryption_keys.push(DecryptionKey {
            id: key_id,
            encrypted_key: aggregated_encrypted,
        });
    }

    Ok(FetchKeyResponse { decryption_keys })
}

/// Validate a key server's response: the response's key ids must match `expected_full_ids`
/// exactly, and each encrypted share must verify against the member's `partial_pk` under the
/// ephemeral verification key. Errors out if any checks failed.
pub fn verify_decryption_keys(
    decryption_keys: &[DecryptionKey],
    partial_pk: &G2Element,
    ephemeral_vk: &ElgamalVerificationKey,
    party_id: u16,
    expected_full_ids: &HashSet<Vec<u8>>,
) -> Result<Vec<DecryptionKey>, InternalError> {
    if decryption_keys.len() != expected_full_ids.len() {
        return Err(InternalError::Failure(format!(
            "party {party_id} returned {} key(s), expected {}",
            decryption_keys.len(),
            expected_full_ids.len()
        )));
    }

    let mut seen = HashSet::with_capacity(decryption_keys.len());
    for dk in decryption_keys {
        if !expected_full_ids.contains(&dk.id) {
            return Err(InternalError::Failure(format!(
                "unexpected key_id {} from party {party_id}",
                Hex::encode(&dk.id)
            )));
        }
        if !seen.insert(&dk.id) {
            return Err(InternalError::Failure(format!(
                "duplicate key_id {} from party {party_id}",
                Hex::encode(&dk.id)
            )));
        }
    }

    let mut verified_keys = Vec::with_capacity(decryption_keys.len());
    for dk in decryption_keys {
        verify_encrypted_signature(&dk.encrypted_key, ephemeral_vk, partial_pk, &dk.id).map_err(
            |e| {
                InternalError::Failure(format!(
                    "verification failed for party {party_id} key_id={}: {e}",
                    Hex::encode(&dk.id)
                ))
            },
        )?;
        verified_keys.push(dk.clone());
    }

    info!(
        "Verified all {} decryption keys from party {}",
        decryption_keys.len(),
        party_id
    );

    Ok(verified_keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::elgamal::{encrypt, genkey};
    use fastcrypto::groups::bls12381::{G1Element, Scalar};
    use fastcrypto::groups::{GroupElement, Scalar as _};
    use rand::thread_rng;

    /// Build a full key id (`[all zero pkg id][inner]`) for testing.
    fn full_id_for_testing(inner: &[u8]) -> Vec<u8> {
        [&[0u8; 32][..], inner].concat()
    }

    /// Build a `DecryptionKey` for testing with `full_id_for_testing(inner)` as its id and a
    /// placeholder encrypted share. Id checks run before signature verification, so the share
    /// does not need to be a valid IBE encryption.
    fn dk_for_testing(inner: &[u8]) -> DecryptionKey {
        let mut rng = thread_rng();
        let (_, eg_pk, _) = genkey::<G1Element, G1Element, _>(&mut rng);
        let secret = G1Element::generator() * Scalar::rand(&mut rng);
        DecryptionKey {
            id: full_id_for_testing(inner),
            encrypted_key: encrypt(&mut rng, &secret, &eg_pk),
        }
    }

    /// Returns dummy partial_pk / ephemeral_vk for testing.
    fn partial_pk_and_eph_vk_for_testing() -> (G2Element, ElgamalVerificationKey) {
        let mut rng = thread_rng();
        let (_, _, eg_vk) = genkey::<G1Element, G2Element, _>(&mut rng);
        (G2Element::generator(), eg_vk)
    }

    #[test]
    fn aggregate_errors_when_responses_below_threshold() {
        let mut rng = thread_rng();
        let (_, eg_pk, _) = genkey::<G1Element, G1Element, _>(&mut rng);
        let share = G1Element::generator() * Scalar::rand(&mut rng);
        let encrypted_key = encrypt(&mut rng, &share, &eg_pk);

        let responses = vec![(
            0u16,
            FetchKeyResponse {
                decryption_keys: vec![DecryptionKey {
                    id: b"id".to_vec(),
                    encrypted_key,
                }],
            },
        )];

        let result = aggregate_verified_encrypted_responses(2, responses);
        assert!(matches!(result, Err(FastCryptoError::InvalidInput)));
    }

    #[test]
    fn verify_rejects_too_few_keys() {
        let (partial_pk, eg_vk) = partial_pk_and_eph_vk_for_testing();
        let expected = [full_id_for_testing(b"a"), full_id_for_testing(b"b")]
            .into_iter()
            .collect();
        let keys = vec![dk_for_testing(b"a")];
        let result = verify_decryption_keys(&keys, &partial_pk, &eg_vk, 0, &expected);
        assert!(matches!(result, Err(InternalError::Failure(_))));
    }

    #[test]
    fn verify_rejects_too_many_keys() {
        let (partial_pk, eg_vk) = partial_pk_and_eph_vk_for_testing();
        let expected = [full_id_for_testing(b"a")].into_iter().collect();
        let keys = vec![dk_for_testing(b"a"), dk_for_testing(b"b")];
        let result = verify_decryption_keys(&keys, &partial_pk, &eg_vk, 0, &expected);
        assert!(matches!(result, Err(InternalError::Failure(_))));
    }

    #[test]
    fn verify_rejects_unexpected_id() {
        let (partial_pk, eg_vk) = partial_pk_and_eph_vk_for_testing();
        let expected = [full_id_for_testing(b"a")].into_iter().collect();
        let keys = vec![dk_for_testing(b"b")];
        let result = verify_decryption_keys(&keys, &partial_pk, &eg_vk, 0, &expected);
        assert!(matches!(result, Err(InternalError::Failure(_))));
    }

    #[test]
    fn verify_rejects_wrong_pkg_id_prefix() {
        // A malicious key server returns full id with wrong package id, fails.
        let (partial_pk, eg_vk) = partial_pk_and_eph_vk_for_testing();
        let expected = [full_id_for_testing(b"a")].into_iter().collect();
        let wrong_full_id = [&[9u8; 32][..], b"a"].concat();
        let mut key = dk_for_testing(b"a");
        key.id = wrong_full_id;
        let keys = vec![key];
        let result = verify_decryption_keys(&keys, &partial_pk, &eg_vk, 0, &expected);
        assert!(matches!(result, Err(InternalError::Failure(_))));
    }

    #[test]
    fn verify_rejects_duplicate_id() {
        let (partial_pk, eg_vk) = partial_pk_and_eph_vk_for_testing();
        let expected = [full_id_for_testing(b"a"), full_id_for_testing(b"b")]
            .into_iter()
            .collect();
        let keys = vec![dk_for_testing(b"a"), dk_for_testing(b"a")];
        let result = verify_decryption_keys(&keys, &partial_pk, &eg_vk, 0, &expected);
        assert!(matches!(result, Err(InternalError::Failure(_))));
    }
}
