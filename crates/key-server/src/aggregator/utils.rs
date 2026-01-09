// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crypto::{elgamal, ibe::verify_encrypted_signature};
use fastcrypto::{
    encoding::{Encoding, Hex},
    error::FastCryptoResult,
    groups::bls12381::G2Element,
};
use seal_sdk::{
    types::{DecryptionKey, ElgamalVerificationKey},
    FetchKeyResponse,
};
use std::collections::HashMap;
use tracing::info;

/// Given a list of fetch key responses of servers: (party id, list of (key_id, encrypted_key)),
/// aggregate encrypted keys of all parties for each key id and return a list of aggregated
/// encrypted keys.
pub fn aggregate_verified_encrypted_responses(
    threshold: u16,
    responses: Vec<(u16, FetchKeyResponse)>, // (party_id, response)
) -> FastCryptoResult<FetchKeyResponse> {
    // Build map: key_id -> Vec<(party_id, encrypted_key)>.
    let mut shares_by_key_id: HashMap<Vec<u8>, Vec<(u16, elgamal::Encryption<_>)>> = HashMap::new();

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

/// Verify decryption keys for one party. Returns error if any key fails verification.
pub fn verify_decryption_keys(
    decryption_keys: &[DecryptionKey],
    partial_pk: &G2Element,
    ephemeral_vk: &ElgamalVerificationKey,
    party_id: u16,
) -> Result<Vec<DecryptionKey>, String> {
    let mut verified_keys = Vec::with_capacity(decryption_keys.len());

    for dk in decryption_keys {
        verify_encrypted_signature(&dk.encrypted_key, ephemeral_vk, partial_pk, &dk.id).map_err(
            |e| {
                format!(
                    "Verification failed for party {} key_id={}: {}",
                    party_id,
                    Hex::encode(&dk.id),
                    e
                )
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
