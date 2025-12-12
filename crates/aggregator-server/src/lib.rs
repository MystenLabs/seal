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
use tracing::{info, warn};

/// Given a list of fetch key responses of servers: (party id, list of (key_id, encrypted_key)),
/// aggregate encrypted keys of all parties for each key id and return a list of aggregated
/// encrypted keys.
pub fn aggregate_encrypted_responses(
    threshold: u16,
    responses: Vec<(u16, FetchKeyResponse)>,
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

/// Verify decryption keys for the partial pk. Only return verified keys and returns error if all
/// failed.
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
