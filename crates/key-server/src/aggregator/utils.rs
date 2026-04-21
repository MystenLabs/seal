// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crypto::{elgamal, ibe::verify_encrypted_signature};
use fastcrypto::{
    encoding::{Encoding, Hex},
    error::{FastCryptoError, FastCryptoResult},
    groups::bls12381::G2Element,
};
use seal_sdk::{
    types::{DecryptionKey, ElgamalEncryption, ElgamalVerificationKey},
    FetchKeyResponse,
};
use std::collections::{HashMap, HashSet};
use tracing::{info, warn};

/// Build `key_id -> [(party_id, encrypted_share)]`.
pub type SharesByKeyId = HashMap<Vec<u8>, Vec<(u16, ElgamalEncryption)>>;

/// Aggregate verified encrypted shares into a single response for all key ids. If a key id cannot
/// reach threshold, log missing parties and skip.
pub fn aggregate_verified_encrypted_responses(
    threshold: u16,
    shares_by_key_id: SharesByKeyId,
    responded_parties: &HashSet<u16>,
) -> FastCryptoResult<FetchKeyResponse> {
    if (responded_parties.len() as u16) < threshold {
        return Err(FastCryptoError::InvalidInput);
    }

    let mut decryption_keys = Vec::with_capacity(shares_by_key_id.len());
    for (key_id, mut shares) in shares_by_key_id {
        // Skip ids that cannot reach threshold and log missing parties.
        if (shares.len() as u16) < threshold {
            let contributed: HashSet<u16> = shares.iter().map(|(p, _)| *p).collect();
            let missing: Vec<u16> = responded_parties
                .difference(&contributed)
                .copied()
                .collect();
            warn!(
                "Skipping key_id {}: {} share(s), threshold {}, omitted by parties {:?}",
                Hex::encode(&key_id),
                shares.len(),
                threshold,
                missing,
            );
            continue;
        }
        // Truncate the shares to threshold and aggregate.
        shares.truncate(threshold as usize);
        let aggregated_encrypted = elgamal::aggregate_encrypted(threshold, &shares)?;
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
    let mut seen_ids = HashSet::with_capacity(decryption_keys.len());

    for dk in decryption_keys {
        if !seen_ids.insert(&dk.id) {
            return Err(format!(
                "Duplicate key_id {} from party {}",
                Hex::encode(&dk.id),
                party_id
            ));
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::elgamal::{decrypt, encrypt, genkey};
    use crypto::ibe::{extract, public_key_from_master_key, MasterKey};
    use fastcrypto::groups::bls12381::{G1Element, G2Element, Scalar};
    use fastcrypto::groups::{GroupElement, Scalar as _};
    use fastcrypto_tbls::polynomial::Poly as TblsPoly;
    use rand::thread_rng;
    use std::num::NonZeroU16;

    /// Produce `n_parties` encrypted shares of a fresh degree-(`threshold`-1) polynomial.
    /// The shares are evaluated at indices 1..=n_parties to match `aggregate_encrypted`'s
    /// party_id -> index mapping.
    fn build_encrypted_shares(
        threshold: u16,
        n_parties: u16,
        eg_pk: &crypto::elgamal::PublicKey<G1Element>,
    ) -> (G1Element, Vec<crypto::elgamal::Encryption<G1Element>>) {
        let mut rng = thread_rng();
        let secret = G1Element::generator() * Scalar::rand(&mut rng);
        let mut coeffs = vec![secret];
        for _ in 1..threshold {
            coeffs.push(G1Element::generator() * Scalar::rand(&mut rng));
        }
        let poly = TblsPoly::from(coeffs);
        let shares = (0..n_parties)
            .map(|i| {
                let share = poly.eval(NonZeroU16::new(i + 1).unwrap()).value;
                encrypt(&mut rng, &share, eg_pk)
            })
            .collect();
        (secret, shares)
    }

    #[test]
    fn aggregate_fails_for_injected_key_id() {
        let threshold = 2u16;
        let mut rng = thread_rng();
        let (eg_sk, eg_pk, _) = genkey::<G1Element, G1Element, _>(&mut rng);

        let (secret_a, shares_a) = build_encrypted_shares(threshold, 3, &eg_pk);
        let (secret_b, shares_b) = build_encrypted_shares(threshold, 3, &eg_pk);
        let (_, shares_fake) = build_encrypted_shares(threshold, 3, &eg_pk);

        let key_a = b"id_a".to_vec();
        let key_b = b"id_b".to_vec();
        let key_fake = b"injected".to_vec();

        // threshold=2, n=3. Party 0 is malicious; parties 1 and 2 are honest.
        let mut shares_by_key_id: SharesByKeyId = HashMap::new();
        // key_id_a: 3 shares from parties 0, 1, 2.
        shares_by_key_id.insert(
            key_a.clone(),
            vec![
                (0, shares_a[0].clone()),
                (1, shares_a[1].clone()),
                (2, shares_a[2].clone()),
            ],
        );
        // key_id_b: 2 shares from parties 1 and 2 — party 0 censored it.
        shares_by_key_id.insert(
            key_b.clone(),
            vec![(1, shares_b[1].clone()), (2, shares_b[2].clone())],
        );
        // key_id_fake: 1 share from party 0 only.
        shares_by_key_id.insert(key_fake, vec![(0, shares_fake[0].clone())]);
        let responded_parties: HashSet<u16> = [0, 1, 2].into_iter().collect();

        let aggregated =
            aggregate_verified_encrypted_responses(threshold, shares_by_key_id, &responded_parties)
                .expect("aggregation should succeed");

        // key_id_a and key_id_b aggregate; key_id_fake is skipped.
        assert_eq!(aggregated.decryption_keys.len(), 2);
        for dk in aggregated.decryption_keys {
            let recovered = decrypt(&eg_sk, &dk.encrypted_key);
            if dk.id == key_a {
                assert_eq!(recovered, secret_a);
            } else if dk.id == key_b {
                assert_eq!(recovered, secret_b);
            }
        }
    }

    #[test]
    fn aggregate_errors_when_too_few_responders() {
        let responded_parties: HashSet<u16> = [0, 1].into_iter().collect();
        let result =
            aggregate_verified_encrypted_responses(3, SharesByKeyId::new(), &responded_parties);
        assert!(matches!(result, Err(FastCryptoError::InvalidInput)));
    }

    #[test]
    fn verify_decryption_keys_rejects_duplicate_key_ids() {
        let mut rng = thread_rng();
        let master = MasterKey::rand(&mut rng);
        let partial_pk = public_key_from_master_key(&master);
        let (_, eg_pk, eg_vk) = genkey::<G1Element, G2Element, _>(&mut rng);

        let id = b"dup".to_vec();
        let usk = extract(&master, &id);
        let enc = encrypt(&mut rng, &usk, &eg_pk);

        let dks = vec![
            DecryptionKey {
                id: id.clone(),
                encrypted_key: enc.clone(),
            },
            DecryptionKey {
                id: id.clone(),
                encrypted_key: enc,
            },
        ];
        let result = verify_decryption_keys(&dks, &partial_pk, &eg_vk, 0);
        assert!(matches!(result, Err(e) if e.contains("Duplicate")));
    }
}
