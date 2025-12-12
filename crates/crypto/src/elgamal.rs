// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{GroupElement, Scalar};
use fastcrypto::traits::AllowedRng;
use fastcrypto_tbls::polynomial::Poly;
use fastcrypto_tbls::types::IndexedValue;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::num::NonZeroU16;

#[derive(Serialize, Deserialize)]
pub struct SecretKey<G: GroupElement>(G::ScalarType);

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicKey<G: GroupElement>(G);

#[derive(Serialize, Deserialize, Clone)]
pub struct VerificationKey<G: GroupElement>(G);

impl<G: GroupElement> VerificationKey<G> {
    pub fn as_element(&self) -> &G {
        &self.0
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Encryption<G: GroupElement>(pub G, pub G);

pub fn genkey<G: GroupElement, VG: GroupElement<ScalarType = G::ScalarType>, R: AllowedRng>(
    rng: &mut R,
) -> (SecretKey<G>, PublicKey<G>, VerificationKey<VG>) {
    let sk = G::ScalarType::rand(rng);
    (
        SecretKey(sk),
        PublicKey(G::generator() * sk),
        VerificationKey(VG::generator() * sk),
    )
}

pub fn encrypt<G: GroupElement, R: AllowedRng>(
    rng: &mut R,
    msg: &G,
    pk: &PublicKey<G>,
) -> Encryption<G> {
    let r = G::ScalarType::rand(rng);
    Encryption(G::generator() * r, pk.0 * r + msg)
}

pub fn decrypt<G: GroupElement>(sk: &SecretKey<G>, e: &Encryption<G>) -> G {
    e.1 - e.0 * sk.0
}

/// Homomorphically aggregate ElGamal encryptions using Lagrange interpolation.
pub fn aggregate_encrypted<G: GroupElement>(
    threshold: u16,
    encrypted_shares: &[(u16, Encryption<G>)],
) -> FastCryptoResult<Encryption<G>> {
    // Validate threshold and shares count.
    if threshold == 0
        || encrypted_shares.len() > u16::MAX as usize
        || (encrypted_shares.len() as u16) < threshold
    {
        return Err(FastCryptoError::InvalidInput);
    }

    let mut seen_ids = HashSet::new();
    let mut c1_shares = Vec::with_capacity(encrypted_shares.len());
    let mut c2_shares = Vec::with_capacity(encrypted_shares.len());

    for (id, enc) in encrypted_shares.iter() {
        // Validate party ID < u16::MAX and check for duplicates.
        if *id == u16::MAX || !seen_ids.insert(id) {
            return Err(FastCryptoError::InvalidInput);
        }

        // Convert to IndexedValue.
        let index = NonZeroU16::new(id + 1).expect("Checked above");
        c1_shares.push(IndexedValue {
            index,
            value: enc.0,
        });
        c2_shares.push(IndexedValue {
            index,
            value: enc.1,
        });
    }

    let result_c1 = Poly::<G>::recover_c0(threshold, c1_shares.into_iter())?;
    let result_c2 = Poly::<G>::recover_c0(threshold, c2_shares.into_iter())?;

    Ok(Encryption(result_c1, result_c2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::groups::bls12381::{G1Element, Scalar};
    use fastcrypto::groups::Scalar as _;
    use fastcrypto_tbls::polynomial::Poly as TblsPoly;
    use rand::thread_rng;
    #[test]
    fn test_aggregate_encrypted_with_polynomial_shares() {
        let threshold = 9u16;
        let secret = G1Element::generator() * Scalar::rand(&mut thread_rng());

        // Generate a t-1 degree polynomial.
        let coeffs: Vec<G1Element> = (0..threshold)
            .map(|i| {
                if i == 0 {
                    secret // Constant term is the secret
                } else {
                    G1Element::generator() * Scalar::rand(&mut thread_rng())
                }
            })
            .collect();
        let poly = TblsPoly::from(coeffs);

        // Generate ephemeral keys.
        let (eg_sk, eg_pk, _eg_vk) = genkey::<_, G1Element, _>(&mut thread_rng());

        // Create shares by evaluating the polynomial at different indices.
        let shares: Vec<(u16, Encryption<G1Element>)> = (0..10)
            .map(|party_id| {
                let index = NonZeroU16::new(party_id + 1).unwrap();
                let share_value = poly.eval(index).value;
                let encrypted = encrypt(&mut thread_rng(), &share_value, &eg_pk);
                (party_id, encrypted)
            })
            .collect();

        // Aggregate using any 9 of the 10 shares.
        let selected_shares: Vec<_> = shares.iter().take(9).cloned().collect();
        let aggregated = aggregate_encrypted(threshold, &selected_shares).unwrap();

        // Decrypt it and verifies it equals to secret.
        let decrypted = decrypt(&eg_sk, &aggregated);
        assert_eq!(decrypted, secret);

        // Insufficient shares should fail.
        let insufficient_shares: Vec<_> = shares.iter().take(8).cloned().collect();
        let result = aggregate_encrypted(threshold, &insufficient_shares);
        assert!(result.is_err());
    }
}
