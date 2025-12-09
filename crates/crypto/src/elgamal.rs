// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{GroupElement, Scalar};
use fastcrypto::traits::AllowedRng;
use fastcrypto_tbls::polynomial::Poly;
use fastcrypto_tbls::types::IndexedValue;
use serde::{Deserialize, Serialize};
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
/// Uses fastcrypto-tbls's polynomial implementation for robust Lagrange interpolation.
pub fn aggregate_encrypted<G: GroupElement>(
    threshold: u16,
    encrypted_shares: impl Iterator<Item = (u16, Encryption<G>)>,
) -> FastCryptoResult<Encryption<G>> {
    let shares: Vec<(u16, Encryption<G>)> = encrypted_shares.collect();

    if (shares.len() as u16) < threshold {
        return Err(FastCryptoError::InvalidInput);
    }

    // Convert shares to IndexedValue format (party IDs are 0-indexed, convert to 1-indexed NonZeroU16)
    let c1_shares: Vec<IndexedValue<G>> = shares
        .iter()
        .map(|(id, enc)| {
            let index = NonZeroU16::new(id + 1).ok_or(FastCryptoError::InvalidInput)?;
            Ok(IndexedValue {
                index,
                value: enc.0,
            })
        })
        .collect::<FastCryptoResult<_>>()?;

    let c2_shares: Vec<IndexedValue<G>> = shares
        .iter()
        .map(|(id, enc)| {
            let index = NonZeroU16::new(id + 1).ok_or(FastCryptoError::InvalidInput)?;
            Ok(IndexedValue {
                index,
                value: enc.1,
            })
        })
        .collect::<FastCryptoResult<_>>()?;

    // Use fastcrypto-tbls's Poly::recover_c0 for Lagrange interpolation at x=0
    let result_c1 = Poly::<G>::recover_c0(threshold, c1_shares.iter())?;
    let result_c2 = Poly::<G>::recover_c0(threshold, c2_shares.iter())?;

    Ok(Encryption(result_c1, result_c2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::groups::bls12381::G1Element;
    use fastcrypto::groups::Scalar;
    use fastcrypto_tbls::polynomial::Poly as TblsPoly;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_aggregate_encrypted_with_polynomial_shares() {
        use fastcrypto::groups::bls12381::Scalar;

        let mut rng = StdRng::from_seed([2u8; 32]);

        // Setup: threshold 2 out of 3
        let threshold = 2u16;

        // Create a secret polynomial with constant term = secret
        let secret = G1Element::generator() * Scalar::rand(&mut rng);

        // Generate coefficients for a degree (threshold-1) polynomial
        let coeffs: Vec<G1Element> = (0..threshold)
            .map(|i| {
                if i == 0 {
                    secret // Constant term is the secret
                } else {
                    G1Element::generator() * Scalar::rand(&mut rng)
                }
            })
            .collect();

        let poly = TblsPoly::from(coeffs);

        // Generate ephemeral keys for ElGamal encryption
        let (eg_sk, eg_pk, _eg_vk) = genkey::<_, G1Element, _>(&mut rng);

        // Create shares by evaluating the polynomial at different indices
        let shares: Vec<(u16, Encryption<G1Element>)> = (0..3)
            .map(|party_id| {
                let index = NonZeroU16::new(party_id + 1).unwrap();
                let share_value = poly.eval(index).value;
                let encrypted = encrypt(&mut rng, &share_value, &eg_pk);
                (party_id, encrypted)
            })
            .collect();

        // Aggregate using any 2 of the 3 shares
        let selected_shares = vec![shares[0].clone(), shares[2].clone()];
        let aggregated = aggregate_encrypted(threshold, selected_shares.into_iter()).unwrap();

        // Decrypt the aggregated result
        let decrypted = decrypt(&eg_sk, &aggregated);

        // The decrypted result should equal the secret (constant term of polynomial)
        assert_eq!(decrypted, secret);
    }
}
