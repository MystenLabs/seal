// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::groups::{GroupElement, Scalar};
use fastcrypto::traits::AllowedRng;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct SecretKey<G: GroupElement>(G::ScalarType);

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicKey<G: GroupElement>(G);

#[derive(Serialize, Deserialize, Clone)]
pub struct VerificationKey<G: GroupElement>(G);

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
///
/// Given encrypted shares Enc(s_i) for i in indices, computes Enc(Σ λ_i * s_i)
/// where λ_i are Lagrange coefficients for threshold reconstruction.
///
/// This allows threshold aggregation WITHOUT decrypting individual shares.
/// The aggregator never sees plaintext values, preserving privacy.
///
/// # Arguments
/// * `threshold` - Minimum number of shares needed (t)
/// * `encrypted_shares` - Iterator of (party_id, Enc(share_i)) pairs
///
/// # Returns
/// Encryption of the aggregated secret: Enc(reconstructed_secret)
pub fn aggregate_encrypted<G: GroupElement>(
    threshold: u16,
    encrypted_shares: impl Iterator<Item = (u16, Encryption<G>)>,
) -> Result<Encryption<G>, &'static str> {
    let shares: Vec<(u16, Encryption<G>)> = encrypted_shares.collect();

    if shares.len() < threshold as usize {
        return Err("Insufficient shares for threshold");
    }

    // Compute Lagrange coefficients at x=0 for the given indices
    // λ_i = Π_{j≠i} (0 - x_j) / (x_i - x_j) = Π_{j≠i} x_j / (x_j - x_i)
    let indices: Vec<u16> = shares.iter().map(|(id, _)| id + 1).collect(); // Party IDs are 0-indexed, Lagrange uses 1-indexed

    let mut result_c1 = G::zero();
    let mut result_c2 = G::zero();

    for (i, (party_id, encryption)) in shares.iter().enumerate() {
        let x_i = (party_id + 1) as i64; // Convert to 1-indexed

        // Compute Lagrange coefficient λ_i
        let mut numerator = 1i64;
        let mut denominator = 1i64;

        for (j, x_j_minus_1) in indices.iter().enumerate() {
            if i != j {
                let x_j = *x_j_minus_1 as i64;
                numerator *= -x_j; // (0 - x_j)
                denominator *= x_i - x_j;
            }
        }

        // Convert to field element
        // λ_i = numerator / denominator (in the scalar field)
        let lambda = compute_lagrange_scalar::<G>(numerator, denominator)?;

        // Homomorphically scale: Enc^λ = (c1^λ, c2^λ)
        let scaled_c1 = encryption.0 * lambda;
        let scaled_c2 = encryption.1 * lambda;

        // Homomorphically add: accumulate the scaled encryptions
        result_c1 += scaled_c1;
        result_c2 += scaled_c2;
    }

    Ok(Encryption(result_c1, result_c2))
}

/// Helper to compute Lagrange coefficient as a scalar field element
fn compute_lagrange_scalar<G: GroupElement>(
    numerator: i64,
    denominator: i64,
) -> Result<G::ScalarType, &'static str> {
    use fastcrypto::groups::Scalar;

    // Convert numerator to scalar
    let num_scalar = if numerator >= 0 {
        G::ScalarType::from(numerator as u128)
    } else {
        G::ScalarType::zero() - G::ScalarType::from((-numerator) as u128)
    };

    // Convert denominator to scalar
    let denom_scalar = if denominator >= 0 {
        G::ScalarType::from(denominator as u128)
    } else {
        G::ScalarType::zero() - G::ScalarType::from((-denominator) as u128)
    };

    // Compute inverse: denominator^-1
    let denom_inv = denom_scalar
        .inverse()
        .map_err(|_| "Failed to compute inverse")?;

    // Return numerator * denominator^-1
    Ok(num_scalar * denom_inv)
}
