// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of a threshold secret-sharing scheme based on Shamir's secret sharing.
//! Secrets can be arbitrary 32 byte values.

use crate::gf256::GF256;
use crate::polynomial::Polynomial;
use crate::utils::transpose;
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use std::iter::repeat_with;

pub struct SecretSharing<const N: usize> {
    pub(crate) secret: [u8; N],
    pub(crate) indices: Vec<u8>,
    pub(crate) shares: Vec<[u8; N]>,
}

impl<const N: usize> SecretSharing<N> {
    pub fn shares(&self) -> &[[u8; N]] {
        &self.shares
    }

    pub fn indices(&self) -> &[u8] {
        &self.indices
    }

    pub fn secret(&self) -> &[u8; N] {
        &self.secret
    }
}

/// Split a secret into `num_shares` shares such that at least `threshold` shares are needed to reconstruct the secret.
pub fn split<R: AllowedRng, const N: usize>(
    rng: &mut R,
    secret: [u8; N],
    threshold: u8,
    number_of_shares: u8,
) -> FastCryptoResult<SecretSharing<N>> {
    if threshold > number_of_shares || threshold == 0 {
        return Err(InvalidInput);
    }

    let indices = (1..=number_of_shares).collect_vec();

    // Share each byte of the secret individually.
    let byte_shares = secret
        .iter()
        .map(|b| split_byte(rng, *b, threshold, &indices))
        .collect::<FastCryptoResult<Vec<_>>>()?;

    // Combine the byte shares into shares.
    let shares = transpose(&byte_shares)?;

    Ok(SecretSharing {
        secret,
        indices,
        shares,
    })
}

/// Interpolate polynomials given a set of shares and return a closure to evaluate the polynomials at a given point.
/// If the number of shares is less than the threshold or some shares are invalid, the result will be wrong but _no_ error is returned.
/// If the indices of the shares are not unique or the set is empty, an [InvalidInput] will be returned.
pub fn interpolate<const N: usize>(
    shares: &[(u8, [u8; N])],
) -> FastCryptoResult<impl Fn(u8) -> [u8; N]> {
    if shares.is_empty()
        || shares.iter().any(|(i, _)| *i == 0)
        || !shares.iter().map(|(i, _)| i).all_unique()
    {
        return Err(InvalidInput);
    }

    let polynomials: Vec<Polynomial> = (0..N)
        .map(|i| {
            Polynomial::interpolate(
                &shares
                    .iter()
                    .map(|(index, share)| (GF256(*index), GF256(share[i])))
                    .collect_vec(),
            )
        })
        .collect();

    Ok(move |x: u8| {
        polynomials
            .iter()
            .map(|p| p.evaluate(&GF256(x)).into())
            .collect_vec()
            .try_into()
            .expect("Fixed length")
    })
}

/// Reconstruct the secret from a set of shares.
/// If the number of shares is less than the threshold or some shares are invalid, the result will be wrong but _no_ error is returned.
/// If the indices of the shares are not unique or the set is empty, an [InvalidInput] will be returned.
pub fn combine<const N: usize>(shares: &[(u8, [u8; N])]) -> FastCryptoResult<[u8; N]> {
    Ok((0..N)
        .map(|i| {
            combine_byte(
                &shares
                    .iter()
                    .map(|share| (share.0, share.1[i]))
                    .collect_vec(),
            )
        })
        .collect::<FastCryptoResult<Vec<_>>>()?
        .try_into()
        .expect("fixed length"))
}

pub fn split_with_given_shares<const N: usize>(
    given_shares: &[[u8; N]],
    number_of_shares: u8,
) -> FastCryptoResult<SecretSharing<N>> {
    let threshold = given_shares.len();
    if threshold > number_of_shares as usize || threshold == 0 {
        return Err(InvalidInput);
    }

    let indices = (1..=number_of_shares).collect_vec();

    // Share each byte of the secret individually.
    let (secret, byte_shares): (Vec<u8>, Vec<Vec<u8>>) = (0..N)
        .map(|i| {
            split_byte_with_given_shares(&given_shares.iter().map(|s| s[i]).collect_vec(), &indices)
        })
        .collect::<FastCryptoResult<Vec<_>>>()?
        .into_iter()
        .unzip();

    // Combine the byte shares into shares.
    let shares = transpose(&byte_shares)?;
    let secret = secret.try_into().expect("fixed length");

    Ok(SecretSharing {
        secret,
        indices,
        shares,
    })
}

/// Internal function to share a secret.
/// This is an implementation of Shamir's secret sharing over the Galois field of 256 elements.
/// See https://dl.acm.org/doi/10.1145/359168.359176.
fn split_byte<R: AllowedRng>(
    rng: &mut R,
    secret: u8,
    threshold: u8,
    indices: &[u8],
) -> FastCryptoResult<Vec<u8>> {
    let number_of_shares = indices.len() as u8;
    if threshold == 0
        || number_of_shares == 0
        || threshold > number_of_shares
        || indices.iter().contains(&0)
        || !indices.iter().all_unique()
    {
        return Err(InvalidInput);
    }

    // Sample a random polynomial of degree `threshold - 1` with the secret as the constant term.
    let mut coefficients = Vec::with_capacity(threshold as usize);
    coefficients.push(GF256::from(secret));
    coefficients.extend(repeat_with(|| GF256::rand(rng)).take((threshold - 1) as usize));
    let polynomial = Polynomial(coefficients);
    Ok(indices
        .iter()
        .map(|i| polynomial.evaluate(&i.into()).into())
        .collect())
}

/// Create a secret sharing of `num_shares` shares such that at least `threshold` shares are needed
/// to reconstruct the byte and such that the first `threshold` shares will be the given ones.
///
/// The shared secret will be determined by the given shares, and the process is deterministic.
///
/// Returns the secret and a vector of the shares.
fn split_byte_with_given_shares(
    given_shares: &[u8],
    indices: &[u8],
) -> FastCryptoResult<(u8, Vec<u8>)> {
    let number_of_shares = indices.len();
    let threshold = given_shares.len() + 1;
    assert!(threshold <= number_of_shares && number_of_shares <= 255 && threshold > 0);
    assert!(indices.iter().all(|&i| i != 0) && indices.iter().all_unique());

    // Construct the polynomial that interpolates the given shares and the secret.
    let polynomial = Polynomial::interpolate(
        &indices
            .iter()
            .zip(given_shares)
            .map(|(&x, &y)| (x.into(), y.into()))
            .collect_vec(),
    );

    // The secret is the constant term of the polynomial.
    let secret = polynomial.0[0].0;

    // Evaluate the polynomial at the remaining indices to get the remaining shares.
    let remaining_shares = indices[given_shares.len()..]
        .iter()
        .map(|i| polynomial.evaluate(&i.into()).0)
        .collect();

    let shares = [given_shares.to_vec(), remaining_shares].concat();

    Ok((secret, shares))
}

/// Internal function to reconstruct a secret.
/// This is an implementation of Shamir's secret sharing over the Galois field of 256 elements.
/// See https://dl.acm.org/doi/10.1145/359168.359176.
fn combine_byte(shares: &[(u8, u8)]) -> FastCryptoResult<u8> {
    if shares.is_empty()
        || !shares.iter().map(|(i, _)| i).all_unique()
        || shares.iter().any(|(i, _)| *i == 0)
    {
        return Err(InvalidInput);
    }
    let product: GF256 = shares.iter().map(|(i, _)| GF256::from(i)).product();
    let quotient: GF256 = shares
        .iter()
        .map(|(i, share_i)| {
            let denominator = &GF256::from(*i)
                * &shares
                    .iter()
                    .map(|(j, _)| j)
                    .filter(|j| j != &i)
                    .map(|j| &GF256::from(j) - &GF256::from(i))
                    .product();
            (&GF256::from(share_i) / &denominator).unwrap()
        })
        .sum();
    Ok((&product * &quotient).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::encoding::{Base64, Encoding};
    use rand::thread_rng;

    #[test]
    fn test_combine_byte() {
        let x = vec![(1, 2), (2, 3), (3, 4), (4, 5)];
        assert_eq!(combine_byte(&x).unwrap(), 202);
    }

    #[test]
    fn test_secret_sharing() {
        let secret = *b"For sale: baby shoes, never worn";

        let SecretSharing {
            indices, shares, ..
        } = split(&mut thread_rng(), secret, 3, 5).unwrap();

        assert_eq!(
            secret,
            combine(&(1..4).map(|i| (indices[i], shares[i])).collect_vec()).unwrap()
        );
        assert_eq!(
            secret,
            combine(&(0..3).map(|i| (indices[i], shares[i])).collect_vec()).unwrap()
        );
        assert_eq!(
            secret,
            combine(&(0..4).map(|i| (indices[i], shares[i])).collect_vec()).unwrap()
        );
        assert_eq!(
            secret,
            combine(&(2..5).map(|i| (indices[i], shares[i])).collect_vec()).unwrap()
        );

        assert_ne!(
            secret,
            combine(&(0..2).map(|i| (indices[i], shares[i])).collect_vec()).unwrap()
        );

        assert!(combine::<32>(&[]).is_err());
        assert!(combine(&[(indices[0], shares[0]), (indices[0], shares[0])]).is_err());
    }

    #[test]
    fn test_invalid_shares() {
        let share1 = [1; 32];
        let share2 = [2; 32];

        // Duplicate indices
        assert!(combine(&[(1u8, share1), (1u8, share2)]).is_err());

        // No shares
        assert!(combine::<32>(&[]).is_err());
    }

    #[test]
    fn typescript_test_vector() {
        const N: usize = 23;
        let expected = *b"My super secret message";
        assert_eq!(expected.len(), N);

        // 2/3 secret sharing
        let shares = vec![
            "C7rQzQ0iL+L+fBcIAZipXBhtZsUju7ot",
            "lO0Boejog7ARBVXjjLUMqAFP/Iut0ZpZ",
            "FsrVroJ5+eWfw7sFgXq8Y3AWDN2Ogvc9",
        ]
        .into_iter()
        .map(Base64::decode)
        .collect::<FastCryptoResult<Vec<_>>>()
        .unwrap();
        let shares = shares
            .iter()
            .map(|bytes| (bytes[N], bytes[..N].try_into().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(combine(&shares[..2]).unwrap(), expected);
        assert_eq!(combine(&shares[1..3]).unwrap(), expected);
        assert_eq!(combine(&shares).unwrap(), expected);

        assert_ne!(combine(&shares[..1]).unwrap(), expected);
    }

    #[test]
    fn test_split_byte_with_given_shares() {
        let given_shares = [5, 19];
        let indices = [1, 2, 3, 4, 5];

        let (secret, shares) = split_byte_with_given_shares(&given_shares, &indices).unwrap();

        let reconstructed = combine_byte(&[
            (indices[0], shares[0]),
            (indices[2], shares[2]),
            (indices[4], shares[4]),
        ])
        .unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_with_given_shares() {
        let given_shares = [
            *b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            *b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            *b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        ];
        let threshold = given_shares.len() as u8;
        let SecretSharing {
            secret,
            indices,
            shares,
        } = split_with_given_shares(&given_shares, 5).unwrap();

        assert_eq!(threshold, given_shares.len() as u8);
        assert_eq!(shares[0], given_shares[0]);
        assert_eq!(shares[1], given_shares[1]);

        assert_eq!(
            secret,
            combine(&(1..4).map(|i| (indices[i], shares[i])).collect_vec()).unwrap()
        );
    }
}
