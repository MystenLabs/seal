// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ibe::{
    decrypt_deterministic, decrypt_randomness, encrypt_batched_deterministic, verify_nonce,
};
use crate::tss::{combine, interpolate, SecretSharing};
use fastcrypto::error::FastCryptoError::{GeneralError, InvalidInput};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::Scalar;
use fastcrypto::hash::{HashFunction, Sha3_256};
use fastcrypto_lattice::falcon_util::falcon;
use fastcrypto_lattice::falcon_util::falcon_field::Felt;
use fastcrypto_lattice::falcon_util::polynomial::Polynomial;
use fastcrypto_lattice::ibe::{sample_polynomial_from_seed, IBE};
use itertools::Itertools;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::HashMap;
pub use sui_sdk_types::Address as ObjectID;
use tss::split;
use utils::{generate_random_bytes, xor};

pub mod dem;
pub mod elgamal;
pub mod gf256;
pub mod ibe;
mod polynomial;
pub mod prefixed_hex;
pub mod tss;
mod utils;

/// The domain separation tag for generating H1(id)
pub const DST_ID: &[u8] = b"SUI-SEAL-IBE-BLS12381-00";

/// The domain separation tag for the hash-to-group unction used in PoP.
pub const DST_POP: &[u8] = b"SUI-SEAL-IBE-BLS12381-POP-00";

/// Domain separation tag for [ibe::kdf]
pub const DST_KDF: &[u8] = b"SUI-SEAL-IBE-BLS12381-H2-00";

/// Domain separation tag for [crate::derive_key]
pub const DST_DERIVE_KEY: &[u8] = b"SUI-SEAL-IBE-BLS12381-H3-00";

pub const KEY_SIZE: usize = 32;

/// This represents an encrypted object.
/// Must be aligned with TypeScript type.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedObject {
    pub version: u8,
    pub package_id: ObjectID,
    pub id: Vec<u8>,
    // The address for a key server + the index of the share held by this server
    pub services: Vec<(ObjectID, u8)>,
    pub threshold: u8,
    pub encrypted_shares: IBEEncryptions,
    pub ciphertext: Ciphertext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Ciphertext {
    Aes256Gcm {
        blob: Vec<u8>,
        aad: Option<Vec<u8>>,
    },
    Hmac256Ctr {
        blob: Vec<u8>,
        aad: Option<Vec<u8>>,
        mac: [u8; KEY_SIZE],
    },
    Plain,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IBEEncryptions {
    BonehFranklinBLS12381 {
        nonce: ibe::Nonce,
        encrypted_shares: Vec<ibe::Ciphertext>,
        encrypted_randomness: ibe::EncryptedRandomness,
    },
    Falcon512 {
        encrypted_shares: Vec<fastcrypto_lattice::ibe::Ciphertext<512>>,
        encrypted_randomness: [u8; KEY_SIZE],
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IBEPublicKeys {
    BonehFranklinBLS12381(Vec<ibe::PublicKey>),
    Falcon512(Vec<falcon::PublicKey<512>>),
}

pub enum IBEUserSecretKeys {
    BonehFranklinBLS12381(HashMap<ObjectID, ibe::UserSecretKey>),
    Falcon512(HashMap<ObjectID, falcon::Signature<512>>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EncryptionInput {
    Aes256Gcm { data: Vec<u8>, aad: Option<Vec<u8>> },
    Hmac256Ctr { data: Vec<u8>, aad: Option<Vec<u8>> },
    Plain,
}

/// Encrypt the given plaintext. This is done as follows:
///  - Generate a random AES key and encrypt the message under this key,
///  - Secret share the key with one share per key-server using the protocol defined in the tss module,
///  - For each key-server, encrypt the share using IBE,
///  - Return the ciphertext, encrypted shares, and the common key encryption nonce.
///
/// @param package_id The package id.
/// @param id The id.
/// @param key_servers The seal key services to use for the encryption.
/// @param public_keys The public keys of the key servers.
/// @param threshold The threshold for the TSS.
/// @param encryption_input The encryption input.
/// @return The encrypted object and the derived symmetric key used for the encryption.
pub fn seal_encrypt(
    package_id: ObjectID,
    id: Vec<u8>,
    key_servers: Vec<ObjectID>,
    public_keys: &IBEPublicKeys,
    threshold: u8,
    encryption_input: EncryptionInput,
) -> FastCryptoResult<(EncryptedObject, [u8; KEY_SIZE])> {
    let number_of_shares = key_servers.len() as u8;
    if threshold > number_of_shares || threshold == 0 {
        return Err(InvalidInput);
    }

    let mut rng = thread_rng();
    let full_id = create_full_id(&package_id.into_inner(), &id);

    // Generate a random base key
    let base_key = generate_random_bytes(&mut rng);

    // Secret share the derived key
    let SecretSharing {
        indices, shares, ..
    } = split(&mut rng, base_key, threshold, number_of_shares)?;

    let services = key_servers.iter().cloned().zip(indices).collect::<Vec<_>>();

    let encrypted_shares = match public_keys {
        IBEPublicKeys::BonehFranklinBLS12381(pks) => {
            if pks.len() != number_of_shares as usize {
                return Err(InvalidInput);
            }
            let randomness = ibe::Randomness::rand(&mut rng);

            // Encrypt the shares using the IBE keys.
            // Use the share index as the `index` parameter for the IBE decryption, allowing encrypting shares for the same identity to the same public key.
            let (nonce, encrypted_shares) =
                encrypt_batched_deterministic(&randomness, &shares, pks, &full_id, &services)?;
            let encrypted_randomness = ibe::encrypt_randomness(
                &randomness,
                &derive_key(
                    KeyPurpose::EncryptedRandomness,
                    &base_key,
                    &encrypted_shares,
                    threshold,
                    &key_servers,
                ),
            );
            IBEEncryptions::BonehFranklinBLS12381 {
                nonce,
                encrypted_shares,
                encrypted_randomness,
            }
        }
        IBEPublicKeys::Falcon512(pks) => {
            if pks.len() != number_of_shares as usize {
                return Err(InvalidInput);
            }

            let randomness: [u8; KEY_SIZE] = generate_random_bytes(&mut rng);

            let encrypted_shares = pks
                .iter()
                .zip(&services)
                .zip(shares)
                .map(|((pk, (_, idx)), share)| {
                    let polys = derive_falcon_share_randomness(&randomness, *idx, pk, &full_id);
                    fastcrypto_lattice::ibe::FalconIBE::encrypt_deterministic(
                        polys,
                        pk,
                        &fastcrypto_lattice::ibe::Plaintext::<32>(share),
                        &full_id,
                    )
                })
                .collect_vec();

            let ciphertext_bytes: Vec<Vec<u8>> = encrypted_shares
                .iter()
                .map(|c| bcs::to_bytes(c).expect("serializable"))
                .collect();
            let encrypted_randomness = xor(
                &randomness,
                &derive_key(
                    KeyPurpose::EncryptedRandomness,
                    &base_key,
                    &ciphertext_bytes,
                    threshold,
                    &key_servers,
                ),
            );

            IBEEncryptions::Falcon512 {
                encrypted_shares,
                encrypted_randomness,
            }
        }
    };

    // Derive the key used by the DEM
    let dem_key = derive_key(
        KeyPurpose::DEM,
        &base_key,
        &encrypted_shares.ciphertexts(),
        threshold,
        &key_servers,
    );
    let ciphertext = encryption_input.encrypt(&dem_key);

    Ok((
        EncryptedObject {
            version: 0,
            package_id,
            id,
            services,
            threshold,
            encrypted_shares,
            ciphertext,
        },
        dem_key,
    ))
}

/// Decrypt the given ciphertext as follows:
///  - Decapsulate the IBE keys for the given nonce and user secret keys,
///  - Decrypt the shares using the deltas,
///  - Reconstruct the AES key from the shares,
///  - Decrypt the ciphertext using the AES key.
///
/// @param encrypted_object The encrypted object. See `seal_encrypt`.
/// @param user_secret_keys The user secret keys. It's assumed that these are validated. Otherwise, the decryption will fail or, eg. in the case of using `Plain` mode, the derived key will be wrong.
/// @param public_keys The public keys of the key servers. If provided, all shares will be decrypted and checked for consistency.
/// @return The decrypted plaintext or, if `Plain` mode was used, the derived key.
pub fn seal_decrypt(
    encrypted_object: &EncryptedObject,
    user_secret_keys: &IBEUserSecretKeys,
    public_keys: Option<&IBEPublicKeys>,
) -> FastCryptoResult<Vec<u8>> {
    let EncryptedObject {
        version,
        package_id,
        id,
        encrypted_shares,
        services,
        threshold,
        ciphertext,
        ..
    } = encrypted_object;

    if *version != 0 {
        return Err(InvalidInput);
    }

    let full_id = create_full_id(package_id.inner(), id);

    // Decap IBE keys and decrypt shares
    let shares = match (&encrypted_shares, user_secret_keys) {
        (
            IBEEncryptions::BonehFranklinBLS12381 {
                nonce,
                encrypted_shares,
                ..
            },
            IBEUserSecretKeys::BonehFranklinBLS12381(user_secret_keys),
        ) => {
            // Check that the encrypted object is valid,
            // e.g., that there is an encrypted share of the key per service
            if encrypted_shares.len() != services.len() {
                return Err(InvalidInput);
            }

            // The indices of the services for which we have a secret key
            let service_indices: Vec<usize> = services
                .iter()
                .enumerate()
                .filter(|(_, (id, _))| user_secret_keys.contains_key(id))
                .map(|(i, _)| i)
                .collect();
            if service_indices.len() < *threshold as usize {
                return Err(InvalidInput);
            }

            service_indices
                .into_iter()
                .map(|i| {
                    let (object_id, index) = services[i];
                    (index, ibe::decrypt(
                        nonce,
                        &encrypted_shares[i],
                        user_secret_keys
                            .get(&object_id)
                            .expect("This shouldn't happen: It's checked above that this secret key is available"),
                        &full_id,
                        &(object_id, index),
                    ))
                })
                .collect_vec()
        }
        (
            IBEEncryptions::Falcon512 {
                encrypted_shares, ..
            },
            IBEUserSecretKeys::Falcon512(user_secret_keys),
        ) => {
            // Check that the encrypted object is valid,
            // e.g., that there is an encrypted share of the key per service
            if encrypted_shares.len() != services.len() {
                return Err(InvalidInput);
            }

            let service_indices: Vec<usize> = services
                .iter()
                .enumerate()
                .filter(|(_, (id, _))| user_secret_keys.contains_key(id))
                .map(|(i, _)| i)
                .collect();
            if service_indices.len() < *threshold as usize {
                return Err(InvalidInput);
            }

            service_indices
                .into_iter()
                .map(|i| {
                    let (object_id, index) = services[i];
                    let user_secret_key = user_secret_keys
                        .get(&object_id)
                        .expect("This shouldn't happen: It's checked above that this secret key is available");
                    (index, fastcrypto_lattice::ibe::FalconIBE::decrypt(
                        user_secret_key,
                        &encrypted_shares[i],
                    ).0)
                })
                .collect_vec()
        }
        _ => panic!("This shouldn't happen: It's not checked above that this secret"),
    };

    // Create the base key from the shares
    let base_key = if let Some(public_keys) = public_keys {
        encrypted_shares.combine_and_check_share_consistency(
            &shares,
            &full_id,
            services,
            *threshold,
            public_keys,
        )?
    } else {
        encrypted_shares.combine_and_verify_nonce(&shares, services, *threshold)?
    };

    // Derive symmetric key and decrypt the ciphertext
    let dem_key = derive_key(
        KeyPurpose::DEM,
        &base_key,
        &encrypted_shares.ciphertexts(),
        *threshold,
        &services.iter().map(|(id, _)| *id).collect_vec(),
    );

    ciphertext.decrypt(&dem_key)
}

/// Create a full id from a package id and an inner id. The result has the following format: [package_id][id].
pub fn create_full_id(package_id: &[u8; 32], id: &[u8]) -> Vec<u8> {
    [package_id, id].concat()
}

/// An enum representing the different purposes of the derived key.
pub enum KeyPurpose {
    /// The key used to encrypt the encryption randomness.
    EncryptedRandomness,
    /// The key used by the DEM.
    DEM,
}

impl KeyPurpose {
    fn tag(&self) -> &[u8] {
        match self {
            KeyPurpose::EncryptedRandomness => &[0],
            KeyPurpose::DEM => &[1],
        }
    }
}

/// Domain separation tag for the Falcon per-share randomness derivation.
const DST_FALCON_SHARE_RANDOMNESS: &[u8] = b"SUI-SEAL-IBE-FALCON512-SHARE-RAND-00";

/// Derive the four small polynomials needed by [`fastcrypto_lattice::ibe::FalconIBE::encrypt_deterministic`]
/// from a global seed, the share index, the recipient's public key, and the full id.
/// Corresponds to `Hash(r, i, A_i, H(ID))` in the protocol.
fn derive_falcon_share_randomness(
    seed: &[u8; KEY_SIZE],
    index: u8,
    pk: &falcon::PublicKey<512>,
    full_id: &[u8],
) -> (
    Polynomial<Felt>,
    Polynomial<Felt>,
    Polynomial<Felt>,
    Polynomial<Felt>,
) {
    const N: usize = 512;
    let pk_bytes = bcs::to_bytes(pk).expect("serializable");
    let make = |tag: &[u8], range: std::ops::RangeInclusive<i32>| {
        let seed_input = [
            DST_FALCON_SHARE_RANDOMNESS,
            tag,
            seed,
            &[index],
            &pk_bytes,
            full_id,
        ]
        .concat();
        sample_polynomial_from_seed(N, &seed_input, range)
    };
    (
        make(b"k", 0..=1),
        make(b"r", -1..=1),
        make(b"e1", -1..=1),
        make(b"e2", -1..=1),
    )
}

/// Derive a key for a specific purpose from the base key.
///
/// Note that in the paper, the public keys are used instead of the object id's of the key servers,
/// but since there is a 1-1 mapping between the two, we can use the object id's instead.
fn derive_key(
    purpose: KeyPurpose,
    base_key: &[u8; KEY_SIZE],
    encrypted_shares: &[impl AsRef<[u8]>],
    threshold: u8,
    key_servers: &[ObjectID],
) -> [u8; KEY_SIZE] {
    assert_eq!(encrypted_shares.len(), key_servers.len());
    let mut hash = Sha3_256::new();
    hash.update(DST_DERIVE_KEY);
    hash.update(base_key);
    hash.update(purpose.tag());
    hash.update([threshold]);
    for encrypted_share in encrypted_shares {
        hash.update(encrypted_share.as_ref());
    }
    for key_server in key_servers {
        hash.update(key_server.as_bytes());
    }
    hash.finalize().digest
}

impl IBEEncryptions {
    /// Given all shares, check that the shares are consistent, e.g., check that all subsets of shares would reconstruct the same polynomial.
    /// If there are not enough shares, this will return an error.
    /// Returns the reconstructed secret, aka the base key.
    fn combine_and_check_share_consistency(
        &self,
        shares: &[(u8, [u8; KEY_SIZE])],
        full_id: &[u8],
        services: &[(ObjectID, u8)],
        threshold: u8,
        public_keys: &IBEPublicKeys,
    ) -> FastCryptoResult<[u8; KEY_SIZE]> {
        // Compute the entire polynomial from the given shares.
        let polynomial = interpolate(shares)?;
        let base_key = polynomial(0);

        // Decrypt all shares using the derived key
        let all_shares = self.decrypt_all_shares_and_verify_nonce(
            full_id,
            services,
            public_keys,
            &base_key,
            threshold,
        )?;

        // Check that all shares are points on the reconstructed polynomials
        if all_shares
            .into_iter()
            .any(|(i, share)| polynomial(i) != share)
        {
            return Err(GeneralError("Inconsistent shares".to_string()));
        }
        Ok(base_key)
    }

    /// Given enough shares, combine them to reconstruct the base key.
    /// If there are not enough shares, this will return an error.
    /// This also verifies the nonce and returns an error if the nonce is invalid.
    fn combine_and_verify_nonce(
        &self,
        shares: &[(u8, [u8; KEY_SIZE])],
        services: &[(ObjectID, u8)],
        threshold: u8,
    ) -> FastCryptoResult<[u8; KEY_SIZE]> {
        let base_key = combine(shares)?;
        match self {
            IBEEncryptions::BonehFranklinBLS12381 {
                encrypted_shares,
                encrypted_randomness,
                nonce,
            } => {
                let randomness_key = derive_key(
                    KeyPurpose::EncryptedRandomness,
                    &base_key,
                    encrypted_shares,
                    threshold,
                    &services.iter().map(|(id, _)| *id).collect_vec(),
                );
                let randomness = decrypt_randomness(encrypted_randomness, &randomness_key)?;
                verify_nonce(&randomness, nonce)?;
            }
            IBEEncryptions::Falcon512 { .. } => {
                // No nonce to verify; the encrypted randomness only matters when
                // `combine_and_check_share_consistency` is called with the public keys.
            }
        }
        Ok(base_key)
    }

    /// Given the derived key, decrypt all shares and verify the nonce.
    fn decrypt_all_shares_and_verify_nonce(
        &self,
        full_id: &[u8],
        services: &[(ObjectID, u8)],
        public_keys: &IBEPublicKeys,
        base_key: &[u8; KEY_SIZE],
        threshold: u8,
    ) -> FastCryptoResult<Vec<(u8, [u8; KEY_SIZE])>> {
        match (self, public_keys) {
            (
                IBEEncryptions::BonehFranklinBLS12381 {
                    encrypted_randomness,
                    encrypted_shares,
                    nonce,
                },
                IBEPublicKeys::BonehFranklinBLS12381(public_keys),
            ) => {
                // Decrypt encrypted nonce,
                let randomness = decrypt_randomness(
                    encrypted_randomness,
                    &derive_key(
                        KeyPurpose::EncryptedRandomness,
                        base_key,
                        &self.ciphertexts(),
                        threshold,
                        &services.iter().map(|(id, _)| *id).collect_vec(),
                    ),
                )?;

                // Verify that the nonce is valid
                verify_nonce(&randomness, nonce)?;

                // Decrypt all shares
                if public_keys.len() != encrypted_shares.len() {
                    return Err(InvalidInput);
                }
                public_keys
                    .iter()
                    .zip(encrypted_shares)
                    .zip(services)
                    .map(|((pk, ciphertext), service)| {
                        decrypt_deterministic(&randomness, ciphertext, pk, full_id, service)
                            .map(|plaintext| (service.1, plaintext))
                    })
                    .collect::<FastCryptoResult<_>>()
            }
            (
                IBEEncryptions::Falcon512 {
                    encrypted_shares,
                    encrypted_randomness,
                },
                IBEPublicKeys::Falcon512(public_keys),
            ) => {
                if public_keys.len() != encrypted_shares.len()
                    || encrypted_shares.len() != services.len()
                {
                    return Err(InvalidInput);
                }

                // Recover the global seed `r` used to derive every share's lattice randomness.
                let randomness = xor(
                    encrypted_randomness,
                    &derive_key(
                        KeyPurpose::EncryptedRandomness,
                        base_key,
                        &self.ciphertexts(),
                        threshold,
                        &services.iter().map(|(id, _)| *id).collect_vec(),
                    ),
                );

                public_keys
                    .iter()
                    .zip(encrypted_shares)
                    .zip(services)
                    .map(|((pk, ciphertext), (_, idx))| {
                        let (k, r, e1, e2) =
                            derive_falcon_share_randomness(&randomness, *idx, pk, full_id);

                        // The FO-style mask is `H(k_polynomial)`. Recover the share via
                        // `share = w XOR H(k)`.
                        let k_bytes: Vec<u8> = k
                            .coefficients
                            .iter()
                            .flat_map(|f| f.value().to_le_bytes())
                            .collect();
                        let mut hash = Sha3_256::new();
                        hash.update(&k_bytes);
                        let hash_k: [u8; KEY_SIZE] = hash.finalize().digest;
                        let share = xor(&hash_k, &ciphertext.w);

                        // Recompute the ciphertext deterministically and verify it matches.
                        // This catches any tampering with `(u, v)` — `w` is checked transitively
                        // via the polynomial-consistency check in the caller.
                        let recomputed = fastcrypto_lattice::ibe::FalconIBE::encrypt_deterministic(
                            (k, r, e1, e2),
                            pk,
                            &fastcrypto_lattice::ibe::Plaintext::<32>(share),
                            full_id,
                        );
                        if bcs::to_bytes(&recomputed).expect("serializable")
                            != bcs::to_bytes(ciphertext).expect("serializable")
                        {
                            return Err(GeneralError(
                                "Falcon ciphertext verification failed".to_string(),
                            ));
                        }
                        Ok((*idx, share))
                    })
                    .collect::<FastCryptoResult<_>>()
            }
            _ => Err(InvalidInput),
        }
    }

    /// Returns a binary representation of all encrypted shares.
    fn ciphertexts(&self) -> Vec<Vec<u8>> {
        match self {
            IBEEncryptions::BonehFranklinBLS12381 {
                encrypted_shares, ..
            } => encrypted_shares.iter().map(|c| c.to_vec()).collect_vec(),
            IBEEncryptions::Falcon512 {
                encrypted_shares, ..
            } => encrypted_shares
                .iter()
                .map(|c| bcs::to_bytes(c).unwrap().to_vec())
                .collect_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dem::{Aes256Gcm, Hmac256Ctr};
    use crate::ibe::{hash_to_g1, public_key_from_master_key, PublicKey};
    use fastcrypto::groups::Scalar as ScalarTrait;
    use fastcrypto::{
        encoding::{Base64, Encoding},
        groups::bls12381::Scalar,
        serde_helpers::ToFromByteArray,
    };
    use std::str::FromStr;
    use sui_sdk_types::Address as NewObjectID;
    use sui_types::base_types::ObjectID;
    #[test]
    fn test_hash_with_prefix_regression() {
        let hash = hash_to_g1(&create_full_id(
            &ObjectID::from_bytes([0u8; 32]).unwrap(),
            &[1, 2, 3, 4],
        ));
        assert_eq!(hex::encode(hash.to_byte_array()), "a2f2624fda29c88ccacd286b560572d8c1261a5687e0c0cdbdcbef93bf0ec5c373563fac64a2cb5bb326cc6181ee65d7");
    }

    #[test]
    fn test_encryption_round_trip_aes() {
        let data = b"Hello, World!";
        let package_id = ObjectID::random();
        let id = vec![1, 2, 3, 4];

        let full_id = create_full_id(&package_id, &id);

        let mut rng = rand::thread_rng();
        let keypairs = (0..3)
            .map(|_| ibe::generate_key_pair(&mut rng))
            .collect_vec();

        let services = keypairs.iter().map(|_| ObjectID::random()).collect_vec();
        let services_ids = services
            .into_iter()
            .map(|id| NewObjectID::new(id.into_bytes()))
            .collect_vec();
        let threshold = 2;
        let public_keys =
            IBEPublicKeys::BonehFranklinBLS12381(keypairs.iter().map(|(_, pk)| *pk).collect_vec());

        let encrypted = seal_encrypt(
            NewObjectID::new(package_id.into_bytes()),
            id,
            services_ids.clone(),
            &public_keys,
            threshold,
            EncryptionInput::Aes256Gcm {
                data: data.to_vec(),
                aad: Some(b"something".to_vec()),
            },
        )
        .unwrap()
        .0;

        let user_secret_keys = IBEUserSecretKeys::BonehFranklinBLS12381(
            services_ids
                .into_iter()
                .zip(keypairs)
                .map(|(s, kp)| (s, ibe::extract(&kp.0, &full_id)))
                .collect(),
        );
        let decrypted = seal_decrypt(&encrypted, &user_secret_keys, Some(&public_keys)).unwrap();

        assert_eq!(data, decrypted.as_slice());

        // Check that decryption fails with different aad
        let mut modified_encrypted = encrypted.clone();
        match modified_encrypted.ciphertext {
            Ciphertext::Aes256Gcm { ref mut aad, .. } => {
                match aad {
                    None => panic!(),
                    Some(aad) => aad.push(0),
                }
                assert!(
                    seal_decrypt(&modified_encrypted, &user_secret_keys, Some(&public_keys))
                        .is_err()
                );
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_encryption_round_trip_hmac() {
        let data = b"Hello, World!";
        let package_id = ObjectID::random();
        let id = vec![1, 2, 3, 4];

        let full_id = create_full_id(&package_id, &id);

        let mut rng = rand::thread_rng();
        let keypairs = (0..3)
            .map(|_| ibe::generate_key_pair(&mut rng))
            .collect_vec();

        let services = keypairs.iter().map(|_| ObjectID::random()).collect_vec();
        let services_ids = services
            .into_iter()
            .map(|id| NewObjectID::new(id.into_bytes()))
            .collect_vec();

        let threshold = 2;
        let public_keys =
            IBEPublicKeys::BonehFranklinBLS12381(keypairs.iter().map(|(_, pk)| *pk).collect_vec());

        let encrypted = seal_encrypt(
            NewObjectID::new(package_id.into_bytes()),
            id,
            services_ids.clone(),
            &public_keys,
            threshold,
            EncryptionInput::Hmac256Ctr {
                data: data.to_vec(),
                aad: Some(b"something".to_vec()),
            },
        )
        .unwrap()
        .0;

        let user_secret_keys = IBEUserSecretKeys::BonehFranklinBLS12381(
            services_ids
                .into_iter()
                .zip(keypairs)
                .map(|(s, kp)| (s, ibe::extract(&kp.0, &full_id)))
                .collect(),
        );
        let decrypted = seal_decrypt(&encrypted, &user_secret_keys, Some(&public_keys)).unwrap();

        assert_eq!(data, decrypted.as_slice());

        // Check that decryption fails with different aad
        let mut modified_encrypted = encrypted.clone();
        match modified_encrypted.ciphertext {
            Ciphertext::Hmac256Ctr { ref mut aad, .. } => {
                match aad {
                    None => panic!(),
                    Some(aad) => aad.push(0),
                }
                assert!(
                    seal_decrypt(&modified_encrypted, &user_secret_keys, Some(&public_keys))
                        .is_err()
                );
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_plain_round_trip() {
        let package_id = ObjectID::random();
        let id = vec![1, 2, 3, 4];
        let full_id = create_full_id(&package_id, &id);

        let mut rng = rand::thread_rng();
        let keypairs = (0..3)
            .map(|_| ibe::generate_key_pair(&mut rng))
            .collect_vec();

        let services = keypairs.iter().map(|_| ObjectID::random()).collect_vec();
        let services_ids = services
            .into_iter()
            .map(|id| NewObjectID::new(id.into_bytes()))
            .collect_vec();
        let threshold = 2;
        let public_keys =
            IBEPublicKeys::BonehFranklinBLS12381(keypairs.iter().map(|(_, pk)| *pk).collect_vec());

        let (encrypted, key) = seal_encrypt(
            NewObjectID::new(package_id.into_bytes()),
            id,
            services_ids.clone(),
            &public_keys,
            threshold,
            EncryptionInput::Plain,
        )
        .unwrap();

        let user_secret_keys = services_ids
            .into_iter()
            .zip(keypairs)
            .map(|(s, kp)| (s, ibe::extract(&kp.0, &full_id)))
            .collect();

        assert_eq!(
            key.to_vec(),
            seal_decrypt(
                &encrypted,
                &IBEUserSecretKeys::BonehFranklinBLS12381(user_secret_keys),
                Some(&public_keys),
            )
            .unwrap()
        );
    }

    #[test]
    fn test_plain_round_trip_pq() {
        let package_id = ObjectID::random();
        let id = vec![1, 2, 3, 4];
        let full_id = create_full_id(&package_id, &id);

        let keypairs = (0..3)
            .map(|_| fastcrypto_lattice::ibe::FalconIBE::keygen(&mut thread_rng()))
            .collect_vec();

        let services = keypairs.iter().map(|_| ObjectID::random()).collect_vec();
        let services_ids = services
            .into_iter()
            .map(|id| NewObjectID::new(id.into_bytes()))
            .collect_vec();

        let threshold = 1;
        let public_keys =
            IBEPublicKeys::Falcon512(keypairs.iter().map(|(pk, _)| pk.clone()).collect_vec());

        let (encrypted, _key) = seal_encrypt(
            NewObjectID::new(package_id.into_bytes()),
            id,
            services_ids.clone(),
            &public_keys,
            threshold,
            EncryptionInput::Aes256Gcm {
                data: b"Hello, World!".to_vec(),
                aad: None,
            },
        )
        .unwrap();

        let user_secret_keys = services_ids
            .into_iter()
            .zip(keypairs)
            .map(|(s, kp)| {
                (
                    s,
                    fastcrypto_lattice::ibe::FalconIBE::extract(&kp.1, &full_id),
                )
            })
            .collect();

        assert_eq!(
            b"Hello, World!".to_vec(),
            seal_decrypt(
                &encrypted,
                &IBEUserSecretKeys::Falcon512(user_secret_keys),
                None,
            )
            .unwrap()
        );
    }

    #[test]
    fn test_pq_round_trip_with_verification() {
        let data = b"Hello, World!";
        let package_id = ObjectID::random();
        let id = vec![1, 2, 3, 4];
        let full_id = create_full_id(&package_id, &id);

        let keypairs = (0..3)
            .map(|_| fastcrypto_lattice::ibe::FalconIBE::keygen(&mut thread_rng()))
            .collect_vec();
        let services = keypairs.iter().map(|_| ObjectID::random()).collect_vec();
        let services_ids = services
            .into_iter()
            .map(|id| NewObjectID::new(id.into_bytes()))
            .collect_vec();
        let threshold = 2;
        let public_keys =
            IBEPublicKeys::Falcon512(keypairs.iter().map(|(pk, _)| pk.clone()).collect_vec());

        let encrypted = seal_encrypt(
            NewObjectID::new(package_id.into_bytes()),
            id,
            services_ids.clone(),
            &public_keys,
            threshold,
            EncryptionInput::Hmac256Ctr {
                data: data.to_vec(),
                aad: Some(b"something".to_vec()),
            },
        )
        .unwrap()
        .0;

        let user_secret_keys = IBEUserSecretKeys::Falcon512(
            services_ids
                .iter()
                .zip(&keypairs)
                .map(|(s, kp)| {
                    (
                        *s,
                        fastcrypto_lattice::ibe::FalconIBE::extract(&kp.1, &full_id),
                    )
                })
                .collect(),
        );

        // Decryption with verification should succeed.
        let decrypted = seal_decrypt(&encrypted, &user_secret_keys, Some(&public_keys)).unwrap();
        assert_eq!(data, decrypted.as_slice());

        // Tampering with one encrypted_share's `w` should be caught by polynomial-consistency.
        let mut tampered = encrypted.clone();
        match tampered.encrypted_shares {
            IBEEncryptions::Falcon512 {
                ref mut encrypted_shares,
                ..
            } => {
                encrypted_shares[0].w[0] ^= 1;
            }
            _ => panic!(),
        }
        assert!(seal_decrypt(&tampered, &user_secret_keys, Some(&public_keys)).is_err());
    }

    #[test]
    fn typescript_test_vector() {
        let package_id = [0u8; 32];
        let inner_id = [1, 2, 3, 4];

        let master_keys = [
            "GpR7SBGd3si0yeCtH/Zf5SbMT8b7wwTi532/NPGNCZI=",
            "bbcjgCVjr8bl3To5S7cQdYEA/o1Tnr4jTk+uZ1ifs8A=",
            "QHBhV16RiH4JfZBofMLa4yHS4qX6Nv8Je0MlB4W2BV0=",
        ]
        .iter()
        .map(|key| {
            Scalar::from_byte_array(&Base64::decode(key).unwrap().try_into().unwrap()).unwrap()
        })
        .collect::<Vec<_>>();
        let public_keys = master_keys
            .iter()
            .map(public_key_from_master_key)
            .collect_vec();

        let encryption = Base64::decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAECAwQDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMeAgCEy0p0JVyGZjTiAwvuhfbZgRbVf6B/7mt4YBW+QVwzyxJvwg7EWKC3fsVYdwiazbEZrmUt+DVDuTiiIvecSoBHN0eOW5WN77xC9ZX5IDVDqyLgP0/CzLPZav3kQES7HlkDUTPTRQGs51AtW3VBP7XW8eVDynrkuNBIAlmK8VpacwqhfgGc9jEeEyI8Radr3vFWawYpBc9NHdRgvD9GRmqhg0aGM4iKmAvnny2XR2i+O59QCk8K77YYsMPCSybazYjQGnUB2DGYvu/mXWg1dle5PPqH004F0vjlyHbNU+IQ+j4AJ2JiOXauUC7qc6NHcDrPkrdwyo4vMO7sxDK54lb719lK5r0M86MwXQEEAQIDBA==").unwrap();
        let encryption: EncryptedObject = bcs::from_bytes(&encryption).unwrap();

        let object_ids = [
            "0x0000000000000000000000000000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000000000000000000000000000002",
            "0x0000000000000000000000000000000000000000000000000000000000000003",
        ]
        .iter()
        .map(|id| NewObjectID::from_str(id).unwrap())
        .collect::<Vec<_>>();

        let full_id = create_full_id(&package_id, &inner_id);
        let user_secret_keys = object_ids
            .into_iter()
            .zip(master_keys)
            .map(|(s, k)| (s, ibe::extract(&k, &full_id)))
            .collect();

        let decrypted = seal_decrypt(
            &encryption,
            &IBEUserSecretKeys::BonehFranklinBLS12381(user_secret_keys),
            Some(&IBEPublicKeys::BonehFranklinBLS12381(public_keys)),
        )
        .unwrap();

        assert_eq!(decrypted, b"My super secret message");
    }
    #[test]
    fn test_share_consistency() {
        let data = b"Hello, World!";
        let package_id = ObjectID::random();
        let id = vec![1, 2, 3, 4];

        let full_id = create_full_id(&package_id, &id);

        let mut rng = rand::thread_rng();
        let keypairs = (0..3)
            .map(|_| ibe::generate_key_pair(&mut rng))
            .collect_vec();

        let services = keypairs.iter().map(|_| ObjectID::random()).collect_vec();
        let services_ids = services
            .clone()
            .into_iter()
            .map(|id| NewObjectID::new(id.into_bytes()))
            .collect_vec();
        let threshold = 2;
        let pks = keypairs.iter().map(|(_, pk)| *pk).collect_vec();
        let public_keys = IBEPublicKeys::BonehFranklinBLS12381(pks.clone());

        let encrypted = seal_encrypt_and_modify_first_share(
            package_id,
            id.clone(),
            services.clone(),
            &pks,
            threshold,
            EncryptionInput::Hmac256Ctr {
                data: data.to_vec(),
                aad: Some(b"something".to_vec()),
            },
        )
        .unwrap()
        .0;

        let usks: [_; 3] = services_ids
            .iter()
            .zip(&keypairs)
            .map(|(s, kp)| (*s, ibe::extract(&kp.0, &full_id)))
            .collect_vec()
            .try_into()
            .unwrap();

        // Decryption fails with all shares
        assert!(seal_decrypt(
            &encrypted,
            &IBEUserSecretKeys::BonehFranklinBLS12381(HashMap::from(usks)),
            Some(&public_keys),
        )
        .is_err());

        // Consider only the last two shares
        let usks = IBEUserSecretKeys::BonehFranklinBLS12381(HashMap::from([usks[1], usks[2]]));

        // Decryption with the last two, valid, shares succeeds.
        assert_eq!(seal_decrypt(&encrypted, &usks, None).unwrap(), data);

        // But not if we also check the share consistency
        assert!(seal_decrypt(&encrypted, &usks, Some(&public_keys))
            .is_err_and(|e| e == GeneralError("Inconsistent shares".to_string())));
    }

    fn seal_encrypt_and_modify_first_share(
        package_id: ObjectID,
        id: Vec<u8>,
        key_servers: Vec<ObjectID>,
        pks: &[PublicKey],
        threshold: u8,
        encryption_input: EncryptionInput,
    ) -> FastCryptoResult<(EncryptedObject, [u8; KEY_SIZE])> {
        let number_of_shares = key_servers.len() as u8;

        let mut rng = thread_rng();
        let full_id = create_full_id(&package_id, &id);

        // Generate a random base key
        let base_key = generate_random_bytes(&mut rng);

        // Secret share the derived key
        let SecretSharing {
            indices, shares, ..
        } = split(&mut rng, base_key, threshold, number_of_shares)?;

        let services = key_servers.into_iter().zip(indices).collect::<Vec<_>>();
        let services_ids = services
            .clone()
            .into_iter()
            .map(|(id, index)| (NewObjectID::new(id.into_bytes()), index))
            .collect_vec();
        if pks.len() != number_of_shares as usize {
            return Err(InvalidInput);
        }
        let randomness = ibe::Randomness::rand(&mut rng);

        // Encrypt the shares using the IBE keys.
        // Use the share index as the `index` parameter for the IBE decryption, allowing to encrypt shares for the same identity to the same public key.
        let (nonce, mut ciphertexts) =
            encrypt_batched_deterministic(&randomness, &shares, pks, &full_id, &services_ids)?;

        // Modify the first share
        ciphertexts[0][0] = ciphertexts[0][0].wrapping_add(1);

        let services = services.iter().map(|(id, _)| *id).collect_vec();
        let service_ids = services
            .into_iter()
            .map(|id| NewObjectID::new(id.into_bytes()))
            .collect_vec();
        let encrypted_randomness = ibe::encrypt_randomness(
            &randomness,
            &derive_key(
                KeyPurpose::EncryptedRandomness,
                &base_key,
                &ciphertexts,
                threshold,
                &service_ids,
            ),
        );
        let encrypted_shares = IBEEncryptions::BonehFranklinBLS12381 {
            nonce,
            encrypted_shares: ciphertexts,
            encrypted_randomness,
        };

        // Derive the key used by the DEM
        let dem_key = derive_key(
            KeyPurpose::DEM,
            &base_key,
            &encrypted_shares.ciphertexts(),
            threshold,
            &service_ids,
        );
        let ciphertext = match encryption_input {
            EncryptionInput::Aes256Gcm { data, aad } => Ciphertext::Aes256Gcm {
                blob: Aes256Gcm::encrypt(&data, aad.as_ref().unwrap_or(&vec![]), &dem_key),
                aad,
            },
            EncryptionInput::Hmac256Ctr { data, aad } => {
                let (blob, mac) =
                    Hmac256Ctr::encrypt(&data, aad.as_ref().unwrap_or(&vec![]), &dem_key);
                Ciphertext::Hmac256Ctr { blob, mac, aad }
            }
            EncryptionInput::Plain => Ciphertext::Plain,
        };

        Ok((
            EncryptedObject {
                version: 0,
                package_id: NewObjectID::new(package_id.into_bytes()),
                id,
                services: services_ids,
                threshold,
                encrypted_shares,
                ciphertext,
            },
            dem_key,
        ))
    }

    /// Run with: cargo test --release -p crypto --lib bench_ibe -- --ignored --nocapture
    #[test]
    #[ignore]
    fn bench_ibe() {
        use std::time::Instant;

        fn fmt(d: std::time::Duration) -> String {
            if d.as_secs_f64() >= 1.0 {
                format!("{:>8.2} s ", d.as_secs_f64())
            } else if d.as_millis() >= 1 {
                format!("{:>8.2} ms", d.as_secs_f64() * 1e3)
            } else {
                format!("{:>8.2} us", d.as_secs_f64() * 1e6)
            }
        }

        fn bench<R>(label: &str, iters: u32, f: impl Fn() -> R) -> std::time::Duration {
            // Warm-up.
            let _ = f();
            let start = Instant::now();
            for _ in 0..iters {
                let _ = f();
            }
            let elapsed = start.elapsed() / iters;
            println!("    {label:<32}{}  (avg of {iters})", fmt(elapsed));
            elapsed
        }

        fn size(label: &str, bytes: usize) {
            println!("    {label:<32}{bytes:>8} B");
        }

        let data = b"Hello, World!".to_vec();
        let aad = Some(b"something".to_vec());
        let configs = [(3u8, 2u8), (5, 3), (7, 4), (10, 7)];

        println!();
        println!("=== Boneh-Franklin BLS12-381 ===");
        for (n, t) in configs {
            println!("  n={n}, threshold={t}");
            let package_id = ObjectID::random();
            let new_package_id = NewObjectID::new(package_id.into_bytes());
            let id = vec![1, 2, 3, 4];
            let full_id = create_full_id(&package_id, &id);
            let mut rng = rand::thread_rng();
            let keypairs = (0..n)
                .map(|_| ibe::generate_key_pair(&mut rng))
                .collect_vec();
            let services = keypairs
                .iter()
                .map(|_| NewObjectID::new(ObjectID::random().into_bytes()))
                .collect_vec();
            let public_keys = IBEPublicKeys::BonehFranklinBLS12381(
                keypairs.iter().map(|(_, pk)| *pk).collect_vec(),
            );

            let master_key = keypairs[0].0;
            bench("extract (1 user key)", 50, || {
                ibe::extract(&master_key, &full_id)
            });

            bench("seal_encrypt", 20, || {
                seal_encrypt(
                    new_package_id,
                    id.clone(),
                    services.clone(),
                    &public_keys,
                    t,
                    EncryptionInput::Hmac256Ctr {
                        data: data.clone(),
                        aad: aad.clone(),
                    },
                )
                .unwrap()
            });

            let (encrypted, _) = seal_encrypt(
                new_package_id,
                id.clone(),
                services.clone(),
                &public_keys,
                t,
                EncryptionInput::Hmac256Ctr {
                    data: data.clone(),
                    aad: aad.clone(),
                },
            )
            .unwrap();
            let usks = IBEUserSecretKeys::BonehFranklinBLS12381(
                services
                    .iter()
                    .zip(&keypairs)
                    .map(|(s, kp)| (*s, ibe::extract(&kp.0, &full_id)))
                    .collect(),
            );

            bench("seal_decrypt (no verify)", 20, || {
                seal_decrypt(&encrypted, &usks, None).unwrap()
            });
            bench("seal_decrypt (verify)", 20, || {
                seal_decrypt(&encrypted, &usks, Some(&public_keys)).unwrap()
            });

            size(
                "public key size",
                bcs::to_bytes(&keypairs[0].1).unwrap().len(),
            );
            size(
                "user secret key size",
                bcs::to_bytes(&ibe::extract(&keypairs[0].0, &full_id))
                    .unwrap()
                    .len(),
            );
            size(
                "encrypted object size",
                bcs::to_bytes(&encrypted).unwrap().len(),
            );
        }

        println!();
        println!("=== Falcon-512 ===");
        for (n, t) in configs {
            println!("  n={n}, threshold={t}");
            let package_id = ObjectID::random();
            let new_package_id = NewObjectID::new(package_id.into_bytes());
            let id = vec![1, 2, 3, 4];
            let full_id = create_full_id(&package_id, &id);

            let kg_start = Instant::now();
            let keypairs = (0..n)
                .map(|_| fastcrypto_lattice::ibe::FalconIBE::keygen(&mut thread_rng()))
                .collect_vec();
            println!(
                "    {:<32}{}  (one-shot, n={n})",
                "FalconIBE::keygen total",
                fmt(kg_start.elapsed())
            );

            let services = keypairs
                .iter()
                .map(|_| NewObjectID::new(ObjectID::random().into_bytes()))
                .collect_vec();
            let public_keys =
                IBEPublicKeys::Falcon512(keypairs.iter().map(|(pk, _)| pk.clone()).collect_vec());

            let master_key = keypairs[0].1.clone();
            bench("extract (1 user key)", 5, || {
                fastcrypto_lattice::ibe::FalconIBE::extract(&master_key, &full_id)
            });

            bench("seal_encrypt", 5, || {
                seal_encrypt(
                    new_package_id,
                    id.clone(),
                    services.clone(),
                    &public_keys,
                    t,
                    EncryptionInput::Hmac256Ctr {
                        data: data.clone(),
                        aad: aad.clone(),
                    },
                )
                .unwrap()
            });

            let (encrypted, _) = seal_encrypt(
                new_package_id,
                id.clone(),
                services.clone(),
                &public_keys,
                t,
                EncryptionInput::Hmac256Ctr {
                    data: data.clone(),
                    aad: aad.clone(),
                },
            )
            .unwrap();
            let usks = IBEUserSecretKeys::Falcon512(
                services
                    .iter()
                    .zip(&keypairs)
                    .map(|(s, kp)| {
                        (
                            *s,
                            fastcrypto_lattice::ibe::FalconIBE::extract(&kp.1, &full_id),
                        )
                    })
                    .collect(),
            );

            bench("seal_decrypt (no verify)", 5, || {
                seal_decrypt(&encrypted, &usks, None).unwrap()
            });
            bench("seal_decrypt (verify)", 5, || {
                seal_decrypt(&encrypted, &usks, Some(&public_keys)).unwrap()
            });

            size(
                "public key size",
                bcs::to_bytes(&keypairs[0].0).unwrap().len(),
            );
            size(
                "user secret key size",
                bcs::to_bytes(&fastcrypto_lattice::ibe::FalconIBE::extract(
                    &keypairs[0].1,
                    &full_id,
                ))
                .unwrap()
                .len(),
            );
            size(
                "encrypted object size",
                bcs::to_bytes(&encrypted).unwrap().len(),
            );
        }
    }
}
