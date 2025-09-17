// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::dem::Purpose::{Encryption, MAC};
use crate::utils::xor_unchecked;
use crate::{Ciphertext, EncryptionInput, KEY_SIZE};
use fastcrypto::error::FastCryptoError;
use fastcrypto::hmac::{hmac_sha3_256, HmacKey};
use fastcrypto::{
    aes::{
        Aes256Gcm as ExternalAes256Gcm, AesKey, AuthenticatedCipher, GenericByteArray,
        InitializationVector,
    },
    error::FastCryptoResult,
    traits::ToFromBytes,
};
use typenum::U16;

pub struct Aes256Gcm;

impl Aes256Gcm {
    pub fn encrypt(msg: &[u8], aad: &[u8], key: &[u8; KEY_SIZE]) -> Vec<u8> {
        ExternalAes256Gcm::new(AesKey::from_bytes(key).expect("Never fails for 32 byte input"))
            .encrypt_authenticated(&Self::iv(), aad, msg)
    }

    pub fn decrypt(
        ciphertext: &[u8],
        aad: &[u8],
        key: &[u8; KEY_SIZE],
    ) -> FastCryptoResult<Vec<u8>> {
        ExternalAes256Gcm::new(AesKey::from_bytes(key).expect("Never fails for 32 byte input"))
            .decrypt_authenticated(&Self::iv(), aad, ciphertext)
    }
}

impl Aes256Gcm {
    /// We use a fixed IV. This is okay because the key is never reused.
    const IV: [u8; 16] = [
        138, 55, 153, 253, 198, 46, 121, 219, 160, 128, 89, 7, 214, 156, 148, 220,
    ];

    /// Get the fixed IV.
    fn iv() -> InitializationVector<U16> {
        GenericByteArray::from_bytes(&Self::IV).expect("fixed value")
    }
}

/// Authenticated encryption using CTR mode with HMAC-SHA3-256 as a PRF.
/// 1. Chunk the message into blocks of 32 bytes, <i>m = m<sub>1</sub> || ... || m<sub>n</sub></i>.
/// 2. Let the ciphertext be defined by <i>c = c<sub>1</sub> || ... || c<sub>n</sub></i> where <i>c<sub>i</sub> = m<sub>i</sub> ⊕ <b>hmac</b>("ENC", k, i)</i>.
/// 3. Compute a MAC over the AAD and the ciphertext, <i>mac = <b>hmac</b>("MAC", k, aad, c).
/// 4. Return <i>mac || c</i>.
///
/// This is intended to be used as part of a KEM/DEM construction with random keys. Since there is no IV for this scheme, the same key must never be used to encrypt two different messages.
pub struct Hmac256Ctr;

impl Hmac256Ctr {
    pub fn encrypt(msg: &[u8], aad: &[u8], key: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
        let ciphertext = encrypt_in_ctr_mode(key, msg);
        let mac = compute_mac(key, aad, &ciphertext);
        (ciphertext, mac)
    }

    pub fn decrypt(
        ciphertext: &[u8],
        mac: &[u8; 32],
        aad: &[u8],
        key: &[u8; 32],
    ) -> FastCryptoResult<Vec<u8>> {
        let actual_mac = compute_mac(key, aad, ciphertext);
        if mac != &actual_mac {
            return Err(FastCryptoError::GeneralError("Invalid MAC".to_string()));
        }
        let msg = encrypt_in_ctr_mode(key, ciphertext);
        Ok(msg)
    }
}

/// Encrypts the message in CTR mode using hmac_sha3_256 as a PRF.
fn encrypt_in_ctr_mode(key: &[u8; KEY_SIZE], msg: &[u8]) -> Vec<u8> {
    // Derive encryption key
    msg.chunks(KEY_SIZE)
        .enumerate()
        .flat_map(|(i, ci)| xor_unchecked(ci, &hmac(Encryption, key, &to_bytes(i as u64))))
        .collect()
}

fn compute_mac(key: &[u8; KEY_SIZE], aad: &[u8], ciphertext: &[u8]) -> [u8; KEY_SIZE] {
    // The length of the aad may vary, so add the length as a prefix to ensure uniqueness of the input.
    hmac(
        MAC,
        key,
        &[&to_bytes(aad.len() as u64), aad, ciphertext].concat(),
    )
}

#[allow(clippy::upper_case_acronyms)]
enum Purpose {
    Encryption,
    MAC,
}

impl Purpose {
    fn tag(&self) -> &[u8] {
        match self {
            Encryption => b"HMAC-CTR-ENC",
            MAC => b"HMAC-CTR-MAC",
        }
    }
}

fn hmac(purpose: Purpose, key: &[u8; KEY_SIZE], data: &[u8]) -> [u8; KEY_SIZE] {
    let data = &[purpose.tag(), data].concat();
    hmac_sha3_256(
        &HmacKey::from_bytes(key).expect("Never fails for 32 byte input"),
        data,
    )
    .digest
}

/// Convenience function for converting an u64 to a byte array.
fn to_bytes(n: u64) -> Vec<u8> {
    bcs::to_bytes(&n).expect("Never fails")
}

impl EncryptionInput {
    pub(crate) fn encrypt(self, key: &[u8; KEY_SIZE]) -> Ciphertext {
        match self {
            EncryptionInput::Aes256Gcm { data, aad } => {
                let blob = Aes256Gcm::encrypt(&data, aad.as_ref().unwrap_or(&vec![]), key);
                Ciphertext::Aes256Gcm { blob, aad }
            }
            EncryptionInput::Hmac256Ctr { data, aad } => {
                let (blob, mac) = Hmac256Ctr::encrypt(&data, aad.as_ref().unwrap_or(&vec![]), key);
                Ciphertext::Hmac256Ctr { blob, aad, mac }
            }
            EncryptionInput::Plain => Ciphertext::Plain,
        }
    }
}

impl Ciphertext {
    pub(crate) fn decrypt(&self, key: &[u8; KEY_SIZE]) -> FastCryptoResult<Vec<u8>> {
        match self {
            Ciphertext::Aes256Gcm { blob, aad } => {
                Aes256Gcm::decrypt(blob, aad.as_ref().unwrap_or(&vec![]), key)
            }
            Ciphertext::Hmac256Ctr { blob, aad, mac } => {
                Hmac256Ctr::decrypt(blob, mac, aad.as_ref().unwrap_or(&vec![]), key)
            }
            Ciphertext::Plain => Ok(key.to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::dem::{Aes256Gcm, Hmac256Ctr};
    use crate::{utils::generate_random_bytes, KEY_SIZE};
    use rand::thread_rng;

    const TEST_MSG: &[u8] = b"The difference between a Miracle and a Fact is exactly the difference between a mermaid and a seal.";
    const TEST_AAD: &[u8] = b"Mark Twain";

    #[test]
    fn test_aes_gcm() {
        let mut rng = thread_rng();
        let key = generate_random_bytes(&mut rng);
        let ciphertext = Aes256Gcm::encrypt(TEST_MSG, TEST_AAD, &key);
        let decrypted = Aes256Gcm::decrypt(&ciphertext, TEST_AAD, &key).unwrap();
        assert_eq!(TEST_MSG, decrypted.as_slice());
    }

    #[test]
    fn test_aes_gcm_fail() {
        let mut rng = thread_rng();
        let key = generate_random_bytes(&mut rng);
        let msg = b"Hello, world!";
        let aad = b"something";
        let ciphertext = Aes256Gcm::encrypt(msg, aad, &key);

        assert_eq!(
            msg,
            Aes256Gcm::decrypt(&ciphertext, b"something", &key)
                .unwrap()
                .as_slice()
        );
        assert!(Aes256Gcm::decrypt(&ciphertext, b"something else", &key).is_err());
    }

    #[test]
    fn regression_test_aes_gcm() {
        let key: [u8; KEY_SIZE] =
            hex::decode("43041389faab1f789fa56722b1def4c3ec6da22675e9bd8ad7329cd931bc840a")
                .unwrap()
                .try_into()
                .unwrap();
        let ciphertext: Vec<u8> = hex::decode("a3a5c857ee27937f43ccfb42b41ca2155c9a4a77a8e54af35f78a78ff102206142d1be22dfc39a6374463255934ae640adceeffb17e56b9190d8c5f6456e9e7ff1c4eaa45114b640b407efd371f26b1f7d7e48bd86d742a01c0ad7dbe18b86df188e27cb029978b7fd243d9a63bdabd76aa478").unwrap();
        assert_eq!(
            TEST_MSG,
            Aes256Gcm::decrypt(&ciphertext, TEST_AAD, &key)
                .unwrap()
                .as_slice()
        );
        assert_eq!(Aes256Gcm::encrypt(TEST_MSG, TEST_AAD, &key), ciphertext);
    }

    #[test]
    fn test_hmac_ctr() {
        let mut rng = thread_rng();
        let key = generate_random_bytes(&mut rng);
        let (ciphertext, mac) = Hmac256Ctr::encrypt(TEST_MSG, TEST_AAD, &key);
        let decrypted = Hmac256Ctr::decrypt(&ciphertext, &mac, TEST_AAD, &key).unwrap();
        assert_eq!(TEST_MSG, decrypted.as_slice());
    }

    #[test]
    fn test_hmac_ctr_fail() {
        let mut rng = thread_rng();
        let key = generate_random_bytes(&mut rng);
        let msg = b"Hello, world!";
        let aad = b"something";
        let (ciphertext, mac) = Hmac256Ctr::encrypt(msg, aad, &key);
        assert_eq!(
            msg,
            Hmac256Ctr::decrypt(&ciphertext, &mac, b"something", &key)
                .unwrap()
                .as_slice()
        );
        assert!(Hmac256Ctr::decrypt(&ciphertext, &mac, b"something else", &key).is_err());
    }

    #[test]
    fn regression_test_hmac_ctr() {
        let key: [u8; KEY_SIZE] =
            hex::decode("5bfdfd7c814903f1311bebacfffa3c001cbeb1cbb3275baa9aafe21fadd9f396")
                .unwrap()
                .try_into()
                .unwrap();
        let ciphertext: Vec<u8> = hex::decode("feadb8c8f781036f86b6a9f436cac6f9f68ba8fc8b8444f0331a5820f78580f32034f698f7ce15f25defae1749f0131c0a8b8c5e751b96aacf507d0dbd4d7790440d196a339fcb8498ca7dd236014e353729b7aa2cf524284a8d2305d2378494eadd6f").unwrap();
        let mac: [u8; KEY_SIZE] =
            hex::decode("85d498365972c3dc7a53f94232f9cb10dcc94eff064d6835d41d7a7536b47b51")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(
            TEST_MSG,
            Hmac256Ctr::decrypt(&ciphertext, &mac, TEST_AAD, &key)
                .unwrap()
                .as_slice()
        );
        assert_eq!(
            Hmac256Ctr::encrypt(TEST_MSG, TEST_AAD, &key),
            (ciphertext, mac)
        );
    }
}
