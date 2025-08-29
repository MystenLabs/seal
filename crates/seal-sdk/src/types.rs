// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crypto::{elgamal, ibe};
use fastcrypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use serde::{Deserialize, Serialize};
use sui_sdk_types::{Address as SuiAddress, UserSignature};

pub type ElGamalPublicKey = elgamal::PublicKey<ibe::UserSecretKey>;
pub type ElgamalEncryption = elgamal::Encryption<ibe::UserSecretKey>;
pub type ElgamalVerificationKey = elgamal::VerificationKey<ibe::PublicKey>;

pub type KeyId = Vec<u8>;

pub type ElGamalSecretKey = crypto::elgamal::SecretKey<fastcrypto::groups::bls12381::G1Element>;
#[derive(Serialize, Deserialize)]
pub struct DecryptionKey {
    pub id: KeyId,
    pub encrypted_key: ElgamalEncryption,
}

#[derive(Serialize, Deserialize)]
pub struct FetchKeyResponse {
    pub decryption_keys: Vec<DecryptionKey>,
}

/// The session certificate, signed by the user.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Certificate {
    pub user: SuiAddress,
    pub session_vk: Ed25519PublicKey,
    pub creation_time: u64,
    pub ttl_min: u16,
    pub signature: UserSignature,
    pub mvr_name: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct FetchKeyRequest {
    pub ptb: String,
    pub enc_key: ElGamalPublicKey,
    pub enc_verification_key: ElgamalVerificationKey,
    pub request_signature: Ed25519Signature,
    pub certificate: Certificate,
}

impl FetchKeyRequest {
    /// Convert to JSON string with GenericSignature-compatible format for the certificate
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        // Create a JSON object manually to match GenericSignature format
        let sig_base64 = self.certificate.signature.to_base64();

        let json = serde_json::json!({
            "ptb": self.ptb,
            "enc_key": self.enc_key,
            "enc_verification_key": self.enc_verification_key,
            "request_signature": self.request_signature,
            "certificate": {
                "user": self.certificate.user,
                "session_vk": self.certificate.session_vk,
                "creation_time": self.certificate.creation_time,
                "ttl_min": self.certificate.ttl_min,
                "signature": sig_base64,
                "mvr_name": self.certificate.mvr_name,
            }
        });

        serde_json::to_string(&json)
    }
}
