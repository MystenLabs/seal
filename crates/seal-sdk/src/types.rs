// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crypto::{elgamal, ibe};
use fastcrypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use serde::{Deserialize, Serialize};
use sui_sdk_types::{Address as SuiAddress, UserSignature};

type IbeDerivedKey = ibe::UserSecretKey;
type IbePublicKey = ibe::PublicKey;

pub(crate) type ElGamalPublicKey = elgamal::PublicKey<IbeDerivedKey>;
pub type ElgamalEncryption = elgamal::Encryption<IbeDerivedKey>;
pub(crate) type ElgamalVerificationKey = elgamal::VerificationKey<IbePublicKey>;

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

pub type KeyId = Vec<u8>;

#[derive(Serialize, Deserialize)]
pub struct DecryptionKey {
    pub id: KeyId,
    pub encrypted_key: ElgamalEncryption,
}

#[derive(Serialize, Deserialize)]
pub struct FetchKeyResponse {
    pub decryption_keys: Vec<DecryptionKey>,
}
