// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crypto::elgamal;
use crypto::ibe;
use fastcrypto::ed25519::Ed25519PublicKey;
use fastcrypto::ed25519::Ed25519Signature;
use serde::{Deserialize, Serialize};
use sui_types::base_types::SuiAddress;
use sui_types::signature::GenericSignature;

/// The Identity-based encryption types.
pub type IbeMasterKey = ibe::MasterKey;
type IbeDerivedKey = ibe::UserSecretKey;
type IbePublicKey = ibe::PublicKey;

/// ElGamal related types.
pub type ElGamalPublicKey = elgamal::PublicKey<IbeDerivedKey>;
pub type ElgamalEncryption = elgamal::Encryption<IbeDerivedKey>;
pub type ElgamalVerificationKey = elgamal::VerificationKey<IbePublicKey>;

/// Proof-of-possession of a key-servers master key.
pub type MasterKeyPOP = ibe::ProofOfPossession;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Network {
    Devnet,
    Testnet,
    Mainnet,
    Custom {
        node_url: String,
    },
    #[cfg(test)]
    TestCluster,
}

impl Network {
    pub fn node_url(&self) -> String {
        match self {
            Network::Devnet => "https://fullnode.devnet.sui.io:443".into(),
            Network::Testnet => "https://fullnode.testnet.sui.io:443".into(),
            Network::Mainnet => "https://fullnode.mainnet.sui.io:443".into(),
            Network::Custom { node_url, .. } => node_url.clone(),
            #[cfg(test)]
            Network::TestCluster => panic!(), // Currently not used, but can be found from cluster.rpc_url() if needed
        }
    }

    pub fn from_str(str: &str) -> Self {
        match str.to_ascii_lowercase().as_str() {
            "devnet" => Network::Devnet,
            "testnet" => Network::Testnet,
            "mainnet" => Network::Mainnet,
            "custom" => Network::Custom {
                node_url: std::env::var("NODE_URL").expect("NODE_URL must be set"),
            },
            _ => panic!("Unknown network: {}", str),
        }
    }
}

// The "session" certificate, signed by the user
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Certificate {
    pub user: SuiAddress,
    pub session_vk: Ed25519PublicKey,
    pub creation_time: u64,
    pub ttl_min: u16,
    pub signature: GenericSignature,
    pub mvr_name: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct FetchKeyRequest {
    // Next fields must be signed to prevent others from sending requests on behalf of the user and
    // being able to fetch the key
    pub ptb: String, // must adhere specific structure, see ValidPtb
    // We don't want to rely on https only for restricting the response to this user, since in the
    // case of multiple services, one service can do a replay attack to get the key from other
    // services.
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
