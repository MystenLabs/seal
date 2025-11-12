// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Type definitions for DKG CLI.

use anyhow::Result;
use fastcrypto::bls12381::min_sig::{BLS12381PrivateKey, BLS12381PublicKey, BLS12381Signature};
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::groups::bls12381::{G2Element, Scalar as G2Scalar};
use fastcrypto::traits::{Signer, VerifyingKey};
use fastcrypto_tbls::dkg_v1::{Message, Output, ProcessedMessage, UsedProcessedMessages};
use fastcrypto_tbls::ecies_v1::{PrivateKey, PublicKey};
use fastcrypto_tbls::nodes::Nodes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::{fs, path::Path};
use sui_sdk_types::Address;

// JSON hex serializers/deserializers using serde modules.
macro_rules! json_hex_serde_module {
    ($module:ident, $type:ty) => {
        mod $module {
            use super::*;

            pub fn serialize<S>(value: &$type, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let bytes = bcs::to_bytes(value).map_err(serde::ser::Error::custom)?;
                serializer.serialize_str(&Hex::encode_with_format(&bytes))
            }

            pub fn deserialize<'de, D>(deserializer: D) -> Result<$type, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let hex_str: String = Deserialize::deserialize(deserializer)?;
                let bytes = Hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
                bcs::from_bytes(&bytes).map_err(serde::de::Error::custom)
            }
        }
    };
}

json_hex_serde_module!(enc_sk_serde, PrivateKey<G2Element>);
json_hex_serde_module!(enc_pk_serde, PublicKey<G2Element>);
json_hex_serde_module!(signing_sk_serde, BLS12381PrivateKey);
json_hex_serde_module!(signing_pk_serde, BLS12381PublicKey);

/// Keys file structure for JSON serialization/deserialization.
#[derive(Serialize, Deserialize)]
pub struct KeysFile {
    #[serde(with = "enc_sk_serde")]
    pub enc_sk: PrivateKey<G2Element>,
    #[serde(with = "enc_pk_serde")]
    pub enc_pk: PublicKey<G2Element>,
    #[serde(with = "signing_sk_serde")]
    pub signing_sk: BLS12381PrivateKey,
    #[serde(with = "signing_pk_serde")]
    pub signing_pk: BLS12381PublicKey,
}

impl KeysFile {
    /// Load keys from a JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let keys_content = fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read keys file {}: {}", path.display(), e))?;
        serde_json::from_str(&keys_content)
            .map_err(|e| anyhow::anyhow!("Failed to parse keys file: {}", e))
    }
}

/// Initialized party configuration.
#[derive(Serialize, Deserialize)]
pub struct InitializedConfig {
    /// My party ID for this committee.
    pub my_party_id: u16,
    /// All nodes in the protocol.
    pub nodes: Nodes<G2Element>,
    /// This committee ID, used for random oracle.
    pub committee_id: Address,
    /// Threshold for this committee.
    pub threshold: u16,
    /// Signing public keys for all parties in this committee.
    pub signing_pks: HashMap<u16, BLS12381PublicKey>,
    /// Threshold for old committee, for key rotation.
    pub old_threshold: Option<u16>,
    /// Mapping from new party ID to old party ID, for key rotation.
    pub new_to_old_mapping: Option<HashMap<u16, u16>>,
    /// Expected partial public keys from old committee, for key rotation.
    pub expected_old_pks: Option<HashMap<u16, G2Element>>,
    /// Old partial key share for key rotation, for continuing members for key rotation.
    pub my_old_share: Option<G2Scalar>,
    /// Old partial public key for key rotation, for continuing members for key rotation.
    pub my_old_pk: Option<G2Element>,
}

/// Local state for DKG protocol, used for storing messages and output.
#[derive(Serialize, Deserialize)]
pub struct DkgState {
    /// Configuration
    pub config: InitializedConfig,
    /// Messages created by this party.
    pub my_message: Option<Message<G2Element, G2Element>>,
    /// Messages received from other parties.
    pub received_messages: HashMap<u16, Message<G2Element, G2Element>>,
    /// Processed messages.
    pub processed_messages: Vec<ProcessedMessage<G2Element, G2Element>>,
    /// Confirmation and used messages.
    pub confirmation: Option<(
        fastcrypto_tbls::dkg_v1::Confirmation<G2Element>,
        UsedProcessedMessages<G2Element, G2Element>,
    )>,
    /// Final output (if completed).
    pub output: Option<Output<G2Element, G2Element>>,
}

impl DkgState {
    /// Save state to the given directory.
    pub(crate) fn save(&self, state_dir: &Path) -> Result<()> {
        fs::create_dir_all(state_dir)?;
        let path = state_dir.join("state.json");
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    pub(crate) fn load(state_dir: &Path) -> Result<Self> {
        let path = state_dir.join("state.json");
        let json = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&json)?)
    }
}

/// Signed message struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SignedMessage {
    pub(crate) message: Message<G2Element, G2Element>,
    pub(crate) signature: BLS12381Signature,
}

impl std::str::FromStr for SignedMessage {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        use fastcrypto::encoding::{Base64, Encoding};
        let bytes = Base64::decode(s)?;
        Ok(bcs::from_bytes(&bytes)?)
    }
}

/// Create BLS signature for signed message.
pub(crate) fn sign_message(
    message: Message<G2Element, G2Element>,
    sk: &BLS12381PrivateKey,
) -> SignedMessage {
    let message_bytes = bcs::to_bytes(&message).expect("Serialization failed");
    let signature = sk.sign(&message_bytes);
    SignedMessage { message, signature }
}

/// Verify BLS signature for signed message.
pub(crate) fn verify_signature(signed_msg: &SignedMessage, pk: &BLS12381PublicKey) -> Result<()> {
    let message_bytes = bcs::to_bytes(&signed_msg.message)?;
    pk.verify(&message_bytes, &signed_msg.signature)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::bls12381::min_sig::BLS12381KeyPair;
    use fastcrypto::traits::KeyPair;
    use rand::thread_rng;

    #[test]
    fn test_keys_file_serde() {
        // Generate random keys
        let mut rng = thread_rng();
        let enc_sk = PrivateKey::<G2Element>::new(&mut rng);
        let enc_pk = PublicKey::from_private_key(&enc_sk);

        let signing_kp = BLS12381KeyPair::generate(&mut rng);
        let signing_pk = signing_kp.public().clone();
        let signing_sk = signing_kp.private();

        let keys = KeysFile {
            enc_sk,
            enc_pk,
            signing_sk,
            signing_pk,
        };

        // Round trip.
        let json = serde_json::to_string_pretty(&keys).expect("Failed to serialize KeysFile");
        let deserialized: KeysFile =
            serde_json::from_str(&json).expect("Failed to deserialize KeysFile");

        assert_eq!(
            bcs::to_bytes(&keys.enc_sk).unwrap(),
            bcs::to_bytes(&deserialized.enc_sk).unwrap()
        );
        assert_eq!(
            bcs::to_bytes(&keys.enc_pk).unwrap(),
            bcs::to_bytes(&deserialized.enc_pk).unwrap()
        );
        assert_eq!(
            bcs::to_bytes(&keys.signing_sk).unwrap(),
            bcs::to_bytes(&deserialized.signing_sk).unwrap()
        );
        assert_eq!(
            bcs::to_bytes(&keys.signing_pk).unwrap(),
            bcs::to_bytes(&deserialized.signing_pk).unwrap()
        );
    }
}
