// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Utility helper functions for working with Seal protocol types.

use crate::seal_move_types::SealCommittee;
use anyhow::Result;
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::groups::bls12381::{G2Element, Scalar as G2Scalar};
use fastcrypto_tbls::ecies_v1::{PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};

/// Build a mapping from new committee party IDs to old committee party IDs.
/// This is used for key rotation to identify which members are continuing from the old committee.
pub fn build_new_to_old_map(
    new_committee: &SealCommittee,
    old_committee: &SealCommittee,
) -> std::collections::HashMap<u16, u16> {
    let mut new_to_old_map = std::collections::HashMap::new();
    new_committee
        .members
        .iter()
        .enumerate()
        .for_each(|(party_id, address)| {
            if let Ok(old_party_id) = old_committee.get_party_id(address) {
                new_to_old_map.insert(party_id as u16, old_party_id);
            }
        });
    new_to_old_map
}

/// Keys file structure for JSON/
#[derive(Serialize, Deserialize)]
pub struct KeysFile {
    #[serde(
        serialize_with = "serialize_enc_sk",
        deserialize_with = "deserialize_enc_sk"
    )]
    pub enc_sk: PrivateKey<G2Element>,
    #[serde(
        serialize_with = "serialize_enc_pk",
        deserialize_with = "deserialize_enc_pk"
    )]
    pub enc_pk: PublicKey<G2Element>,
    #[serde(
        serialize_with = "serialize_signing_sk",
        deserialize_with = "deserialize_signing_sk"
    )]
    pub signing_sk: G2Scalar,
    #[serde(
        serialize_with = "serialize_signing_pk",
        deserialize_with = "deserialize_signing_pk"
    )]
    pub signing_pk: G2Element,
}

/// Helper function to serialize BCS to Hex with 0x prefix.
fn serialize_to_hex<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: serde::Serialize,
{
    let bytes = bcs::to_bytes(value).map_err(serde::ser::Error::custom)?;
    let hex_str = Hex::encode_with_format(&bytes);
    serializer.serialize_str(&hex_str)
}

/// Helper function to deserialize Hex into a BCS type.
fn deserialize_hex_bcs<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let hex_str: String = Deserialize::deserialize(deserializer)?;
    let decoded = Hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
    bcs::from_bytes(&decoded).map_err(serde::de::Error::custom)
}

/// Macro to generate serde serializer/deserializer pairs for hex-encoded BCS.
macro_rules! hex_bcs_serde {
    ($serialize_fn:ident, $deserialize_fn:ident, $type:ty) => {
        fn $serialize_fn<S>(value: &$type, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serialize_to_hex(value, serializer)
        }

        fn $deserialize_fn<'de, D>(deserializer: D) -> Result<$type, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserialize_hex_bcs(deserializer)
        }
    };
}

hex_bcs_serde!(serialize_enc_sk, deserialize_enc_sk, PrivateKey<G2Element>);
hex_bcs_serde!(serialize_enc_pk, deserialize_enc_pk, PublicKey<G2Element>);
hex_bcs_serde!(serialize_signing_sk, deserialize_signing_sk, G2Scalar);
hex_bcs_serde!(serialize_signing_pk, deserialize_signing_pk, G2Element);

/// Helper function to format a BCS-serializable value as hex string with 0x prefix.
pub fn format_pk_hex<T: Serialize>(pk: &T) -> Result<String> {
    Ok(Hex::encode_with_format(&bcs::to_bytes(pk)?))
}
