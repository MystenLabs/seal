// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Move struct definitions and parsers.

use anyhow::{anyhow, Result};
use fastcrypto::bls12381::min_sig::BLS12381PublicKey;
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::groups::bls12381::G2Element;
use fastcrypto_tbls::ecies_v1::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sui_sdk_types::Address;
use sui_types::collection_types::VecSet;

#[derive(Deserialize, Debug)]
pub struct VecMap<K, V>(pub sui_types::collection_types::VecMap<K, V>);

#[derive(Deserialize, Debug)]
pub struct KeyServerV2 {
    pub name: String,
    pub key_type: u8,
    pub pk: Vec<u8>,
    pub server_type: ServerType,
}

#[derive(Deserialize, Debug)]
pub struct KeyServer {
    pub id: Address,
    pub first_version: u64,
    pub last_version: u64,
}

#[derive(Deserialize, Debug)]
pub enum ServerType {
    Independent {
        url: String,
    },
    Committee {
        version: u32,
        threshold: u16,
        partial_key_servers: VecMap<Address, PartialKeyServer>,
    },
}

#[derive(Deserialize, Debug)]
pub struct PartialKeyServer {
    #[serde(deserialize_with = "deserialize_move_bytes")]
    pub partial_pk: Vec<u8>,
    pub url: String,
    pub party_id: u16,
}

#[derive(Deserialize, Serialize)]
pub struct Wrapper<T> {
    pub name: T,
}

#[derive(Deserialize)]
pub struct Field<K, V> {
    pub id: Address,
    pub name: K,
    pub value: V,
}

#[derive(Clone)]
pub struct PartialKeyServerInfo {
    pub party_id: u16,
    pub partial_pk: G2Element,
}

#[derive(Deserialize, Debug)]
pub struct MemberInfo {
    #[serde(deserialize_with = "deserialize_enc_pk")]
    pub enc_pk: PublicKey<G2Element>,
    #[serde(deserialize_with = "deserialize_signing_pk")]
    pub signing_pk: BLS12381PublicKey,
    pub url: String,
}

#[derive(Deserialize, Debug)]
pub enum CommitteeState {
    Init {
        members_info: VecMap<Address, MemberInfo>,
    },
    PostDKG {
        members_info: VecMap<Address, MemberInfo>,
        partial_pks: Vec<Vec<u8>>,
        #[serde(deserialize_with = "deserialize_move_bytes")]
        pk: Vec<u8>,
        approvals: VecSet<Address>,
    },
    Finalized,
}

#[derive(Deserialize, Debug)]
pub struct SealCommittee {
    pub id: Address,
    pub threshold: u16,
    pub members: Vec<Address>,
    pub state: CommitteeState,
    pub old_committee_id: Option<Address>,
}

impl SealCommittee {
    /// Get party ID (index in the members list) for a given member address.
    pub fn get_party_id(&self, member_addr: &Address) -> Result<u16> {
        self.members
            .iter()
            .position(|addr| addr == member_addr)
            .map(|idx| idx as u16) // safe because length is limited by u16.
            .ok_or_else(|| {
                anyhow!(
                    "Member address {} not found in committee {}",
                    member_addr,
                    self.id
                )
            })
    }

    /// Check if committee is in Init state, returns error if not.
    pub fn is_init(&self) -> Result<()> {
        if !matches!(self.state, CommitteeState::Init { .. }) {
            return Err(anyhow!(
                "Committee {} is not in Init state. Current state: {:?}",
                self.id,
                self.state
            ));
        }
        Ok(())
    }

    /// Check if committee is in Finalized state, returns error if not.
    pub fn is_finalized(&self) -> Result<()> {
        if !matches!(self.state, CommitteeState::Finalized) {
            return Err(anyhow!(
                "Committee {} is not in Finalized state. Current state: {:?}",
                self.id,
                self.state
            ));
        }
        Ok(())
    }

    /// Check if the committee contains a specific member.
    pub fn contains(&self, member_addr: &Address) -> bool {
        self.members.contains(member_addr)
    }

    /// Extract members' info and return a HashMap mapping address to ParsedMemberInfo.
    pub fn get_members_info(&self) -> Result<HashMap<Address, ParsedMemberInfo>> {
        // Extract candidate data from Init state
        let members_info = match &self.state {
            CommitteeState::Init { members_info } => members_info,
            CommitteeState::PostDKG { members_info, .. } => members_info,
            _ => {
                return Err(anyhow!(
                    "Invalid committee state {}: {:?}",
                    self.id,
                    self.state
                ));
            }
        };

        let info_map: HashMap<_, _> = members_info
            .0
            .contents
            .iter()
            .map(|entry| (&entry.key, &entry.value))
            .collect();

        // Party ID is the index in self.members.
        self.members
            .iter()
            .enumerate()
            .map(|(party_id, member_addr)| {
                let info = info_map.get(member_addr).ok_or_else(|| {
                    anyhow!(
                        "Member {} not registered in committee {}. Do not init DKG before all members register.",
                        member_addr,
                        self.id
                    )
                })?;

                Ok((
                    *member_addr,
                    ParsedMemberInfo {
                        party_id: party_id as u16,
                        address: *member_addr,
                        enc_pk: info.enc_pk.clone(),
                        signing_pk: info.signing_pk.clone(),
                    },
                ))
            })
            .collect()
    }
}

/// Helper struct storing member info with deserialized public keys.
pub struct ParsedMemberInfo {
    pub party_id: u16,
    pub address: Address,
    pub enc_pk: PublicKey<G2Element>,
    pub signing_pk: BLS12381PublicKey,
}

/// Helper function to parse Move byte literal (x"0x..." or x"...") to decoded bytes.
fn parse_move_byte_literal(bytes: &[u8]) -> Result<Vec<u8>> {
    let str = String::from_utf8(bytes.to_vec())
        .map_err(|e| anyhow!("Failed to convert bytes to UTF-8 string: {}", e))?;

    // Strip Move byte literal format: x"..." or just "..."
    let hex_str = str
        .strip_prefix("x\"")
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| str.strip_prefix('x'))
        .unwrap_or(&str);

    // Strip 0x prefix if present
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    Ok(Hex::decode(hex_str)?)
}

/// Macro to generate serde deserializers for Move byte literals.
macro_rules! move_bytes_deserializer {
    // For Vec<u8>, just return the decoded bytes
    ($deserialize_fn:ident, Vec<u8>) => {
        fn $deserialize_fn<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
            parse_move_byte_literal(&bytes).map_err(serde::de::Error::custom)
        }
    };
    // For other types, decode and then deserialize from BCS
    ($deserialize_fn:ident, $type:ty) => {
        fn $deserialize_fn<'de, D>(deserializer: D) -> Result<$type, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
            let decoded = parse_move_byte_literal(&bytes).map_err(serde::de::Error::custom)?;
            bcs::from_bytes(&decoded).map_err(serde::de::Error::custom)
        }
    };
}

move_bytes_deserializer!(deserialize_move_bytes, Vec<u8>);
move_bytes_deserializer!(deserialize_enc_pk, PublicKey<G2Element>);
move_bytes_deserializer!(deserialize_signing_pk, BLS12381PublicKey);
