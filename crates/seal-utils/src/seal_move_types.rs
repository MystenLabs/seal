// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Move struct definitions matching the onchain Seal protocol types.

use anyhow::{anyhow, Result};
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::groups::bls12381::G2Element;
use fastcrypto_tbls::ecies_v1::PublicKey;
use serde::Deserialize;
use sui_sdk_types::Address;
use sui_types::collection_types::VecSet;

#[derive(Deserialize, Debug)]
pub struct VecMap<K, V>(pub sui_types::collection_types::VecMap<K, V>);

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct MemberInfo {
    pub enc_pk: Vec<u8>,
    pub signing_pk: Vec<u8>,
    pub url: String,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub enum CommitteeState {
    Init {
        members_info: VecMap<Address, MemberInfo>,
    },
    PostDKG {
        members_info: VecMap<Address, MemberInfo>,
        partial_pks: Vec<Vec<u8>>,
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
    /// Get party ID for a given member address.
    pub fn get_party_id(&self, member_addr: &Address) -> Result<u16> {
        self.members
            .iter()
            .position(|addr| addr == member_addr)
            .map(|idx| idx as u16)
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

    /// Extract members' party ID, address, enc_pk and signing_pk from Init state.
    pub fn get_members_info(&self) -> Result<Vec<ParsedMemberInfo>> {
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

        let mut members = Vec::new();

        // Party ID is the index in self.members.
        for (party_id, member_addr) in self.members.iter().enumerate() {
            // Find member info entry for the address.
            let entry = members_info
                .0
                .contents
                .iter()
                .find(|e| &e.key == member_addr)
                .ok_or_else(|| {
                    anyhow!(
                        "Member {} not registered in committee {}. Do not init DKG before all members register.",
                        member_addr,
                        self.id
                    )
                })?;

            // Parse enc_pk.
            let enc_pk_bytes = parse_move_byte_literal(&entry.value.enc_pk)?;
            let enc_pk: PublicKey<G2Element> = bcs::from_bytes(&enc_pk_bytes).map_err(|e| {
                anyhow!(
                    "Failed to deserialize ECIES PK for party {}: {}",
                    party_id,
                    e
                )
            })?;

            // Parse signing_pk.
            let signing_pk_bytes = parse_move_byte_literal(&entry.value.signing_pk)?;
            let signing_pk: G2Element = bcs::from_bytes(&signing_pk_bytes).map_err(|e| {
                anyhow!(
                    "Failed to deserialize signing PK for party {}: {}",
                    party_id,
                    e
                )
            })?;

            members.push(ParsedMemberInfo {
                party_id: party_id as u16,
                address: *member_addr,
                enc_pk,
                signing_pk,
            });
        }
        Ok(members)
    }
}

/// Helper struct storing member info with deserialized public keys.
pub struct ParsedMemberInfo {
    pub party_id: u16,
    pub address: Address,
    pub enc_pk: PublicKey<G2Element>,
    pub signing_pk: G2Element,
}

/// Helper function to parse Move byte literal (x0x...) to decoded bytes.
fn parse_move_byte_literal(bytes: &[u8]) -> Result<Vec<u8>> {
    let str = String::from_utf8(bytes.to_vec())
        .map_err(|e| anyhow!("Failed to convert bytes to UTF-8 string: {}", e))?;
    let hex_str = str.strip_prefix('x').unwrap_or(&str);
    Ok(Hex::decode(hex_str)?)
}
