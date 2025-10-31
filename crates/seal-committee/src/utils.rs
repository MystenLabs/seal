// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Utility helper functions for working with Seal protocol types.

use crate::move_types::SealCommittee;

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
