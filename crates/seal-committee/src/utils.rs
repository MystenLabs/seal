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
    new_committee
        .members
        .iter()
        .enumerate()
        .filter_map(|(party_id, address)| {
            old_committee
                .get_party_id(address)
                .map(|old_party_id| (party_id as u16, old_party_id))
                .ok()
        })
        .collect()
}
