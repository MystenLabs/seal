// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Time lock encryption pattern:
/// - Anyone can encrypt to time T using key-id [pkg id][bcs::to_bytes(T)].
/// - Anyone can request the key for key-id = T after time T has passed.
///
/// Use cases that can be built on top of this: MEV resilient trading, secure voting.
///
/// Similar patterns:
/// - Time lock encryption with an Update Cap - Anyone can create a shared object UpdatableTle{ id: UID, end_time: u64 }
///   and receive UpdateCap { id: UID, updatable_tle_id: ID }. The associated key-id is [pkg id][id of UpdatableTle].
///   The cap owner can increase the end_time before the end_time has passed. Once the end_time has passed, anyone
///   can request the key.
///
/// This pattern does NOT implement versioning, please see other patterns for
/// examples of versioning.
///
module patterns::tle;

use sui::{bcs::{Self, BCS}, clock};

const ENoAccess: u64 = 77;

/////////////////////////////////////
/// Access control
/// key format: [pkg id][bcs::to_bytes(T)]

fun check_policy(id: vector<u8>, c: &clock::Clock): bool {
    let mut prepared: BCS = bcs::new(id);
    let t = prepared.peel_u64();
    let leftovers = prepared.into_remainder_bytes();

    // Check that the time has passed.
    (leftovers.length() == 0) && (c.timestamp_ms() >= t)
}

entry fun seal_approve(id: vector<u8>, c: &clock::Clock) {
    assert!(check_policy(id, c), ENoAccess);
}

#[test]
fun test_approve() {
    let ctx = &mut tx_context::dummy();
    let mut c = clock::create_for_testing(ctx); // time = 0
    let t = 1u64;
    let id = bcs::to_bytes(&t);

    // 0 < 1
    assert!(!check_policy(id, &c), 0);

    // 1 == 1
    c.increment_for_testing(1);
    assert!(check_policy(id, &c), 0);
    // 2 > 1
    c.increment_for_testing(1);
    assert!(check_policy(id, &c), 0);

    c.destroy_for_testing();
}
