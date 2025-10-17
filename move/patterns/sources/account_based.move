// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Account based encryption:
/// - Anyone can encrypt to address B using key-id [pkg id]::[bcs::to_bytes(B)].
/// - Only the owner of account B can access the associated key.
///
/// Use cases that can be built on top of this: offchain secure messaging.
///
/// This pattern does NOT implement versioning, please see other patterns for
/// examples of versioning.
///
module patterns::account_based;

use sui::bcs;

const ENoAccess: u64 = 1;

/////////////////////////////////////
/// Access control
/// key format: [pkg id][bcs::to_bytes(B)] for address B

fun check_policy(id: vector<u8>, ctx: &TxContext): bool {
    let caller_bytes = bcs::to_bytes(&ctx.sender());
    id == caller_bytes
}

entry fun seal_approve(id: vector<u8>, ctx: &TxContext) {
    assert!(check_policy(id, ctx), ENoAccess);
}

#[test]
fun test_check_policy() {
    let ctx = tx_context::dummy();
    let sender = ctx.sender();
    let id = bcs::to_bytes(&sender);
    assert!(check_policy(id, &ctx), 0);

    let id = bcs::to_bytes(&0x0232);
    assert!(!check_policy(id, &ctx), 0);
}
