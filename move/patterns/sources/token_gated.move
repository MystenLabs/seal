// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Token-gated access pattern:
/// - Anyone can create a gate for a specific object type T.
/// - Anyone can encrypt to the gate's key-id.
/// - Anyone who owns an object of type T can request the associated key.
///
/// Access travels with the asset: if Alice holds an NFT that grants access
/// and transfers it to Bob, Bob gains access and Alice loses it automatically.
/// No admin update required.
///
/// Use cases that can be built on top of this: NFT-gated content (art reveals,
/// membership perks), DAO governance documents, gaming assets unlocking
/// encrypted content.
///
/// Security: assumes the token type T is only ever owned, never shared or frozen.
/// If T can be shared or frozen, anyone could pass a reference and bypass the gate.
/// For high-value content with token types you don't control, a collection-specific
/// integration with concrete types would be more appropriate.
///
/// This pattern does NOT implement versioning, please see other patterns for
/// examples of versioning.
///
module patterns::token_gated;

use std::type_name::{Self, TypeName};

const ENoAccess: u64 = 1;
const ETypeMismatch: u64 = 2;

public struct TokenGate has key {
    id: UID,
    /// The type of token required for access (defense-in-depth).
    /// Uses with_original_ids so the check survives package upgrades.
    required_type: TypeName,
}

/// Cap can also be used to add admin operations in future versions,
/// see https://docs.sui.io/concepts/sui-move-concepts/packages/upgrade#versioned-shared-objects
public struct Cap has key, store {
    id: UID,
    gate_id: ID,
}

//////////////////////////////////////////
/////// Token gate with an admin cap (frozen after creation)

/// Create a token gate for a specific token type T.
/// The associated key-ids are [pkg id][gate id][nonce] for any nonce (thus
/// many key-ids can be created for the same gate).
public fun create_token_gate<T: key>(ctx: &mut TxContext): (Cap, TokenGate) {
    let gate = TokenGate {
        id: object::new(ctx),
        required_type: type_name::with_original_ids<T>(),
    };
    let cap = Cap {
        id: object::new(ctx),
        gate_id: object::id(&gate),
    };
    (cap, gate)
}

/// Freeze the gate as an immutable object. TokenGate is never mutated after
/// creation, so freeze_object is more appropriate than share_object: it signals
/// immutability, avoids consensus overhead on reads, and prevents accidental
/// mutation via future upgrades.
public fun freeze_token_gate(gate: TokenGate) {
    transfer::freeze_object(gate);
}

// Convenience function to create a gate and freeze it in one step.
entry fun create_token_gate_entry<T: key>(ctx: &mut TxContext) {
    let (cap, gate) = create_token_gate<T>(ctx);
    freeze_token_gate(gate);
    transfer::public_transfer(cap, ctx.sender());
}

//////////////////////////////////////////////////////////
/// Access control
/// key format: [pkg id][gate id][random nonce]

/// Verify type match and key-id prefix (same structure as whitelist.move).
fun check_policy<T: key>(id: vector<u8>, _token: &T, gate: &TokenGate): bool {
    // Defense-in-depth: verify T matches the required type.
    // Uses with_original_ids so the check survives NFT package upgrades
    // (same function as key_request.move lines 43, 67).
    assert!(
        type_name::with_original_ids<T>() == gate.required_type,
        ETypeMismatch,
    );

    // Check if the id has the right prefix (gate's object ID).
    let prefix = gate.id.to_bytes();
    let mut i = 0;
    if (prefix.length() > id.length()) {
        return false
    };
    while (i < prefix.length()) {
        if (prefix[i] != id[i]) {
            return false
        };
        i = i + 1;
    };
    true
}

/// Approve access if caller owns any object of type T.
/// Ownership is enforced by the Move VM for owned objects: only the owner
/// can pass &T as a transaction argument.
entry fun seal_approve<T: key>(id: vector<u8>, _token: &T, gate: &TokenGate) {
    assert!(check_policy<T>(id, _token, gate), ENoAccess);
}

// ===== Test Helpers =====

#[test_only]
public fun destroy_for_testing(gate: TokenGate, cap: Cap) {
    let TokenGate { id, required_type: _ } = gate;
    object::delete(id);
    let Cap { id, .. } = cap;
    object::delete(id);
}

#[test_only]
public struct TestNFT has key {
    id: UID,
}

#[test_only]
public fun create_test_nft(ctx: &mut TxContext): TestNFT {
    TestNFT { id: object::new(ctx) }
}

#[test_only]
public fun destroy_test_nft(nft: TestNFT) {
    let TestNFT { id } = nft;
    object::delete(id);
}

// ===== Tests =====

#[test]
fun test_check_policy() {
    let ctx = &mut tx_context::dummy();
    let nft = create_test_nft(ctx);
    let (cap, gate) = create_token_gate<TestNFT>(ctx);

    // Fail for empty id
    assert!(!check_policy<TestNFT>(b"", &nft, &gate), 1);

    // Fail for invalid id
    assert!(!check_policy<TestNFT>(b"123", &nft, &gate), 1);

    // Work for valid id with gate prefix
    let mut obj_id = object::id(&gate).to_bytes();
    obj_id.push_back(11);
    assert!(check_policy<TestNFT>(obj_id, &nft, &gate), 1);

    destroy_test_nft(nft);
    destroy_for_testing(gate, cap);
}

#[test]
fun test_seal_approve() {
    let ctx = &mut tx_context::dummy();
    let nft = create_test_nft(ctx);
    let (cap, gate) = create_token_gate<TestNFT>(ctx);

    let mut obj_id = object::id(&gate).to_bytes();
    obj_id.push_back(11);

    // Correct type + valid prefix succeeds
    seal_approve<TestNFT>(obj_id, &nft, &gate);

    destroy_test_nft(nft);
    destroy_for_testing(gate, cap);
}

#[test]
fun test_multiple_nonces() {
    let ctx = &mut tx_context::dummy();
    let nft = create_test_nft(ctx);
    let (cap, gate) = create_token_gate<TestNFT>(ctx);

    let gate_bytes = object::id(&gate).to_bytes();

    // Different nonces for the same gate should all work
    let mut id1 = gate_bytes;
    id1.push_back(1);
    assert!(check_policy<TestNFT>(id1, &nft, &gate), 1);

    let mut id2 = gate_bytes;
    id2.push_back(255);
    assert!(check_policy<TestNFT>(id2, &nft, &gate), 1);

    let mut id3 = gate_bytes;
    id3.push_back(0);
    id3.push_back(42);
    assert!(check_policy<TestNFT>(id3, &nft, &gate), 1);

    // Exact gate ID with no nonce should also work
    assert!(check_policy<TestNFT>(gate_bytes, &nft, &gate), 1);

    destroy_test_nft(nft);
    destroy_for_testing(gate, cap);
}

#[test, expected_failure(abort_code = ETypeMismatch)]
fun test_wrong_type_rejected() {
    let ctx = &mut tx_context::dummy();
    let nft = create_test_nft(ctx);
    let (cap, gate) = create_token_gate<TestNFT>(ctx);

    let mut obj_id = object::id(&gate).to_bytes();
    obj_id.push_back(11);

    // Wrong type aborts with ETypeMismatch
    seal_approve<Cap>(obj_id, &cap, &gate);

    destroy_test_nft(nft);
    destroy_for_testing(gate, cap);
}

#[test, expected_failure(abort_code = ENoAccess)]
fun test_wrong_prefix_rejected() {
    let ctx = &mut tx_context::dummy();
    let nft = create_test_nft(ctx);
    let (cap, gate) = create_token_gate<TestNFT>(ctx);

    // Use cap's ID (valid-length but wrong prefix)
    let mut wrong_id = object::id(&cap).to_bytes();
    wrong_id.push_back(11);

    seal_approve<TestNFT>(wrong_id, &nft, &gate);

    destroy_test_nft(nft);
    destroy_for_testing(gate, cap);
}

#[test]
fun test_create_and_destroy() {
    let ctx = &mut tx_context::dummy();
    let (cap, gate) = create_token_gate<TestNFT>(ctx);
    destroy_for_testing(gate, cap);
}
