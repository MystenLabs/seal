// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Secret allowlist pattern:
/// - Like the whitelist pattern, but the members are a secret argument: only the key servers
///   learn who is on the list.
/// - The admin encrypts `bcs(vector[bcs(members)])` to all key servers with threshold 1 under the
///   id [pkg id]["seal-secret-v1"], and stores the ciphertext in the `Allowlist`.
/// - Requesters call `seal_secret_arguments(id, allowlist)` followed by
///   `seal_approve(id, allowlist)`. The key servers decrypt the members and pass them to
///   `seal_approve` as a `Secret<vector<address>>`.
///
/// An invalid ciphertext denies access, since an allowlist should fail closed.
///
/// This pattern does NOT implement versioning, please see other patterns for
/// examples of versioning.
module patterns::secret_allowlist;

use seal::secret::Secret;

const ENoAccess: u64 = 1;
const EInvalidCap: u64 = 2;

public struct Allowlist has key {
    id: UID,
    /// Encryption of the members to the key servers.
    encrypted_members: vector<u8>,
}

public struct Cap has key, store {
    id: UID,
    allowlist_id: ID,
}

/// Create an allowlist with an admin cap.
/// The associated key-ids are [pkg id][allowlist id][nonce] for any nonce.
public fun create_allowlist(encrypted_members: vector<u8>, ctx: &mut TxContext): Cap {
    let allowlist = Allowlist { id: object::new(ctx), encrypted_members };
    let cap = Cap { id: object::new(ctx), allowlist_id: object::id(&allowlist) };
    transfer::share_object(allowlist);
    cap
}

public fun set_members(allowlist: &mut Allowlist, cap: &Cap, encrypted_members: vector<u8>) {
    assert!(cap.allowlist_id == object::id(allowlist), EInvalidCap);
    allowlist.encrypted_members = encrypted_members;
}

/// Called in the requester's PTB right before `seal_approve`. Returns the encrypted members, and
/// that an invalid encryption should deny access.
entry fun seal_secret_arguments(id: vector<u8>, allowlist: &Allowlist): (vector<u8>, bool) {
    assert!(has_prefix(&id, &allowlist.id.to_bytes()), ENoAccess);
    (allowlist.encrypted_members, false)
}

/// `members` is filled in by the key servers.
entry fun seal_approve(
    id: vector<u8>,
    members: Secret<vector<address>>,
    allowlist: &Allowlist,
    ctx: &TxContext,
) {
    assert!(has_prefix(&id, &allowlist.id.to_bytes()), ENoAccess);
    assert!(members.get().contains(&ctx.sender()), ENoAccess);
}

fun has_prefix(id: &vector<u8>, prefix: &vector<u8>): bool {
    let n = prefix.length();
    n <= id.length() && vector::tabulate!(n, |i| id[i]) == *prefix
}

#[test_only]
fun destroy_for_testing(allowlist: Allowlist, cap: Cap) {
    let Allowlist { id, .. } = allowlist;
    id.delete();
    let Cap { id, .. } = cap;
    id.delete();
}

#[test]
fun test_seal_approve() {
    let ctx = &mut tx_context::dummy();
    let allowlist = Allowlist { id: object::new(ctx), encrypted_members: x"0102" };
    let cap = Cap { id: object::new(ctx), allowlist_id: object::id(&allowlist) };
    let mut id = allowlist.id.to_bytes();
    id.push_back(7);

    let (encrypted, open_if_invalid) = seal_secret_arguments(id, &allowlist);
    assert!(encrypted == x"0102" && !open_if_invalid);

    seal_approve(id, seal::secret::new(vector[@0xB, ctx.sender()]), &allowlist, ctx);
    destroy_for_testing(allowlist, cap);
}

#[test, expected_failure(abort_code = ENoAccess)]
fun test_seal_approve_not_member() {
    let ctx = &mut tx_context::dummy();
    let allowlist = Allowlist { id: object::new(ctx), encrypted_members: vector[] };
    let cap = Cap { id: object::new(ctx), allowlist_id: object::id(&allowlist) };
    let id = allowlist.id.to_bytes();

    seal_approve(id, seal::secret::new(vector[@0xB]), &allowlist, ctx);
    destroy_for_testing(allowlist, cap);
}
