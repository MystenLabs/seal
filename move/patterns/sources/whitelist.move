// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Whitelist pattern:
/// - Anyone can create a whitelist which defines a unique key-id.
/// - Anyone can encrypt to that key-id.
/// - Anyone on the whitelist can request the key associated with the whitelist's key-id,
///   allowing it to decrypt all data encrypted to that key-id.
///
/// Use cases that can be built on top of this: subscription based access to encrypted files.
///
/// Similar patterns:
/// - Whitelist with temporary privacy: same whitelist as below, but also store created_at: u64.
///   After a fixed TTL anyone can access the key, regardless of being on the whitelist.
///   Temporary privacy can be useful for compliance reasons, e.g., GDPR.
///
/// This pattern implements versioning per whitelist.
///
module patterns::whitelist;

use sui::table;

const ENoAccess: u64 = 1;
const EInvalidCap: u64 = 2;
const EDuplicate: u64 = 3;
const ENotInWhitelist: u64 = 4;
const EWrongVersion: u64 = 5;

const VERSION: u64 = 1;

public struct Whitelist has key {
    id: UID,
    version: u64,
    addresses: table::Table<address, bool>,
}

public struct Cap has key, store {
    id: UID,
    wl_id: ID,
}

//////////////////////////////////////////
/////// Simple whitelist with an admin cap

/// Create a whitelist with an admin cap.
/// The associated key-ids are [pkg id][whitelist id][nonce] for any nonce (thus
/// many key-ids can be created for the same whitelist).
public fun create_whitelist(ctx: &mut TxContext): (Cap, Whitelist) {
    let wl = Whitelist {
        id: object::new(ctx),
        version: VERSION,
        addresses: table::new(ctx),
    };
    let cap = Cap {
        id: object::new(ctx),
        wl_id: object::id(&wl),
    };
    (cap, wl)
}

public fun share_whitelist(wl: Whitelist) {
    transfer::share_object(wl);
}

// Helper function for creating a whitelist and send it back to sender.
entry fun create_whitelist_entry(ctx: &mut TxContext) {
    let (cap, wl) = create_whitelist(ctx);
    share_whitelist(wl);
    transfer::public_transfer(cap, ctx.sender());
}

public fun add(wl: &mut Whitelist, cap: &Cap, account: address) {
    assert!(cap.wl_id == object::id(wl), EInvalidCap);
    assert!(!wl.addresses.contains(account), EDuplicate);
    wl.addresses.add(account, true);
}

/// Removing an address only blocks future key derivations - keys it already fetched keep
/// working, including for content encrypted later. See the note on `seal_approve`.
public fun remove(wl: &mut Whitelist, cap: &Cap, account: address) {
    assert!(cap.wl_id == object::id(wl), EInvalidCap);
    assert!(wl.addresses.contains(account), ENotInWhitelist);
    wl.addresses.remove(account);
}

// Cap can also be used to upgrade the version of Whitelist in future versions,
// see https://docs.sui.io/concepts/sui-move-concepts/packages/upgrade#versioned-shared-objects

//////////////////////////////////////////////////////////
/// Access control
/// key format: [pkg id][whitelist id][random nonce]
/// (Alternative key format: [pkg id][creator address][random nonce] - see private_data.move)

/// All whitelisted addresses can access all IDs with the prefix of the whitelist
fun check_policy(caller: address, id: vector<u8>, wl: &Whitelist): bool {
    // Check we are using the right version of the package.
    assert!(wl.version == VERSION, EWrongVersion);

    // Check if the id has the right prefix
    let prefix = wl.id.to_bytes();
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

    // Check if user is in the whitelist
    wl.addresses.contains(caller)
}

/// Note: the key for a given id is fixed, and once a user fetches it, the user may store
/// it and use it for future decryptions. This function approves any id with the
/// whitelist's prefix, so a whitelisted user can fetch keys for such ids, and removing
/// the user later does not take those keys back (see `remove`).
///
/// The developer should decide whether future encryptions can or must not be decryptable
/// with previously fetched keys, and based on that encrypt them to the same or to
/// different key ids. In this pattern the nonce can be used for creating unique key ids,
/// for example:
/// - A random nonce per encryption: each key covers a single piece of content, and future
///   ids are unguessable, so keys cannot be pre-fetched for content that does not exist
///   yet. Avoid predictable nonces such as a counter or timestamp: a user can enumerate
///   future ids and pre-fetch their keys before being removed.
/// - A revocation version: the Whitelist stores a version, `remove` bumps it, and this
///   function checks that the id carries the current value. Previously fetched keys then
///   stop working for content encrypted to the new version, at the cost of encryptors
///   reading the current version onchain before each encryption.
/// - A time bucket (e.g., the current epoch or date): keys rotate on a schedule, so a
///   removal takes effect at the next bucket without an onchain bump.
/// - An identifier of the content itself (e.g., a Walrus blob id): each key is scoped to
///   exactly that content.
///
/// The nonce is only one option. Alternatives include checking the full key id against an
/// onchain object so ids cannot be pre-fetched at all (see private_data.move), or using a
/// single fixed id for the whole policy when sharing one key is acceptable (see
/// account_based.move and tle.move).
entry fun seal_approve(id: vector<u8>, wl: &Whitelist, ctx: &TxContext) {
    assert!(check_policy(ctx.sender(), id, wl), ENoAccess);
}

#[test_only]
public fun destroy_for_testing(wl: Whitelist, cap: Cap) {
    let Whitelist { id, version: _, addresses } = wl;
    addresses.drop();
    object::delete(id);
    let Cap { id, .. } = cap;
    object::delete(id);
}

#[test]
fun test_approve() {
    let ctx = &mut tx_context::dummy();
    let (cap, mut wl) = create_whitelist(ctx);
    wl.add(&cap, @0x1);
    wl.remove(&cap, @0x1);
    wl.add(&cap, @0x2);

    // Fail for invalid id
    assert!(!check_policy(@0x2, b"123", &wl), 1);
    // Work for valid id, user 2 is in the whitelist
    let mut obj_id = object::id(&wl).to_bytes();
    obj_id.push_back(11);
    assert!(check_policy(@0x2, obj_id, &wl), 1);
    // Fail for user 1
    assert!(!check_policy(@0x1, obj_id, &wl), 1);

    destroy_for_testing(wl, cap);
}
