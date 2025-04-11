// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Based on the allowlist pattern

module walrus::allowlist;

use std::string::String;
use sui::dynamic_field as df;
use walrus::utils::is_prefix;

const EInvalidCap: u64 = 0;
const ENoAccess: u64 = 1;
const EDuplicate: u64 = 2;
const MARKER: u64 = 3;

public struct Allowlist has key {
    id: UID,
    name: String,
    list: vector<address>,
}

public struct Cap has key {
    id: UID,
    allowlist_id: ID,
}

//////////////////////////////////////////
/////// Simple allowlist with an admin cap

/// Create an allowlist with an admin cap.
/// The associated key-ids are [pkg id]::[allowlist id][nonce] for any nonce (thus
/// many key-ids can be created for the same allowlist).
public fun create_allowlist(name: String, ctx: &mut TxContext): Cap {
    let allowlist = Allowlist {
        id: object::new(ctx),
        list: vector::empty(),
        name: name,
    };
    let cap = Cap {
        id: object::new(ctx),
        allowlist_id: object::id(&allowlist),
    };
    transfer::share_object(allowlist);
    cap
}

// convenience function to create a allowlist and send it back to sender (simpler ptb for cli)
entry fun create_allowlist_entry(name: String, ctx: &mut TxContext) {
    transfer::transfer(create_allowlist(name, ctx), ctx.sender());
}

public fun add(allowlist: &mut Allowlist, cap: &Cap, account: address) {
    assert!(cap.allowlist_id == object::id(allowlist), EInvalidCap);
    assert!(!allowlist.list.contains(&account), EDuplicate);
    allowlist.list.push_back(account);
}

public fun remove(allowlist: &mut Allowlist, cap: &Cap, account: address) {
    assert!(cap.allowlist_id == object::id(allowlist), EInvalidCap);

    let len = vector::length(&allowlist.list);
    let mut i = 0;
    while (i < len) {
        if (vector::borrow(&allowlist.list, i) == account) {
            let last_index = len - 1;
            // If the found element is not the last one, swap it with the last element.
            if (i != last_index) {
                // Remove the last element from the vector.
                let last_elem = vector::pop_back(&mut allowlist.list);
                // Replace the element at index i with the last element.
                *vector::borrow_mut(&mut allowlist.list, i) = last_elem;
            } else {
                // If it is the last element, simply remove it.
                vector::pop_back(&mut allowlist.list);
            };
            break
        };
        i = i + 1;
    }
}

//////////////////////////////////////////////////////////
/// Access control
/// key format: [pkg id]::[allowlist id][random nonce]
/// (Alternative key format: [pkg id]::[creator address][random nonce] - see private_data.move)

public fun namespace(allowlist: &Allowlist): vector<u8> {
    allowlist.id.to_bytes()
}

/// All allowlisted addresses can access all IDs with the prefix of the allowlist
fun approve_internal(caller: address, id: vector<u8>, allowlist: &Allowlist): bool {
    // Check if the id has the right prefix
    let namespace = namespace(allowlist);
    if (!is_prefix(namespace, id)) {
        return false
    };

    // Check if user is in the allowlist
    allowlist.list.contains(&caller)
}

entry fun seal_approve(id: vector<u8>, allowlist: &Allowlist, ctx: &TxContext) {
    assert!(approve_internal(ctx.sender(), id, allowlist), ENoAccess);
}

/// Encapsulate a blob into a Sui object and attach it to the allowlist
public fun publish(allowlist: &mut Allowlist, cap: &Cap, blob_id: String) {
    assert!(cap.allowlist_id == object::id(allowlist), EInvalidCap);
    df::add(&mut allowlist.id, blob_id, MARKER);
}

#[test_only]
public fun new_allowlist_for_testing(ctx: &mut TxContext): Allowlist {
    use std::string::utf8;

    Allowlist {
        id: object::new(ctx),
        name: utf8(b"test"),
        list: vector::empty(),
    }
}

#[test_only]
public fun new_cap_for_testing(ctx: &mut TxContext, allowlist: &Allowlist): Cap {
    Cap {
        id: object::new(ctx),
        allowlist_id: object::id(allowlist),
    }
}

#[test_only]
public fun destroy_for_testing(allowlist: Allowlist, cap: Cap) {
    let Allowlist { id, .. } = allowlist;
    object::delete(id);
    let Cap { id, .. } = cap;
    object::delete(id);
}

#[test]
public fun test_remove_middle_last_element() {
    use std::string::utf8;

    let mut ctx = tx_context::dummy();
    
    let mut allowlist = Allowlist {
        id: object::new(&mut ctx),
        name: utf8(b"test"),
        list: vector::empty(),
    };
    let cap = Cap {
        id: object::new(&mut ctx),
        allowlist_id: object::id(&allowlist),
    };
    vector::push_back(&mut allowlist.list, @0x1);
    vector::push_back(&mut allowlist.list, @0x2);
    vector::push_back(&mut allowlist.list, @0x3);
    vector::push_back(&mut allowlist.list, @0x4);
    
    // remove middle element
    remove(&mut allowlist, &cap, @0x2);

    assert!(vector::length(&allowlist.list) == 3, 0);
    assert!(vector::borrow(&allowlist.list, 0) == @0x1, 1);
    assert!(vector::borrow(&allowlist.list, 1) == @0x4, 2);
    assert!(vector::borrow(&allowlist.list, 2) == @0x3, 3);

    // remove last element
    remove(&mut allowlist, &cap, @0x3);

    assert!(vector::length(&allowlist.list) == 2, 0);
    assert!(vector::borrow(&allowlist.list, 0) == @0x1, 1);
    assert!(vector::borrow(&allowlist.list, 1) == @0x4, 2);
    
    let Allowlist { id, .. } = allowlist;
    object::delete(id);
    let Cap { id, .. } = cap;
    object::delete(id);
}