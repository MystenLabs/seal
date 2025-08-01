// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Immutable registry for storing public keys
/// This package cannot be upgraded, ensuring key immutability
module immutable::registry;

use sui::dynamic_field as df;

// Error codes
const EAlreadyRegistered: u64 = 1;
const ENotFound: u64 = 2;

public struct Registry has key {
    id: UID,
}

/// One-time initialization
fun init(ctx: &mut TxContext) {
    let registry = Registry {
        id: object::new(ctx),
    };
    transfer::share_object(registry);
}

public fun register(
    registry: &mut Registry,
    key_server_id: ID,
    value: vector<u8>,
    name: vector<u8>,
) {
    assert!(!df::exists_(&registry.id, name), EAlreadyRegistered);
    let mut key = key_server_id.to_bytes();
    key.append(name);
    df::add(&mut registry.id, key, value);
}

/// Get public key from registry
public fun get(registry: &Registry, key_server_id: ID, name: vector<u8>): vector<u8> {
    let mut key = key_server_id.to_bytes();
    key.append(name);
    assert!(df::exists_(&registry.id, key), ENotFound);
    *df::borrow<vector<u8>, vector<u8>>(&registry.id, key)
}
