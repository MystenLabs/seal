// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Permissionless registration of a key server:
// - Key server should expose an endpoint /service that returns the official object id of its key server (to prevent
//   impersonation) and a PoP(key=IBE key, m=[key_server_id | IBE public key]).
// - Key server should expose an endpoint /fetch_key that allows users to request a key from the key server.

module seal::key_server;

use std::string::String;
use sui::{bls12381::{G2, g2_from_bytes}, dynamic_field as df, group_ops::Element};

const EInvalidKeyType: u64 = 1;
const EInvalidVersion: u64 = 2;

const KEY_TYPE_BONEH_FRANKLIN_BLS12381: u8 = 0;

/// KeyServer should always be guarded as it's a capability
/// on its own. It should either be an owned object, wrapped object,
/// or TTO'd object (where access to it is controlled externally).
public struct KeyServer has key, store {
    id: UID,
    first_version: u64,
    last_version: u64,
}

public struct KeyServerV1 has store {
    name: String,
    url: String,
    key_type: u8,
    pk: vector<u8>,
}

// Helper function to register a key server object and transfer it to the caller.
entry fun create_and_transfer_v1(
    name: String,
    url: String,
    key_type: u8,
    pk: vector<u8>,
    ctx: &mut TxContext,
) {
    let key_server = create_v1(name, url, key_type, pk, ctx);
    transfer::transfer(key_server, ctx.sender());
}

public fun v1(s: &KeyServer): &KeyServerV1 {
    assert!(df::exists_(&s.id, 1), EInvalidVersion);
    df::borrow(&s.id, 1)
}

public fun name(s: &KeyServer): String {
    s.v1().name
}

public fun url(s: &KeyServer): String {
    s.v1().url
}

public fun key_type(s: &KeyServer): u8 {
    s.v1().key_type
}

public fun pk(s: &KeyServer): &vector<u8> {
    &s.v1().pk
}

public fun id(s: &KeyServer): address {
    s.id.to_address()
}

public fun pk_as_bf_bls12381(s: &KeyServer): Element<G2> {
    let v1 = s.v1();
    assert!(v1.key_type == KEY_TYPE_BONEH_FRANKLIN_BLS12381, EInvalidKeyType);
    g2_from_bytes(&v1.pk)
}

public fun update(s: &mut KeyServer, url: String) {
    assert!(df::exists_(&s.id, 1), EInvalidVersion);
    let v1: &mut KeyServerV1 = df::borrow_mut(&mut s.id, 1);
    v1.url = url;
}

fun create_v1(
    name: String,
    url: String,
    key_type: u8,
    pk: vector<u8>,
    ctx: &mut TxContext,
): KeyServer {
    // Currently only BLS12-381 is supported.
    assert!(key_type == KEY_TYPE_BONEH_FRANKLIN_BLS12381, EInvalidKeyType);
    let _ = g2_from_bytes(&pk);

    let mut key_server = KeyServer {
        id: object::new(ctx),
        first_version: 1,
        last_version: 1,
    };

    let key_server_v1 = KeyServerV1 {
        name,
        url,
        key_type,
        pk,
    };
    df::add(&mut key_server.id, 1, key_server_v1);
    key_server
}

#[test_only]
public fun destroy_for_testing(v: KeyServer) {
    let KeyServer { id, .. } = v;
    id.delete();
}

#[test]
fun test_flow() {
    use sui::test_scenario::{Self, next_tx, ctx};
    use sui::bls12381::{g2_generator};
    use std::unit_test::assert_eq;

    let addr1 = @0xA;
    let mut scenario = test_scenario::begin(addr1);

    let pk = g2_generator();
    let pk_bytes = *pk.bytes();
    create_and_transfer_v1(
        b"mysten".to_string(),
        b"https::/mysten-labs.com".to_string(),
        0,
        pk_bytes,
        scenario.ctx(),
    );
    scenario.next_tx(addr1);

    let mut s: KeyServer = scenario.take_from_sender();
    assert_eq!(s.name(), b"mysten".to_string());
    assert_eq!(s.url(), b"https::/mysten-labs.com".to_string());
    assert_eq!(*s.pk(), *pk.bytes());

    s.update(b"https::/mysten-labs2.com".to_string());
    assert_eq!(s.url(), b"https::/mysten-labs2.com".to_string());

    destroy_for_testing(s);
    scenario.end();
}
