// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Permissionless registration of a key server:
// - Key server should expose an endpoint /service that returns the official object id of its key server (to prevent
//   impersonation) and a PoP(key=IBE key, m=[key_server_id | IBE public key]).
// - Key server should expose an endpoint /fetch_key that allows users to request a key from the key server.

module seal::key_server;

use std::string::String;
use sui::{bls12381::{G2, g2_from_bytes}, dynamic_field as df, group_ops::Element};

const EInvalidCap: u64 = 0;
const EInvalidKeyType: u64 = 1;
const EInvalidVersion: u64 = 2;
const KeyTypeBonehFranklinBLS12381: u8 = 0;

public struct KeyServer has key {
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

public struct Cap has key {
    id: UID,
    key_server_id: ID,
}

public fun create_v1(
    name: String,
    url: String,
    key_type: u8,
    pk: vector<u8>,
    ctx: &mut TxContext,
): Cap {
    // Currently only BLS12-381 is supported.
    assert!(key_type == KeyTypeBonehFranklinBLS12381, EInvalidKeyType);
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

    let cap = Cap {
        id: object::new(ctx),
        key_server_id: object::id(&key_server),
    };

    transfer::share_object(key_server);
    cap
}

// Helper function to register a key server and transfer the cap to the caller.
entry fun create_and_transfer_v1(
    name: String,
    url: String,
    key_type: u8,
    pk: vector<u8>,
    ctx: &mut TxContext,
) {
    let cap = create_v1(name, url, key_type, pk, ctx);
    transfer::transfer(cap, ctx.sender());
}

public fun v1(s: &KeyServer): &KeyServerV1 {
    assert!(df::exists_(&s.id, 1), EInvalidVersion);
    df::borrow(&s.id, 1)
}

public fun name(s: &KeyServer): String {
    let v1 = v1(s);
    v1.name
}

public fun url(s: &KeyServer): String {
    let v1 = v1(s);
    v1.url
}

public fun key_type(s: &mut KeyServer): u8 {
    let v1 = v1(s);
    v1.key_type
}

public fun pk(s: &KeyServer): &vector<u8> {
    let v1 = v1(s);
    &v1.pk
}

public fun id(s: &KeyServer): &UID {
    &s.id
}

public fun pk_as_bf_bls12381(s: &KeyServer): Element<G2> {
    let v1: &KeyServerV1 = v1(s);
    assert!(v1.key_type == KeyTypeBonehFranklinBLS12381, EInvalidKeyType);
    g2_from_bytes(&v1.pk)
}

public fun update(s: &mut KeyServer, cap: &Cap, url: String) {
    assert!(object::id(s) == cap.key_server_id, EInvalidCap);
    assert!(df::exists_(&s.id, 1), EInvalidVersion);
    let v1: &mut KeyServerV1 = df::borrow_mut(&mut s.id, 1);
    v1.url = url;
}

#[test_only]
public fun destroy_cap(c: Cap) {
    let Cap { id, .. } = c;
    object::delete(id);
}

#[test]
fun test_flow() {
    use sui::test_scenario::{Self, next_tx, ctx};
    use sui::bls12381::{g2_generator};
    use std::string;

    let addr1 = @0xA;
    let mut scenario = test_scenario::begin(addr1);

    let pk = g2_generator();
    let pk_bytes = *pk.bytes();
    let cap = create_v1(
        string::utf8(b"mysten"),
        string::utf8(b"https::/mysten-labs.com"),
        0,
        pk_bytes,
        ctx(&mut scenario),
    );
    next_tx(&mut scenario, addr1);

    let mut s: KeyServer = test_scenario::take_shared(&scenario);
    assert!(name(&s) == string::utf8(b"mysten"), 0);
    assert!(url(&s) == string::utf8(b"https::/mysten-labs.com"), 0);
    assert!(pk(&s) == pk.bytes(), 0);
    s.update(&cap, string::utf8(b"https::/mysten-labs2.com"));
    assert!(url(&s) == string::utf8(b"https::/mysten-labs2.com"), 0);

    test_scenario::return_shared(s);
    destroy_cap(cap);
    test_scenario::end(scenario);
}
