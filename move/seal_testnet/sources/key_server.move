// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Permissionless registration of a key server:
// - Key server should expose an endpoint /service that returns the official object id of its key server (to prevent
//   impersonation) and a PoP(key=IBE key, m=[key_server_id | IBE public key]).
// - Key server should expose an endpoint /fetch_key that allows users to request a key from the key server.

module seal_testnet::key_server;

use std::string::String;
use sui::{bls12381::{G2, g2_from_bytes}, dynamic_field as df, group_ops::Element};

const KeyTypeBonehFranklinBLS12381: u8 = 0;
const EInvalidKeyType: u64 = 1;
const EInvalidVersion: u64 = 2;
const EPartialKeyServerNotFound: u64 = 3;
const EInvalidServerType: u64 = 4;

/// KeyServer should always be guarded as it's a capability
/// on its own. It should either be an owned object, wrapped object,
/// or TTO'd object (where access to it is controlled externally).
public struct KeyServer has key, store {
    id: UID,
    first_version: u64,
    last_version: u64,
}

// ===== V1 Structs =====

public struct KeyServerV1 has store {
    name: String,
    url: String,
    key_type: u8,
    pk: vector<u8>,
}

// ===== V2 Structs =====

public enum ServerType has copy, drop, store {
    Independent {
        url: String,
    },
    Committee {
        threshold: u16,
    },
}

/// PartialKeyServer is added as dynamic field to KeyServer
public struct PartialKeyServer has key, store {
    id: UID,
    /// Partial public key (BLS G2 point)
    pk: vector<u8>,
    /// Key server URL
    url: String,
    party_id: u16,
    owner: address,
}

/// KeyServerV2: supports both single and committee-based key servers
public struct KeyServerV2 has key, store {
    id: UID, // TODO: consider if this can be removed.
    name: String, // For both types
    key_type: u8, // For both types
    pk: vector<u8>, // For both types
    server_type: ServerType,
}

// ===== V2 Functions =====

/// Create a committee-owned KeyServer. todo: check this, can only be called by committee.
public fun create_committee_v2(
    name: String,
    threshold: u16,
    pk: vector<u8>,
    ctx: &mut TxContext,
): KeyServer {
    let mut key_server = KeyServer {
        id: object::new(ctx),
        first_version: 2,
        last_version: 2,
    };

    let key_server_v2 = KeyServerV2 {
        id: object::new(ctx),
        name,
        key_type: KeyTypeBonehFranklinBLS12381,
        pk,
        server_type: ServerType::Committee { threshold },
    };

    df::add(&mut key_server.id, 2, key_server_v2);
    key_server
}

/// Upgrade the current key server to v2, still a single owner object.
public fun upgrade_to_v2(ks: &mut KeyServer, ctx: &mut TxContext) {
    let key_server_v2 = KeyServerV2 {
        id: object::new(ctx),
        name: ks.v1().name,
        key_type: ks.v1().key_type,
        pk: ks.v1().pk,
        server_type: ServerType::Independent { url: ks.v1().url },
    };

    df::add(&mut ks.id, 2, key_server_v2);
    ks.last_version = 2;
}

/// Create and add partial key server objects for a committee-owned key server.
public fun add_all_partial_key_servers(
    key_server: &mut KeyServer,
    members: &vector<address>,
    partial_pks: &vector<vector<u8>>,
    ctx: &mut TxContext,
) {
    assert_committee_server_v2(key_server);
    let mut i = 0;
    while (i < members.length()) {
        let partial_pk = partial_pks[i];
        let partial_key_server = PartialKeyServer {
            id: object::new(ctx),
            pk: partial_pk,
            url: b"".to_string(), // intialize empty url, member can update this
            party_id: (i as u16),
            owner: members[i],
        };

        let v2: &mut KeyServerV2 = key_server.v2_mut();
        df::add(&mut v2.id, members[i], partial_key_server);
        i = i + 1;
    };
}

/// Remove a single partial key server (for members leaving during rotation)
public fun remove_partial_key_server(key_server: &mut KeyServer, member: address) {
    assert_committee_server_v2(key_server);
    let v2: &mut KeyServerV2 = key_server.v2_mut();

    if (df::exists_(&v2.id, member)) {
        let PartialKeyServer { id, pk: _, url: _, party_id: _, owner: _ } = df::remove<
            address,
            PartialKeyServer,
        >(&mut v2.id, member);
        object::delete(id);
    };
}

/// Add a single partial key server (for new members during rotation)
public fun add_partial_key_server(
    key_server: &mut KeyServer,
    member: address,
    partial_pk: vector<u8>,
    party_id: u16,
    url: String,
    ctx: &mut TxContext,
) {
    assert_committee_server_v2(key_server);
    let partial_key_server = PartialKeyServer {
        id: object::new(ctx),
        pk: partial_pk,
        url,
        party_id,
        owner: member,
    };

    let v2: &mut KeyServerV2 = key_server.v2_mut();
    df::add(&mut v2.id, member, partial_key_server);
}

/// Update the URL of a partial key server, can only update the caller created server.
public fun update_partial_ks_url(key_server: &mut KeyServer, url: String, ctx: &mut TxContext) {
    assert_committee_server_v2(key_server);
    let v2: &mut KeyServerV2 = key_server.v2_mut();
    assert!(df::exists_(&v2.id, ctx.sender()), EPartialKeyServerNotFound);
    let partial_key_server: &mut PartialKeyServer = df::borrow_mut(&mut v2.id, ctx.sender());
    partial_key_server.url = url;
}

/// Get the v2 struct of a key server.
public fun v2(s: &KeyServer): &KeyServerV2 {
    assert!(df::exists_(&s.id, 2), EInvalidVersion);
    df::borrow(&s.id, 2)
}

/// Get the mutable v2 struct of a key server.
public fun v2_mut(s: &mut KeyServer): &mut KeyServerV2 {
    assert!(df::exists_(&s.id, 2), EInvalidVersion);
    df::borrow_mut(&mut s.id, 2)
}

/// Check if KeyServer has v2
public fun has_v2(s: &KeyServer): bool {
    df::exists_(&s.id, 2)
}

/// Check if KeyServer is v2 and is a committee server.
public fun assert_committee_server_v2(s: &KeyServer) {
    assert!(has_v2(s), EInvalidVersion);
    assert!(
        match (&s.v2().server_type) {
            ServerType::Committee { threshold: _ } => true,
            _ => false,
        },
        EInvalidServerType,
    );
}

#[test_only]
/// Check if a member has a partial key server
public fun has_partial_key_server(s: &KeyServer, member: address): bool {
    assert!(has_v2(s), EInvalidVersion);
    let v2 = v2(s);
    df::exists_(&v2.id, member)
}

#[test_only]
/// Get partial key server for a member (for testing)
public fun get_partial_key_server(s: &KeyServer, member: address): &PartialKeyServer {
    assert!(has_v2(s), EInvalidVersion);
    let v2 = v2(s);
    assert!(df::exists_(&v2.id, member), EPartialKeyServerNotFound);
    df::borrow(&v2.id, member)
}

#[test_only]
/// Get pk from partial key server
public fun partial_key_server_pk(pks: &PartialKeyServer): &vector<u8> {
    &pks.pk
}

#[test_only]
/// Get url from partial key server
public fun partial_key_server_url(pks: &PartialKeyServer): String {
    pks.url
}

public fun id(s: &KeyServer): address {
    s.id.to_address()
}

/// Get name (supports both v1 and v2)
public fun name(s: &KeyServer): String {
    if (has_v2(s)) {
        s.v2().name
    } else {
        s.v1().name
    }
}

/// Get key type (supports both v1 and v2)
public fun key_type(s: &KeyServer): u8 {
    if (has_v2(s)) {
        s.v2().key_type
    } else {
        s.v1().key_type
    }
}

// ===== V1 functions =====

fun create_v1(
    name: String,
    url: String,
    key_type: u8,
    pk: vector<u8>,
    ctx: &mut TxContext,
): KeyServer {
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
    key_server
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

/// Update URL for v1 or v2 independent server.
public fun update(s: &mut KeyServer, url: String) {
    if (df::exists_(&s.id, 1)) {
        let v1: &mut KeyServerV1 = df::borrow_mut(&mut s.id, 1);
        v1.url = url;
    } else if (df::exists_(&s.id, 2)) {
        let v2: &mut KeyServerV2 = df::borrow_mut(&mut s.id, 2);
        v2.server_type = ServerType::Independent { url: url };
    } else {
        abort EInvalidVersion
    }
}

/// Get URL (supports v1)
public fun url(s: &KeyServer): String {
    s.v1().url
}

/// Get public key (supports both v1 and v2)
public fun pk(s: &KeyServer): &vector<u8> {
    if (has_v2(s)) {
        &s.v2().pk
    } else {
        &s.v1().pk
    }
}

/// Get public key as BLS12-381 element (supports v1)
public fun pk_as_bf_bls12381(s: &KeyServer): Element<G2> {
    let v1 = s.v1();
    assert!(v1.key_type == KeyTypeBonehFranklinBLS12381, EInvalidKeyType);
    g2_from_bytes(&v1.pk)
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
    assert!(name(&s) == b"mysten".to_string(), 0);
    assert!(url(&s) == b"https::/mysten-labs.com".to_string(), 0);
    assert!(pk(&s) == pk.bytes(), 0);
    s.update(b"https::/mysten-labs2.com".to_string());
    assert!(url(&s) == b"https::/mysten-labs2.com".to_string(), 0);

    upgrade_to_v2(&mut s, scenario.ctx());
    update(&mut s, b"https::/mysten-labs3.com".to_string());
    assert!(url(&s) == b"https::/mysten-labs3.com".to_string(), 0);

    destroy_for_testing(s);
    test_scenario::end(scenario);
}
