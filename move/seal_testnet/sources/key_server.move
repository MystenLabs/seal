// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Key server is a top level object that maps to versioned key server. 
// V1: Supports only independent key servers. A V1 server can upgrade to a V2 independent server.
// V2: Supports both independent and committee-based key servers. A committee based V2 server can 
// be created afresh, that holds map of partial key servers that contains the member's partial 
// public key, party ID and URL. When a committee rotates, the partial public keys and party IDs 
// are updated. 
//
// Permissionless registration of a key server:
// - Key server should expose an endpoint /service: For V1 or V2 independent server, it returns the 
// official object id of its key server (to prevent impersonation) and a PoP(key=IBE key, 
// m=[key_server_id | IBE public key]). For V2 committee based server it returns the key server
// object ID for the committee it belongs to, and a PoP(key=IBE key, m=[key_server_id | party_id | 
// partial public key]). 
// 
// - Key server should expose an endpoint /fetch_key that allows users to request a key from the key
// server.

module seal_testnet::key_server;

use std::string::String;
use sui::{bls12381::{G2, g2_from_bytes}, dynamic_field as df, group_ops::Element, vec_map::VecMap};

const KeyTypeBonehFranklinBLS12381: u8 = 0;
const EInvalidKeyType: u64 = 1;
const EInvalidVersion: u64 = 2;
const EInvalidServerType: u64 = 3;
const EInvalidThreshold : u64 = 4;

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

/// KeyServerV2, supports both single and committee-based key servers.
public struct KeyServerV2 has store {
    name: String,
    key_type: u8,
    pk: vector<u8>,
    server_type: ServerType,
}

/// Server types for KeyServerV2.
public enum ServerType has drop, store {
    Independent {
        url: String,
    },
    Committee {
        threshold: u64,
        partial_key_servers: VecMap<address, PartialKeyServer>,
    },
}

/// PartialKeyServer, holds the partial pk, party ID and URL for a committee member.
public struct PartialKeyServer has copy, drop, store {
    partial_pk: vector<u8>, // Partial public key (G2 element).
    url: String, // Key server URL.
    party_id: u64, // Party ID in the DKG.
}

// ===== V2 Functions =====

/// Create a committee-owned KeyServer.
public fun create_committee_v2(
    name: String,
    threshold: u64,
    pk: vector<u8>,
    partial_key_servers: VecMap<address, PartialKeyServer>,
    ctx: &mut TxContext,
): KeyServer {
    assert!(threshold > 0, EInvalidThreshold);
    assert!(partial_key_servers.length() >= threshold, EInvalidThreshold);
    // TODO: assert pk and partial_pk are all valid elements. 
    let mut key_server = KeyServer {
        id: object::new(ctx),
        first_version: 2,
        last_version: 2,
    };

    let key_server_v2 = KeyServerV2 {
        name,
        key_type: KeyTypeBonehFranklinBLS12381,
        pk,
        server_type: ServerType::Committee { threshold, partial_key_servers },
    };

    df::add(&mut key_server.id, 2, key_server_v2);
    key_server
}

/// Upgrade the current key server to v2, still a single owner object.
public fun upgrade_to_independent_v2(ks: &mut KeyServer) {
    if (ks.has_v2()) { return };

    let v1 = ks.v1();
    assert!(ks.last_version == 1, EInvalidVersion);

    let key_server_v2 = KeyServerV2 {
        name: v1.name,
        key_type: v1.key_type,
        pk: v1.pk,
        server_type: ServerType::Independent { url: v1.url },
    };

    df::add(&mut ks.id, 2, key_server_v2);
    ks.last_version = 2;
}

/// Create a PartialKeyServer with respective fields.
public fun create_partial_key_server(
    partial_pk: vector<u8>,
    url: String,
    party_id: u64,
): PartialKeyServer {
    // TODO: validate partial_pk is a valid element.
    PartialKeyServer {
        partial_pk,
        url,
        party_id,
    }
}

/// Set the VecMap of partial key servers for a committee based KeyServerV2.
public fun set_partial_key_servers(
    s: &mut KeyServer,
    partial_key_servers: VecMap<address, PartialKeyServer>,
) {
    // TODO: validate partial pk are valid elements. 
    s.assert_committee_server_v2();
    let v2: &mut KeyServerV2 = df::borrow_mut(&mut s.id, 2);
    match (&mut v2.server_type) {
        ServerType::Committee { partial_key_servers: value, .. } => {
            *value = partial_key_servers;
        },
        _ => abort EInvalidServerType,
    }
}

/// Update URL for a member's partial key server in a committee based KeyServerV2.
public fun update_member_url(s: &mut KeyServer, url: String, member: address) {
    assert_committee_server_v2(s);
    let v2: &mut KeyServerV2 = df::borrow_mut(&mut s.id, 2);
    match (&mut v2.server_type) {
        ServerType::Committee { partial_key_servers, .. } => {
            let partial_key_server = partial_key_servers.get_mut(&member);
            partial_key_server.url = url;
        },
        _ => abort EInvalidServerType,
    }
}

/// Get the v2 struct of a key server.
public fun v2(s: &KeyServer): &KeyServerV2 {
    assert!(s.has_v2(), EInvalidVersion);
    df::borrow(&s.id, 2)
}

/// Check if KeyServer has v2.
public fun has_v2(s: &KeyServer): bool {
    df::exists_(&s.id, 2)
}

/// Check if KeyServer is v2 and is a committee server.
public fun assert_committee_server_v2(s: &KeyServer) {
    assert!(s.has_v2(), EInvalidVersion);
    assert!(
        match (&s.v2().server_type) {
            ServerType::Committee { .. } => true,
            _ => false,
        },
        EInvalidServerType,
    );
}

// ===== V1 functions =====

// Entry function to register a key server v1 object and transfer it to the caller.
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

/// Update URL for v1 or v2 independent server.
public fun update(s: &mut KeyServer, url: String) {
    if (s.has_v2()) {
        let v2: &mut KeyServerV2 = df::borrow_mut(&mut s.id, 2);
        match (&mut v2.server_type) {
            ServerType::Independent { url: value } => {
                *value = url;
            },
            _ => abort EInvalidServerType,
        }
    } else if (df::exists_(&s.id, 1)) {
        let v1: &mut KeyServerV1 = df::borrow_mut(&mut s.id, 1);
        v1.url = url;
    } else {
        abort EInvalidVersion
    }
}

/// Get the v1 struct of a key server.
public fun v1(s: &KeyServer): &KeyServerV1 {
    assert!(df::exists_(&s.id, 1), EInvalidVersion);
    df::borrow(&s.id, 1)
}

/// Get name, supports both v1 and v2.
public fun name(s: &KeyServer): String {
    if (s.has_v2()) {
        s.v2().name
    } else {
        s.v1().name
    }
}

/// Get URL, supports v1 and v2 independent server only.
public fun url(s: &KeyServer): String {
    if (s.has_v2()) {
        let v2 = s.v2();
        match (&v2.server_type) {
            ServerType::Independent { url } => *url,
            _ => abort EInvalidServerType,
        }
    } else {
        s.v1().url
    }
}

/// Get key type, supports both v1 and v2.
public fun key_type(s: &KeyServer): u8 {
    if (s.has_v2()) {
        s.v2().key_type
    } else {
        s.v1().key_type
    }
}

/// Get public key, supports both v1 and v2.
public fun pk(s: &KeyServer): &vector<u8> {
    if (s.has_v2()) {
        &s.v2().pk
    } else {
        &s.v1().pk
    }
}

/// Get the ID of the KeyServer, supports both v1 and v2.
public fun id(s: &KeyServer): address {
    s.id.to_address()
}

/// Get public key as BLS12-381 element, supports both v1 and v2.
public fun pk_as_bf_bls12381(s: &KeyServer): Element<G2> {
    if (s.has_v2()) {
        let v2 = s.v2();
        g2_from_bytes(&v2.pk)
    } else {
        let v1 = s.v1();
        assert!(v1.key_type == KeyTypeBonehFranklinBLS12381, EInvalidKeyType);
        g2_from_bytes(&v1.pk)
    }
}

/// Internal function to create a KeyServerV1 object.
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


/// Get the partial key server object corresponding to the member.
#[test_only]
public fun partial_key_server_for_member(s: &KeyServer, member: address): PartialKeyServer {
    s.assert_committee_server_v2();
    let v2: &KeyServerV2 = df::borrow(&s.id, 2);
    match (&v2.server_type) {
        ServerType::Committee { partial_key_servers, .. } => {
            *partial_key_servers.get(&member)
        },
        _ => abort EInvalidServerType,
    }
}

/// Get URL for PartialKeyServer.
#[test_only]
public fun partial_ks_url(partial: &PartialKeyServer): String {
    partial.url
}

/// Get partial PK for PartialKeyServer.
#[test_only]
public fun partial_ks_pk(partial: &PartialKeyServer): vector<u8> {
    partial.partial_pk
}

/// Get party ID for PartialKeyServer.
#[test_only]
public fun partial_ks_party_id(partial: &PartialKeyServer): u64 {
    partial.party_id
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
        b"https:/mysten-labs.com".to_string(),
        0,
        pk_bytes,
        scenario.ctx(),
    );
    scenario.next_tx(addr1);

    let mut s: KeyServer = scenario.take_from_sender();
    assert!(s.name() == b"mysten".to_string(), 0);
    assert!(s.url() == b"https:/mysten-labs.com".to_string(), 0);
    assert!(*s.pk() == *pk.bytes(), 0);
    s.update(b"https:/mysten-labs2.com".to_string());
    assert!(s.url() == b"https:/mysten-labs2.com".to_string(), 0);

    s.upgrade_to_independent_v2();
    s.update(b"https:/mysten-labs3.com".to_string());
    assert!(s.url() == b"https:/mysten-labs3.com".to_string(), 0);

    s.destroy_for_testing();
    scenario.end();
}
