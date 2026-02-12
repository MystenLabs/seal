// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Implementation for Seal key server onchain registration.
//
// Key server is a top level object that contains dynamic field objects for versioned key server.
//
// V1: Supports only independent key servers. A V1 server can upgrade to a V2 independent server.
// V2: Supports both independent and committee key servers. A committee based V2 key server holds a
// map of partial key servers that contains the member's partial public key, party ID and URL. The
// partial public keys and party IDs can be updated while the key server public key is unchanged.
//
// A key server can be registered permissionlessly onchain. The server allows users to request a 
// key for a given Seal policy.

module seal::key_server;

use std::string::String;
use sui::{bls12381::{G2, g2_from_bytes}, dynamic_field as df, group_ops::Element, vec_map::VecMap};

const KEY_TYPE_BONEH_FRANKLIN_BLS12381: u8 = 0;
const EInvalidKeyType: u64 = 1;
const EInvalidVersion: u64 = 2;
const EInvalidServerType: u64 = 3;
const EInvalidThreshold: u64 = 4;
const EInvalidPartyId: u64 = 5;
const ENotMember: u64 = 6;

const V1: u64 = 1;
const V2: u64 = 2;

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
        /// Incremented on every rotation of the committee.
        version: u32,
        threshold: u16,
        /// Maps of current members' addresses to their partial key server info. Updated on every
        /// rotation of the committee.
        partial_key_servers: VecMap<address, PartialKeyServer>,
    },
}

/// PartialKeyServer struct for a committee member.
public struct PartialKeyServer has copy, drop, store {
    /// Unique name of the partial key server.
    name: String,
    /// Server URL, can be updated by the owning member.
    url: String,
    /// Partial public key (G2 element).
    partial_pk: vector<u8>,
    /// Party ID in the DKG committee.
    party_id: u16,
}

// ===== V2 Public Functions =====

/// Create a key server object with df of KeyServerV2 of committee server type.
public fun create_committee_v2(
    name: String,
    threshold: u16,
    pk: vector<u8>,
    partial_key_servers: VecMap<address, PartialKeyServer>,
    ctx: &mut TxContext,
): KeyServer {
    let _ = g2_from_bytes(&pk);
    validate_partial_key_servers(threshold, &partial_key_servers);

    // Key server version starts at 2.
    let mut key_server = KeyServer {
        id: object::new(ctx),
        first_version: V2,
        last_version: V2,
    };

    // Committee version starts at 0.
    let key_server_v2 = KeyServerV2 {
        name,
        key_type: KEY_TYPE_BONEH_FRANKLIN_BLS12381,
        pk,
        server_type: ServerType::Committee { version: 0, threshold, partial_key_servers },
    };

    // Add KeyServerV2 as df.
    df::add(&mut key_server.id, V2, key_server_v2);
    key_server
}

/// Upgrade the current key server's to v2 by adding a df to KeyServerV2, still a single owner object.
public fun upgrade_v1_to_independent_v2(ks: &mut KeyServer) {
    assert!(ks.first_version == V1, EInvalidVersion);
    assert!(ks.last_version == V1, EInvalidVersion);
    assert!(!ks.has_v2(), EInvalidVersion);

    let v1 = ks.v1();
    let key_server_v2 = KeyServerV2 {
        name: v1.name,
        key_type: v1.key_type,
        pk: v1.pk,
        server_type: ServerType::Independent { url: v1.url },
    };

    df::add(&mut ks.id, V2, key_server_v2);
    ks.last_version = V2;
}

/// Create a PartialKeyServer with respective fields.
public fun create_partial_key_server(
    name: String,
    url: String,
    partial_pk: vector<u8>,
    party_id: u16,
): PartialKeyServer {
    let _ = g2_from_bytes(&partial_pk);
    PartialKeyServer {
        name,
        url,
        partial_pk,
        party_id,
    }
}

/// Updates threshold and VecMap of partial key servers and increments version. Can only be called
/// on V2 committee server type KeyServer.
public fun update_partial_key_servers(
    s: &mut KeyServer,
    threshold: u16,
    partial_key_servers: VecMap<address, PartialKeyServer>,
) {
    validate_partial_key_servers(threshold, &partial_key_servers);
    s.assert_committee_server_v2();

    let v2: &mut KeyServerV2 = df::borrow_mut(&mut s.id, V2);
    match (&mut v2.server_type) {
        ServerType::Committee { partial_key_servers: value, threshold: t, version: v } => {
            *value = partial_key_servers;
            *t = threshold;
            *v = *v + 1;
        },
        _ => abort EInvalidServerType,
    }
}

/// Updates URL for a partial key server for a given member. Can only be called on V2 committee
/// server type KeyServer.
public fun update_member_url(s: &mut KeyServer, url: String, member: address) {
    s.assert_committee_server_v2();

    let v2: &mut KeyServerV2 = df::borrow_mut(&mut s.id, V2);
    match (&mut v2.server_type) {
        ServerType::Committee { partial_key_servers, .. } => {
            assert!(partial_key_servers.contains(&member), ENotMember);
            let partial_key_server = partial_key_servers.get_mut(&member);
            partial_key_server.url = url;
        },
        _ => abort EInvalidServerType,
    }
}

// ===== V1 Public Functions =====

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

/// Update server URL. Can only be called on V1 or V2 independent server type KeyServer.
public fun update(s: &mut KeyServer, url: String) {
    if (s.has_v2()) {
        let v2: &mut KeyServerV2 = df::borrow_mut(&mut s.id, V2);
        match (&mut v2.server_type) {
            ServerType::Independent { url: value } => {
                *value = url;
            },
            _ => abort EInvalidServerType,
        }
    } else if (s.has_v1()) {
        let v1: &mut KeyServerV1 = df::borrow_mut(&mut s.id, V1);
        v1.url = url;
    } else {
        abort EInvalidVersion
    }
}

/// Get KeyServerV1 from KeyServer.
public fun v1(s: &KeyServer): &KeyServerV1 {
    assert!(s.has_v1(), EInvalidVersion);
    df::borrow(&s.id, V1)
}

/// Get name of key server. Supports both V1 and V2.
public fun name(s: &KeyServer): String {
    if (s.has_v2()) {
        s.v2().name
    } else if (s.has_v1()) {
        s.v1().name
    } else {
        abort EInvalidVersion
    }
}

/// Get URL of key server. Supports V1 and V2 independent server type only.
public fun url(s: &KeyServer): String {
    if (s.has_v2()) {
        let v2 = s.v2();
        match (&v2.server_type) {
            ServerType::Independent { url } => *url,
            _ => abort EInvalidServerType,
        }
    } else if (s.has_v1()) {
        s.v1().url
    } else {
        abort EInvalidVersion
    }
}

/// Get key type. Supports both V1 and V2.
public fun key_type(s: &KeyServer): u8 {
    if (s.has_v2()) {
        s.v2().key_type
    } else if (s.has_v1()) {
        s.v1().key_type
    } else {
        abort EInvalidVersion
    }
}

/// Get public key. Supports both V1 and V2.
public fun pk(s: &KeyServer): &vector<u8> {
    if (s.has_v2()) {
        &s.v2().pk
    } else if (s.has_v1()) {
        &s.v1().pk
    } else {
        abort EInvalidVersion
    }
}

/// Get the ID of the KeyServer. Supports both V1 and V2.
public fun id(s: &KeyServer): address {
    s.id.to_address()
}

/// Get public key as BLS12-381 element. Supports both V1 and V2.
public fun pk_as_bf_bls12381(s: &KeyServer): Element<G2> {
    if (s.has_v2()) {
        let v2 = s.v2();
        assert!(v2.key_type == KEY_TYPE_BONEH_FRANKLIN_BLS12381, EInvalidKeyType);
        g2_from_bytes(&v2.pk)
    } else if (s.has_v1()) {
        let v1 = s.v1();
        assert!(v1.key_type == KEY_TYPE_BONEH_FRANKLIN_BLS12381, EInvalidKeyType);
        g2_from_bytes(&v1.pk)
    } else {
        abort EInvalidVersion
    }
}

// ===== V2 Internal Functions =====

/// Validates threshold and party IDs are unique and in range.
fun validate_partial_key_servers(
    threshold: u16,
    partial_key_servers: &VecMap<address, PartialKeyServer>,
) {
    assert!(threshold > 1, EInvalidThreshold);
    assert!(partial_key_servers.length() as u16 >= threshold, EInvalidThreshold);

    let n = partial_key_servers.length() as u16;
    let mut party_ids = sui::vec_set::empty();
    partial_key_servers.keys().do_ref!(|key| {
        let partial_key_server = partial_key_servers.get(key);

        // Validate party ID is in valid range and unique.
        let party_id = partial_key_server.party_id;
        assert!(party_id < n, EInvalidPartyId);
        assert!(!party_ids.contains(&party_id), EInvalidPartyId);
        party_ids.insert(party_id);
    });
}

/// Check if KeyServer is v2 and is a committee server type.
fun assert_committee_server_v2(s: &KeyServer) {
    assert!(s.first_version <= V2 && s.last_version >= V2, EInvalidVersion);
    assert!(df::exists_(&s.id, V2), EInvalidVersion);

    let v2: &KeyServerV2 = df::borrow(&s.id, V2);
    assert!(
        match (&v2.server_type) {
            ServerType::Committee { .. } => true,
            _ => false,
        },
        EInvalidServerType,
    );
}

/// Check if KeyServer has v2.
fun has_v2(s: &KeyServer): bool {
    df::exists_(&s.id, V2)
}

/// Get KeyServerV2 of a key server.
fun v2(s: &KeyServer): &KeyServerV2 {
    assert!(s.has_v2(), EInvalidVersion);
    assert!(s.first_version <= V2 && s.last_version >= V2, EInvalidVersion);
    df::borrow(&s.id, V2)
}

/// Check if KeyServer has v1.
fun has_v1(s: &KeyServer): bool {
    df::exists_(&s.id, V1)
}

// ==== V1 Internal Functions ====

/// Internal function to create a KeyServerV1 object.
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
    df::add(&mut key_server.id, V1, key_server_v1);
    key_server
}

// ==== Test Only Functions ====

/// Get the partial key server object corresponding to the member.
#[test_only]
public fun partial_key_server_for_member(s: &KeyServer, member: address): PartialKeyServer {
    s.assert_committee_server_v2();
    let v2: &KeyServerV2 = df::borrow(&s.id, V2);
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
public fun partial_ks_party_id(partial: &PartialKeyServer): u16 {
    partial.party_id
}

/// Get the committee version and threshold for a committee-based KeyServer.
#[test_only]
public fun committee_version_and_threshold(s: &KeyServer): (u32, u16) {
    s.assert_committee_server_v2();
    let v2: &KeyServerV2 = df::borrow(&s.id, V2);
    match (&v2.server_type) {
        ServerType::Committee { version, threshold, .. } => (*version, *threshold),
        _ => abort EInvalidServerType,
    }
}

#[test_only]
public fun last_version(s: &KeyServer): u64 {
    s.last_version
}

#[test_only]
public fun create_v1_for_testing(
    name: String,
    url: String,
    key_type: u8,
    pk: vector<u8>,
    ctx: &mut TxContext,
): KeyServer {
    create_v1(name, url, key_type, pk, ctx)
}

#[test_only]
public fun destroy_for_testing(self: KeyServer) {
    let KeyServer { id, first_version: _, last_version: _ } = self;
    id.delete();
}
