// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Permissionless registration of a key server:
// - Key server should expose an endpoint /service that returns the official object id of its key server (to prevent
//   impersonation) and a PoP(key=IBE key, m=[key_server_id | IBE public key]).
// - Key server should expose an endpoint /fetch_key that allows users to request a key from the key server.

module seal::key_server;

use std::string::String;
use sui::{bls12381::{G2, g2_from_bytes}, dynamic_field as df, group_ops::Element};

const KeyTypeBonehFranklinBLS12381: u8 = 0;
const EInvalidKeyType: u64 = 1;
const EInvalidVersion: u64 = 2;
const ENotCommitteeMember: u64 = 3;

/// KeyServer should always be guarded as it's a capability
/// on its own. It should either be an owned object, wrapped object,
/// or TTO'd object (where access to it is controlled externally).
public struct KeyServer has key, store {
    id: UID,
    first_version: u64,
    last_version: u64,
    // owns partial key server
}

public struct KeyServerV1 has store {
    name: String,
    url: String,
    key_type: u8,
    pk: vector<u8>,
}


public enum ServerType has store, drop, copy {
    Committee,
    Single,
}

/// PartialKeyServer - owned by individual committee members
public struct PartialKeyServer has key, store {
    id: UID,
    /// Associated KeyServer ID
    key_server_id: address,
    /// Party ID in the DKG
    party_id: u16,
    /// Partial public key (BLS G2 point)
    pk: vector<u8>,
    /// Key server URL
    url: String,
}

/// KeyServerV2 - supports both single and committee-based key servers
public struct KeyServerV2 has store {
    name: String,
    url: String,  // For Single type only
    key_type: u8,
    pk: vector<u8>,  // Full public key (VSS polynomial coefficients for Committee)
    server_type: ServerType,
    threshold: u16,  // t for Committee, 0 for Single
    /// Committee members' addresses (empty for Single)
    members: vector<address>,
    /// Partial key server IDs (empty for Single)
    partial_keyserver_ids: vector<address>,
}

// ===== V2 Functions =====

/// Create a committee-based KeyServer (after DKG completion)
public fun create_v2(
    name: String,
    key_type: u8,
    vss_pk: vector<u8>, 
    threshold: u16,
    members: vector<address>,
    ctx: &mut TxContext,
): KeyServer {
    assert!(key_type == KeyTypeBonehFranklinBLS12381, EInvalidKeyType);
    
    let mut key_server = KeyServer {
        id: object::new(ctx),
        first_version: 2,
        last_version: 2,
    };
    
    let key_server_v2 = KeyServerV2 {
        name,
        url: name,
        key_type,
        pk: vss_pk,
        server_type: ServerType::Committee,
        threshold,
        members,
        partial_keyserver_ids: vector::empty(),
    };
    
    df::add(&mut key_server.id, 2, key_server_v2);
    key_server
}

/// Upgrade current owned key server to v2. 
public fun upgrade_to_v2(
    ks: &mut KeyServer,
) {
    let key_server_v2 = KeyServerV2 {
        name: ks.v1().name,
        url: ks.v1().url,
        key_type: ks.v1().key_type,
        pk: ks.v1().pk,
        server_type: ServerType::Single,
        threshold: 0,
        members: vector::empty(),
        partial_keyserver_ids: vector::empty(),
    };
    
    df::add(&mut ks.id, 2, key_server_v2);
    ks.last_version = 2;
}

/// Create a PartialKeyServer as an owned object to caller. 
/// Only committee members can create partial key servers for their committee's KeyServer
public fun new_partial_key_server(
    key_server: &mut KeyServer,
    party_id: u16,
    partial_pk: vector<u8>,
    server_url: String,
    ctx: &mut TxContext,
): PartialKeyServer {
    // Verify sender is a member of the committee
    assert!(is_member(key_server, ctx.sender()), ENotCommitteeMember);
    
    let partial_key_server = PartialKeyServer {
        id: object::new(ctx),
        key_server_id: key_server.id.to_address(),
        party_id,
        pk: partial_pk,
        url: server_url,
    };
    
    // Add the partial keyserver ID to the keyserver's tracking
    assert!(has_v2(key_server), EInvalidVersion);
    let v2: &mut KeyServerV2 = df::borrow_mut(&mut key_server.id, 2);
    v2.partial_keyserver_ids.push_back(partial_key_server.id.to_address());
    
    partial_key_server
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

public fun v2(s: &KeyServer): &KeyServerV2 {
    assert!(df::exists_(&s.id, 2), EInvalidVersion);
    df::borrow(&s.id, 2)
}

public fun is_member(keyserver: &KeyServer, sender: address): bool {
    let mut i = 0;
    let v2 = keyserver.v2();
    while (i < v2.members.length()) {
        if (v2.members[i] == sender) {
            return true
        };
        i = i + 1;
    };
    false
}

/// Check if KeyServer has v2
public fun has_v2(s: &KeyServer): bool {
    df::exists_(&s.id, 2)
}

/// Get name (supports both v1 and v2)
public fun name(s: &KeyServer): String {
    if (has_v2(s)) {
        s.v2().name
    } else {
        s.v1().name
    }
}

/// Get URL (supports both v1 and v2)
public fun url(s: &KeyServer): String {
    if (has_v2(s)) {
        s.v2().url
    } else {
        s.v1().url
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

/// Get public key (supports both v1 and v2)
public fun pk(s: &KeyServer): &vector<u8> {
    if (has_v2(s)) {
        &s.v2().pk
    } else {
        &s.v1().pk
    }
}

public fun pk_as_bf_bls12381(s: &KeyServer): Element<G2> {
    if (has_v2(s)) {
        let v2 = s.v2();
        assert!(v2.key_type == KeyTypeBonehFranklinBLS12381, EInvalidKeyType);
        // For committee, pk contains VSS coefficients - return first coefficient as public key
        g2_from_bytes(&v2.pk)
    } else {
        let v1 = s.v1();
        assert!(v1.key_type == KeyTypeBonehFranklinBLS12381, EInvalidKeyType);
        g2_from_bytes(&v1.pk)
    }
}

public fun update(s: &mut KeyServer, url: String) {
    if (df::exists_(&s.id, 1)) {
        let v1: &mut KeyServerV1 = df::borrow_mut(&mut s.id, 1);
        v1.url = url;
    } else {
        abort EInvalidVersion
    }
}

public fun update_partial(s: &mut PartialKeyServer, url: String) {
    s.url = url;
}

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

    destroy_for_testing(s);
    test_scenario::end(scenario);
}
