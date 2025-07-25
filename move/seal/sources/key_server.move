// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Permissionless registration of a key server:
// - Key server should expose an endpoint /service that returns the official object id of its key server (to prevent
//   impersonation) and a PoP(key=IBE key, m=[key_server_id | IBE public key]).
// - Key server should expose an endpoint /fetch_key that allows users to request a key from the key server.

module seal::key_server;

use std::string::String;
use sui::{bls12381::{G2, g2_from_bytes}, dynamic_field as df, group_ops::Element};
use sui::object::id_to_address;
use sui::transfer::Receiving;

const EInvalidKeyType: u64 = 1;
const EInvalidVersion: u64 = 2;
const EInvalidCommittee: u64 = 3;
const EInsufficientApprovals: u64 = 4;
const ECommitteeNotActive: u64 = 6;
const KeyTypeBonehFranklinBLS12381: u8 = 0;

public struct KeyServer has key {
    id: UID,
    first_version: u64,
    last_version: u64,
}

public struct PartialKeyServer has store, copy {
    id: ID,
    pk: vector<u8>,
    url: String,
}

public struct Committee has key {
    id: UID,
    threshold: u8, 
    distributed_servers: vector<PartialKeyServer>,
    is_active: bool,
    votes: vector<ID>,
}

public struct CommitteeCap has key, store {
    id: UID,
    committee_id: ID,
}

public struct KeyServerV1 has store {
    name: String,
    url: String,
    key_type: u8,
    pk: vector<u8>,
}

public struct KeyServerV2 has store {
    name: String,
    url: String,
    key_type: u8,
    pk: vector<u8>,
    threshold: u8, 
    distributed_servers: vector<PartialKeyServer>,
}

public fun create_committee(
    threshold: u8,
    ctx: &mut TxContext,
): (Committee, CommitteeCap) {
    assert!(threshold > 0, EInvalidCommittee);
    
    let committee = Committee {
        id: object::new(ctx),
        threshold,
        distributed_servers: vector::empty(),
        is_active: true,
        votes: vector::empty(),
    };
    
    let cap = CommitteeCap {
        id: object::new(ctx),
        committee_id: object::id(&committee),
    };
    
    (committee, cap)
}

public fun add_distributed_server(
    current_committee: &mut Committee,
    server: PartialKeyServer
) {
    current_committee.distributed_servers.push_back(server);
}

public fun partial_key_server_id(s: &PartialKeyServer): &ID {
    &s.id
}

public fun id(s: &KeyServer): &UID {
    &s.id
}

public fun approve(
    current_committee: &mut Committee,
    partial_key_server: &PartialKeyServer,
    new_committee: &mut Committee,
) {
    assert!(current_committee.distributed_servers.contains(partial_key_server), EInvalidCommittee);

    if (!current_committee.votes.contains(partial_key_server_id(partial_key_server))) {
        current_committee.votes.push_back(*partial_key_server_id(partial_key_server));
    };
    
    if (new_committee.votes.length() >= new_committee.threshold as u64) {
        new_committee.is_active = true;
        current_committee.is_active = false;
    }
}

public fun activate_committee(
    current_committee: &mut Committee,
    new_committee: &mut Committee,
) {
    assert!(current_committee.is_active, ECommitteeNotActive);
    assert!(new_committee.votes.length() >= new_committee.threshold as u64, EInsufficientApprovals);
    
    current_committee.is_active = false;
    new_committee.is_active = true;
}

// === Key Server Transfer and Receiving Functions ===

/// Transfer a key server to a new committee
public fun transfer_key_server_to_committee(
    key_server: KeyServer,
    new_committee: &Committee,
    cap: &CommitteeCap,
) {
    assert!(object::id(new_committee) == cap.committee_id, EInvalidCommittee);
    assert!(new_committee.is_active, ECommitteeNotActive);
    
    // Transfer the key server to the new committee
    transfer::transfer(key_server, id_to_address(&object::id(new_committee)));
}

/// Receive a key server that was transferred to the committee
/// This function can be called by any committee member with the committee cap
public fun receive_key_server(
    committee: &mut Committee,
    cap: &CommitteeCap,
    sent: Receiving<KeyServer>,
): KeyServer {
    assert!(object::id(committee) == cap.committee_id, EInvalidCommittee);
    assert!(committee.is_active, ECommitteeNotActive);
    transfer::receive(&mut committee.id, sent)
}

/// Update a key server owned by the committee
public fun update_key_server_v2(
    committee: &mut Committee,
    cap: &CommitteeCap,
    key_server: &mut KeyServer,
    new_url: String,
) {
    assert!(object::id(committee) == cap.committee_id, EInvalidCommittee);
    assert!(committee.is_active, ECommitteeNotActive);
    
    let v2: &mut KeyServerV2 = df::borrow_mut(&mut key_server.id, 2);
    v2.url = new_url;
}

/// Check if committee is active
public fun is_committee_active(committee: &Committee): bool {
    committee.is_active
}

public fun create_v2(
    name: String,
    url: String,
    key_type: u8,
    pk: vector<u8>,
    committee: &Committee,
    ctx: &mut TxContext,
) {
    // Currently only BLS12-381 is supported.
    assert!(key_type == KeyTypeBonehFranklinBLS12381, EInvalidKeyType);
    let _ = g2_from_bytes(&pk);

    let mut key_server = KeyServer {
        id: object::new(ctx),
        first_version: 1,
        last_version: 2,
    };

    let key_server_v2 = KeyServerV2 {
        name,
        url,
        key_type,
        pk,
        threshold: committee.threshold,
        distributed_servers: committee.distributed_servers,
    };
    df::add(&mut key_server.id, 2, key_server_v2);
    transfer::transfer(key_server, id_to_address(&object::id(committee)));
}

public fun create_v1(
    name: String,
    url: String,
    key_type: u8,
    pk: vector<u8>,
    ctx: &mut TxContext,
) {
        let mut key_server = KeyServer {
        id: object::new(ctx),
        first_version: 1,
        last_version: 2,
    };

    let key_server_v1 = KeyServerV1 {
        name,
        url,
        key_type,
        pk,
    };
    df::add(&mut key_server.id, 1, key_server_v1);
    transfer::transfer(key_server, tx_context::sender(ctx));
}

entry fun create_and_transfer_v2(
    name: String,
    url: String,
    key_type: u8,
    pk: vector<u8>,
    committee: &Committee,
    ctx: &mut TxContext,
) {
    create_v2(name, url, key_type, pk, committee, ctx);
}

entry fun create_and_transfer_v1(
    name: String,
    url: String,
    key_type: u8,
    pk: vector<u8>,
    ctx: &mut TxContext,
) {
    create_v1(name, url, key_type, pk, ctx);
}

public fun v1(s: &KeyServer): &KeyServerV1 {
    assert!(df::exists_(&s.id, 1), EInvalidVersion);
    df::borrow(&s.id, 1)
}

public fun v2(s: &KeyServer): &KeyServerV2 {
    assert!(df::exists_(&s.id, 2), EInvalidVersion);
    df::borrow(&s.id, 2)
}

public fun name(s: &KeyServer): String {
    if (df::exists_(&s.id, 2)) {
        let v2 = v2(s);
        v2.name
    } else {
        let v1 = v1(s);
        v1.name
    }
}

public fun url(s: &KeyServer): String {
    if (df::exists_(&s.id, 2)) {
        let v2 = v2(s);
        v2.url
    } else {
        let v1 = v1(s);
        v1.url
    }
}

public fun key_type(s: &KeyServer): u8 {
    if (df::exists_(&s.id, 2)) {
        let v2 = v2(s);
        v2.key_type
    } else {
        let v1 = v1(s);
        v1.key_type
    }
}

public fun pk(s: &KeyServer): &vector<u8> {
    if (df::exists_(&s.id, 2)) {
        let v2 = v2(s);
        &v2.pk
    } else {
        let v1 = v1(s);
        &v1.pk
    }
}

public fun pk_as_bf_bls12381(s: &KeyServer): Element<G2> {
    let pk_bytes = pk(s);
    assert!(key_type(s) == KeyTypeBonehFranklinBLS12381, EInvalidKeyType);
    g2_from_bytes(pk_bytes)
}

public fun update(s: &mut KeyServer, url: String) {
    if (df::exists_(&s.id, 2)) {
        let v2: &mut KeyServerV2 = df::borrow_mut(&mut s.id, 2);
        v2.url = url;
    } else {
        assert!(df::exists_(&s.id, 1), EInvalidVersion);
        let v1: &mut KeyServerV1 = df::borrow_mut(&mut s.id, 1);
        v1.url = url;
    }
}

#[test_only]
public fun destroy_for_testing(v: KeyServer) {
    let KeyServer { id, .. } = v;
    object::delete(id);
}

#[test]
fun test_flow() {

    // use sui::test_scenario::{Self, next_tx, ctx};
    // use sui::bls12381::{g2_generator};
    // use std::string;

    // let addr1 = @0xA;
    // let mut scenario = test_scenario::begin(addr1);

    // let pk = g2_generator();
    // let pk_bytes = *pk.bytes();
    // create_v1(
    //     string::utf8(b"mysten"),
    //     string::utf8(b"https::/mysten-labs.com"),
    //     0,
    //     pk_bytes,
    //     ctx(&mut scenario),
    // );
    // next_tx(&mut scenario, addr1);

    // let mut s: KeyServer = scenario.take_from_sender();
    // assert!(name(&s) == string::utf8(b"mysten"), 0);
    // assert!(url(&s) == string::utf8(b"https::/mysten-labs.com"), 0);
    // assert!(pk(&s) == pk.bytes(), 0);
    // s.update(string::utf8(b"https::/mysten-labs2.com"));
    // assert!(url(&s) == string::utf8(b"https::/mysten-labs2.com"), 0);

    // destroy_for_testing(s);
    // test_scenario::end(scenario);
}
