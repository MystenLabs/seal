// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Permissionless registration of a key server:
// - Key server should expose an endpoint /service that returns the official object id of its key server (to prevent
//   impersonation) and a PoP(key=IBE key, m=[key_server_id | IBE public key]).
// - Key server should expose an endpoint /fetch_key that allows users to request a key from the key server.

module seal::key_server;

use std::string::String;
use sui::{bls12381::{G2, g2_from_bytes}, dynamic_field as df, group_ops::Element};
use sui::vec_set::{Self, VecSet};
use immutable::wrapper::{Self, Wrapper, Cap};

const KeyTypeBonehFranklinBLS12381: u8 = 0;
const EInvalidKeyType: u64 = 1;
const EInvalidVersion: u64 = 2;
const EInvalidCommittee: u64 = 3;
const ECommitteeNotActive: u64 = 4;
const ENotKeyServerOwner: u64 = 5;
const EAlreadyVoted: u64 = 6;

// ===== Existing types (unchanged for compatibility) =====

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

// ===== New types for V2 functionality =====

/// Partial key server - pk is immutable (set by committee), url is mutable (by owner)
public struct PartialKeyServer has key, store {
    id: UID,
    pk: vector<u8>,      // Immutable - set once by committee
    url: String,         // Mutable - can be updated by owner
    owner: address,      // The operator who can update the URL
}

/// Committee that controls the KeyServer through wrapper pattern
public struct Committee has key, store {
    id: UID,
    threshold: u8, 
    members: VecSet<address>,
    is_active: bool,
    // ID of the KeyServer wrapper (store cap in dynamic fields)
    key_server_wrapper_id: ID,
    // Voting for adding partial key servers
    pending_partial_server: Option<PendingPartialServer>,
    votes: VecSet<address>,
}

public struct PendingPartialServer has store, drop {
    pk: vector<u8>,
    url: String,
    owner: address,
}

public struct KeyServerV2 has store {
    name: String,
    key_type: u8,
    threshold: u8,
    // Store IDs of partial key servers instead of copying them
    partial_servers: vector<ID>,
}

// ===== Existing V1 functions (unchanged for compatibility) =====

public fun create_v1(
    name: String,
    url: String,
    key_type: u8,
    pk: vector<u8>,
    ctx: &mut TxContext,
) {
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
    transfer::transfer(key_server, tx_context::sender(ctx));
}

// Helper function to register a key server and transfer the cap to the caller.
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

public fun name(s: &KeyServer): String {
    if (df::exists_(&s.id, 1)) {
        let v1 = v1(s);
        v1.name
    } else {
        let v2: &KeyServerV2 = df::borrow(&s.id, 2);
        v2.name
    }
}

public fun url(s: &KeyServer): String {
    // V1 compatibility - returns V1 url only
    let v1 = v1(s);
    v1.url
}

public fun key_type(s: &KeyServer): u8 {
    if (df::exists_(&s.id, 1)) {
        let v1 = v1(s);
        v1.key_type
    } else {
        let v2: &KeyServerV2 = df::borrow(&s.id, 2);
        v2.key_type
    }
}

public fun pk(s: &KeyServer): &vector<u8> {
    // V1 compatibility - returns V1 pk only
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

public fun update(s: &mut KeyServer, url: String) {
    // Only works for V1 key servers
    assert!(df::exists_(&s.id, 1), EInvalidVersion);
    let v1: &mut KeyServerV1 = df::borrow_mut(&mut s.id, 1);
    v1.url = url;
}

// ===== New V2 functions =====

/// Create a new committee-controlled key server (V2)
public fun create_committee_key_server(
    name: String,
    key_type: u8,
    threshold: u8,
    committee_members: vector<address>,
    committee_threshold: u8,
    ctx: &mut TxContext,
): (ID, ID) {
    // Create the KeyServer
    let mut key_server = KeyServer {
        id: object::new(ctx),
        first_version: 2,
        last_version: 2,
    };
    
    // Create KeyServerV2
    let key_server_v2 = KeyServerV2 {
        name,
        key_type,
        threshold,
        partial_servers: vector::empty(),
    };
    df::add(&mut key_server.id, 2, key_server_v2);
    
    // Wrap the KeyServer
    let (key_server_wrapper, key_server_cap) = wrapper::wrap(key_server, ctx);
    
    // Create the Committee
    let committee = Committee {
        id: object::new(ctx),
        threshold: committee_threshold,
        members: vec_set::from_keys(committee_members),
        is_active: true,
        key_server_wrapper_id: object::id(&key_server_wrapper),
        pending_partial_server: option::none(),
        votes: vec_set::empty(),
    };
    
    // Transfer the key server cap to the committee object
    wrapper::transfer_cap(key_server_cap, object::id_address(&committee));
    
    // Wrap the Committee
    let (committee_wrapper, committee_cap) = wrapper::wrap(committee, ctx);
    // Transfer the committee cap to sender for now
    wrapper::transfer_cap(committee_cap, tx_context::sender(ctx));
    
    // Get IDs before sharing
    let committee_wrapper_id = object::id(&committee_wrapper);
    let key_server_wrapper_id = object::id(&key_server_wrapper);
    
    // Share both wrappers
    wrapper::share_wrapper(committee_wrapper);
    wrapper::share_wrapper(key_server_wrapper);
    
    (committee_wrapper_id, key_server_wrapper_id)
}

/// Committee votes to add a partial key server
public fun vote_add_partial_key_server(
    committee_wrapper: &mut Wrapper<Committee>,
    member_cap: &Cap,
    key_server_wrapper: &mut Wrapper<KeyServer>,
    key_server_cap: transfer::Receiving<Cap>,
    pk: vector<u8>,
    url: String,
    owner: address,
    ctx: &mut TxContext,
) {
    let committee = wrapper::get_mut(committee_wrapper, member_cap);
    let sender = tx_context::sender(ctx);
    
    // Verify member and committee state
    assert!(committee.members.contains(&sender), EInvalidCommittee);
    assert!(committee.is_active, ECommitteeNotActive);
    assert!(!committee.votes.contains(&sender), EAlreadyVoted);
    
    // Validate the public key
    assert!(pk.length() > 0, EInvalidKeyType);
    let _ = g2_from_bytes(&pk);
    
    // First vote sets the pending server
    if (committee.votes.is_empty()) {
        committee.pending_partial_server = option::some(PendingPartialServer {
            pk,
            url,
            owner,
        });
    };
    
    // Add vote
    committee.votes.insert(sender);
    
    // Execute if threshold met
    if (committee.votes.size() >= (committee.threshold as u64)) {
        let pending: PendingPartialServer = option::extract(&mut committee.pending_partial_server);
        
        // Create the partial key server
        let partial_server = PartialKeyServer {
            id: object::new(ctx),
            pk: pending.pk,
            url: pending.url,
            owner: pending.owner,
        };
        let partial_server_id = object::id(&partial_server);
        
        // Receive the key server cap to access the key server
        let key_server_cap_obj = transfer::public_receive(&mut committee.id, key_server_cap);
        let key_server = wrapper::get_mut(key_server_wrapper, &key_server_cap_obj);
        let v2: &mut KeyServerV2 = df::borrow_mut(&mut key_server.id, 2);
        v2.partial_servers.push_back(partial_server_id);
        
        // Transfer partial server to its owner
        transfer::transfer(partial_server, pending.owner);
        
        // Transfer the key server cap back to the committee
        wrapper::transfer_cap(key_server_cap_obj, object::id_address(committee));
        
        // Reset votes
        committee.votes = vec_set::empty();
    }
}

/// Owner updates the URL of their partial key server
public fun update_partial_key_server_url(
    partial_server: &mut PartialKeyServer,
    new_url: String,
    ctx: &mut TxContext,
) {
    assert!(tx_context::sender(ctx) == partial_server.owner, ENotKeyServerOwner);
    partial_server.url = new_url;
}

/// Transfer ownership of a partial key server
public fun transfer_partial_key_server_ownership(
    partial_server: &mut PartialKeyServer,
    new_owner: address,
    ctx: &mut TxContext,
) {
    assert!(tx_context::sender(ctx) == partial_server.owner, ENotKeyServerOwner);
    partial_server.owner = new_owner;
}

/// Get partial key server info (public function)
public fun get_partial_key_server_info(
    partial_server: &PartialKeyServer,
): (vector<u8>, String, address) {
    (partial_server.pk, partial_server.url, partial_server.owner)
}

/// Committee rotates to a new committee
public fun rotate_committee(
    old_committee_wrapper: &mut Wrapper<Committee>,
    member_cap: &Cap,
    key_server_cap: transfer::Receiving<Cap>,
    new_members: vector<address>,
    new_threshold: u8,
    ctx: &mut TxContext,
): ID {
    let old_committee = wrapper::get_mut(old_committee_wrapper, member_cap);
    
    // Verify sender is a member
    let sender = tx_context::sender(ctx);
    assert!(old_committee.members.contains(&sender), EInvalidCommittee);
    assert!(old_committee.is_active, ECommitteeNotActive);
    
    // Deactivate old committee
    old_committee.is_active = false;
    
    // Receive the key server cap from old committee
    let key_server_cap_obj = transfer::public_receive(&mut old_committee.id, key_server_cap);
    
    // Create new committee
    let mut new_committee = Committee {
        id: object::new(ctx),
        threshold: new_threshold,
        members: vec_set::from_keys(new_members),
        is_active: true,
        key_server_wrapper_id: old_committee.key_server_wrapper_id,
        pending_partial_server: option::none(),
        votes: vec_set::empty(),
    };
    
    // Transfer the key server cap to new committee
    wrapper::transfer_cap(key_server_cap_obj, object::id_address(&new_committee));
    
    // Wrap and share new committee
    let (new_committee_wrapper, new_committee_cap) = wrapper::wrap(new_committee, ctx);
    
    // Get ID before sharing
    let new_committee_wrapper_id = object::id(&new_committee_wrapper);
    
    // Share the wrapper
    wrapper::share_wrapper(new_committee_wrapper);
    
    // Transfer the committee cap to sender
    wrapper::transfer_cap(new_committee_cap, tx_context::sender(ctx));
    
    new_committee_wrapper_id
}

/// Get key server info (requires committee member cap)
public fun get_key_server_info_v2(
    committee_wrapper: &mut Wrapper<Committee>,
    member_cap: &Cap,
    key_server_wrapper: &Wrapper<KeyServer>,
    key_server_cap: transfer::Receiving<Cap>,
): (String, u8, u8, vector<ID>) {
    let committee = wrapper::get_mut(committee_wrapper, member_cap);
    
    // Receive the key server cap to access the key server
    let key_server_cap_obj = transfer::public_receive(&mut committee.id, key_server_cap);
    let key_server = wrapper::get(key_server_wrapper, &key_server_cap_obj);
    
    let v2: &KeyServerV2 = df::borrow(&key_server.id, 2);
    
    // Store the result before transferring the cap back
    let name = v2.name;
    let key_type = v2.key_type;
    let threshold = v2.threshold;
    let partial_servers = v2.partial_servers;
    
    // Transfer the key server cap back to the committee
    wrapper::transfer_cap(key_server_cap_obj, object::id_address(committee));
    
    (name, key_type, threshold, partial_servers)
}

/// Check if a key server is V1 or V2
public fun is_v1(s: &KeyServer): bool {
    df::exists_(&s.id, 1)
}

public fun is_v2(s: &KeyServer): bool {
    df::exists_(&s.id, 2)
}

/// Get the first version of key server
public fun first_version(s: &KeyServer): u64 {
    s.first_version
}

/// Get the last version of key server  
public fun last_version(s: &KeyServer): u64 {
    s.last_version
}

// ===== Test functions =====

#[test_only]
public fun destroy_for_testing(v: KeyServer) {
    let KeyServer { id, .. } = v;
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
    create_v1(
        string::utf8(b"mysten"),
        string::utf8(b"https::/mysten-labs.com"),
        0,
        pk_bytes,
        ctx(&mut scenario),
    );
    next_tx(&mut scenario, addr1);

    let mut s: KeyServer = scenario.take_from_sender();
    assert!(name(&s) == string::utf8(b"mysten"), 0);
    assert!(url(&s) == string::utf8(b"https::/mysten-labs.com"), 0);
    assert!(pk(&s) == pk.bytes(), 0);
    s.update(string::utf8(b"https::/mysten-labs2.com"));
    assert!(url(&s) == string::utf8(b"https::/mysten-labs2.com"), 0);

    destroy_for_testing(s);
    test_scenario::end(scenario);
}