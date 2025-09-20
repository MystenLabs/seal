// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module committee::committee;

use std::string::String;
use sui::dynamic_field as df;
use sui::vec_set;
use seal::key_server::{Self, KeyServer};
use sui::transfer::Receiving;

// ===== Errors =====
const ENotMember: u64 = 0;
const EDuplicateMember: u64 = 1;
const EInvalidThreshold: u64 = 2;
const ENotCandidate: u64 = 3;
const EAlreadyApproved: u64 = 4;
const EInvalidPartialPks: u64 = 6;
const EAlreadyRegistered: u64 = 8;
const EInvalidState: u64 = 10;
const ENotFinalized: u64 = 11;
// ===== Structs =====

/// Candidate data for a member to register before dkg.
public struct CandidateData has store, drop {
    enc_pk: vector<u8>,
    signing_pk: vector<u8>,
}

public enum State has store, drop {
    Init,
    PreDKG,
    PostDKG {
        approvals: vector<address>,
        partial_pks: vector<vector<u8>>,
        pk: vector<u8>,
    },
    Finalized
}

/// MPC committee with defined threshold and members. The state is an enum
/// in different stages.
public struct Committee has key {
    id: UID,
    threshold: u16,
    members: vector<address>, // party id is the index of this vector
    state: State,
    /// For rotation: reference to old committee and old threshold
    old_committee_id: Option<ID>,
    old_threshold: Option<u16>,
}


// ===== Functions =====

/// Create a committee for fresh DKG
public fun init_committee(
    threshold: u16,
    members: vector<address>,
    ctx: &mut TxContext,
) {
    assert!(threshold > 0, EInvalidThreshold);
    assert!(members.length() >= threshold as u64, EInvalidThreshold);

    let member_set = vec_set::from_keys(members);
    assert!(vec_set::size(&member_set) == members.length(), EDuplicateMember);

    transfer::share_object(Committee {
        id: object::new(ctx),
        threshold,
        members,
        state: State::Init,
        old_committee_id: option::none(),
        old_threshold: option::none(),
    });
}

/// Create a committee for rotation from an existing finalized committee
public fun init_committee_for_rotation(
    threshold: u16,
    members: vector<address>,
    old_committee: &Committee,
    ctx: &mut TxContext,
) {
    assert!(threshold > 0, EInvalidThreshold);
    assert!(members.length() >= threshold as u64, EInvalidThreshold);

    let member_set = vec_set::from_keys(members);
    assert!(vec_set::size(&member_set) == members.length(), EDuplicateMember);

    // Verify old committee is finalized for rotation
    assert!(match (&old_committee.state) {
        State::Finalized => true,
        _ => false,
    }, ENotFinalized);

    transfer::share_object(Committee {
        id: object::new(ctx),
        threshold,
        members,
        state: State::Init,
        old_committee_id: option::some(object::id(old_committee)),
        old_threshold: option::some(old_committee.threshold),
    });
}

/// Register as a candidate with ecies pk and signing pk. Transition state to PreDKG if not already.
public fun register(
    enc_pk: vector<u8>,
    signing_pk: vector<u8>,
    committee: &mut Committee,
    ctx: &mut TxContext,
) {
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    let sender = ctx.sender();
    match (&committee.state) {
        State::Init => {
            // Transition from Init to PreDKG
            committee.state = State::PreDKG;
            // Store candidate data as dynamic field
            df::add(&mut committee.id, sender, CandidateData { enc_pk, signing_pk });
        },
        State::PreDKG => {
            // Already in PreDKG, just add the candidate
            assert!(!df::exists_(&committee.id, sender), EAlreadyRegistered);
            df::add(&mut committee.id, sender, CandidateData { enc_pk, signing_pk });
        },
        _ => abort EInvalidState
    }
}

/// Propose a committee with partial pks and master pk after DKG
public fun propose(
    committee: &mut Committee,
    partial_pks: vector<vector<u8>>,
    pk: vector<u8>,
    ctx: &mut TxContext,
) {
    assert!(committee.members.contains(&ctx.sender()), ENotCandidate);
    assert!(partial_pks.length() == committee.members.length(), EInvalidPartialPks);

    // For both fresh DKG and rotation, ensure we're in PreDKG state
    assert!(match (&committee.state) {
        State::PreDKG => true,
        _ => false,
    }, EInvalidState);

    committee.state = State::PostDKG { approvals: vector::empty(), partial_pks, pk };
}

/// Propose a rotation committee - all members must register first
public fun propose_for_rotation(
    old_committee: &Committee,
    committee: &mut Committee,
    partial_pks: vector<vector<u8>>,
    ctx: &mut TxContext,
) {
    assert!(committee.members.contains(&ctx.sender()), ENotCandidate);
    assert!(partial_pks.length() == committee.members.length(), EInvalidPartialPks);
    assert!(committee.old_committee_id.is_some(), EInvalidState);
    assert!(object::id(old_committee) == *committee.old_committee_id.borrow(), EInvalidState);

    // Ensure we're in PreDKG state (all members must have registered)
    assert!(match (&committee.state) {
        State::PreDKG => true,
        _ => false,
    }, EInvalidState);

    // Ensure old committee is finalized
    assert!(match (&old_committee.state) {
        State::Finalized => true,
        _ => false,
    }, ENotFinalized);

    // Master pk is preserved from KeyServer during rotation, use empty vector as placeholder
    committee.state = State::PostDKG { approvals: vector::empty(), partial_pks, pk: vector::empty() };
}

/// Approve the proposed committee after checking all partial pks and key server pk
/// matches with the member's dkg finalization locally. This can be called by any 
/// members of committee.
public fun approve_committee(
    committee: &mut Committee,
    ctx: &mut TxContext,
) {
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    match (&mut committee.state) {
        State::PostDKG { approvals, .. } => {
            assert!(!approvals.contains(&ctx.sender()), EAlreadyApproved);
            approvals.push_back(ctx.sender());
        },
        _ => {
            assert!(false, EInvalidState);
        }
    }
}

/// Finalize the committee - creates new KeyServer for fresh DKG
public fun finalize_committee(
    committee: &mut Committee,
    ctx: &mut TxContext,
) {
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    assert!(committee.old_committee_id.is_none(), EInvalidState); // Only for fresh DKG

    match (&committee.state) {
        State::PostDKG { approvals, partial_pks, pk } => {
            assert!(approvals.length() >= committee.threshold as u64, EInvalidThreshold);

            // Fresh DKG - create new KeyServer
            let mut key_server = key_server::create_committee_v2(
                committee.id.to_address().to_string(),
                committee.threshold,
                *pk,
                ctx,
            );

            key_server::add_all_partial_key_servers(
                &mut key_server,
                &committee.members,
                partial_pks,
                ctx,
            );

            // Transfer the key server object to the Committee object via TTO
            transfer::public_transfer(key_server, committee.id.to_address());
            committee.state = State::Finalized;
        },
        _ => abort EInvalidState
    }
}

/// Finalize rotation - transfers KeyServer from old committee and destroys the old committee
public fun finalize_committee_for_rotation(
    committee: &mut Committee,
    mut old_committee: Committee,  // Pass by value to destroy it
    key_server: Receiving<KeyServer>,
    ctx: &mut TxContext,
) {
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    assert!(committee.old_committee_id.is_some(), EInvalidState);
    assert!(object::id(&old_committee) == *committee.old_committee_id.borrow(), EInvalidState);

    // Verify old committee is finalized
    assert!(match (&old_committee.state) {
        State::Finalized => true,
        _ => false,
    }, ENotFinalized);

    match (&committee.state) {
        State::PostDKG { approvals, partial_pks, pk: _pk } => {
            assert!(approvals.length() >= committee.threshold as u64, EInvalidThreshold);

            // Receive the KeyServer from old committee
            let mut key_server = transfer::public_receive(&mut old_committee.id, key_server);

            // Remove all old partial key servers
            let mut i = 0;
            while (i < old_committee.members.length()) {
                key_server::remove_partial_key_server(&mut key_server, old_committee.members[i]);
                i = i + 1;
            };

            // Add partial key servers with new pks
            let mut j = 0;
            while (j < committee.members.length()) {
                key_server::add_partial_key_server(
                    &mut key_server,
                    committee.members[j],
                    partial_pks[j],
                    ctx,
                );
                j = j + 1;
            };

            // Transfer KeyServer to new committee
            transfer::public_transfer(key_server, committee.id.to_address());

            // Finalize new committee (master pk is preserved in KeyServer)
            committee.state = State::Finalized;

            // Destroy old committee
            let Committee { id, threshold: _, members: _, state: _, old_committee_id: _, old_threshold: _ } = old_committee;
            object::delete(id);
        },
        _ => abort EInvalidState
    }
}

/// Update the url of the key server object. Only the 
public fun update_url(
    ks: Receiving<KeyServer>,
    committee: &mut Committee,
    url: String,
    ctx: &mut TxContext,
) {
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    let mut key_server = transfer::public_receive(&mut committee.id, ks);
    key_server::update_url(&mut key_server, url, ctx);
    transfer::public_transfer(key_server, committee.id.to_address());
}

#[test]
fun test_committee_rotation_2of3_to_3of4() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    let ctx = scenario.ctx();

    // Create initial 2-of-3 committee.
    // Members: @0x0, @0x1, @0x2, Threshold: 2
    init_committee(2, vector[@0x0, @0x1, @0x2], ctx);

    // Register all 3 members
    scenario.next_tx(@0x0);
    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_0", b"signing_pk_0", &mut committee, scenario.ctx());
    test_scenario::return_shared(committee);

    scenario.next_tx(@0x1);
    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_1", b"signing_pk_1", &mut committee, scenario.ctx());
    test_scenario::return_shared(committee);

    scenario.next_tx(@0x2);
    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_2", b"signing_pk_2", &mut committee, scenario.ctx());

    // DKG is done offline, member @0x03 proposes a committee with partial keys and master pk. 
    let partial_pks = vector[b"partial_pk_0", b"partial_pk_1", b"partial_pk_2"];
    let master_pk = b"master_public_key_2of3";
    propose(&mut committee, partial_pks, master_pk, scenario.ctx());
    test_scenario::return_shared(committee);

    // Approve it by 2 members. 
    scenario.next_tx(@0x1);
    let mut committee = scenario.take_shared<Committee>();
    approve_committee(&mut committee, scenario.ctx());
    scenario.next_tx(@0x2);
    approve_committee(&mut committee, scenario.ctx());

    // A member finalizes it. 
    finalize_committee(&mut committee, scenario.ctx());
    let old_committee_id = object::id(&committee);
    test_scenario::return_shared(committee);

    // Initialize rotation to 3-of-4 committee. 
    // Old committee (2-of-3): @0x0=party0, @0x1=party1, @0x2=party2
    // New committee (3-of-4): @0x1=party0, @0x0=party1, @0x3=party3, @0x4=party4
    // party 0 and party 1 are continuing members, swapped. 
    scenario.next_tx(@0x1);
    let old_committee = scenario.take_shared_by_id<Committee>(old_committee_id);
    init_committee_for_rotation(
        3,  // New threshold
        vector[@0x1, @0x0, @0x3, @0x4],  // @0x0 and @0x1 continue but swap positions
        &old_committee,
        scenario.ctx()
    );
    test_scenario::return_shared(old_committee);

    // Get the new and old committee shared obj.
    scenario.next_tx(@0x1);
    let committee1 = scenario.take_shared<Committee>();
    let mut new_committee;
    let new_committee_id;
    if (committee1.old_committee_id.is_some()) {
        new_committee = committee1;
        new_committee_id = object::id(&new_committee);
    } else {
        test_scenario::return_shared(committee1);
        new_committee = scenario.take_shared<Committee>();
        new_committee_id = object::id(&new_committee);
    };

    // Check new committee init state. 
    assert!(new_committee.old_committee_id == option::some(old_committee_id), 0);
    assert!(new_committee.old_threshold == option::some(2), 1);
    assert!(new_committee.threshold == 3, 2);
    assert!(new_committee.members.length() == 4, 3);
    assert!(match (&new_committee.state) {
        State::Init => true,
        _ => false,
    }, 32);

    // Register all 4 members. 
    scenario.next_tx(@0x0);
    register(b"enc_pk_0", b"signing_pk_0", &mut new_committee, scenario.ctx());
    test_scenario::return_shared(new_committee);

    scenario.next_tx(@0x1);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    register(b"enc_pk_1", b"signing_pk_1", &mut new_committee, scenario.ctx());
    test_scenario::return_shared(new_committee);

    scenario.next_tx(@0x3);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    register(b"enc_pk_3", b"signing_pk_3", &mut new_committee, scenario.ctx());
    test_scenario::return_shared(new_committee);

    scenario.next_tx(@0x4);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    register(b"enc_pk_4", b"signing_pk_4", &mut new_committee, scenario.ctx());

    // Verify committee PreDKG state
    assert!(match (&new_committee.state) {
        State::PreDKG => true,
        _ => false,
    }, 34);
    assert!(df::exists_(&new_committee.id, @0x0), 35);
    assert!(df::exists_(&new_committee.id, @0x1), 36);
    assert!(df::exists_(&new_committee.id, @0x3), 37);
    assert!(df::exists_(&new_committee.id, @0x4), 38);
    test_scenario::return_shared(new_committee);

    scenario.next_tx(@0x1);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    let old_committee = scenario.take_shared_by_id<Committee>(old_committee_id);

    // New partial pks for all 4 members (order matches new committee member order)
    let new_partial_pks = vector[
        b"new_partial_pk_1",  // @0x1
        b"new_partial_pk_0",  // @0x0 
        b"new_partial_pk_3",  // @0x3 
        b"new_partial_pk_4"   // @0x4 
    ];

    // Propose rotation with all partial pks. 
    propose_for_rotation(
        &old_committee,
        &mut new_committee,
        new_partial_pks,
        scenario.ctx()
    );

    // Verify PostDKG state. 
    assert!(match (&new_committee.state) {
        State::PostDKG { approvals: _, partial_pks: _, pk: _ } => true,
        _ => false,
    }, 33);

    test_scenario::return_shared(old_committee);
    test_scenario::return_shared(new_committee);

    // 5. Approve new committee by 3 members
    scenario.next_tx(@0x0);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    approve_committee(&mut new_committee, scenario.ctx());
    test_scenario::return_shared(new_committee);

    scenario.next_tx(@0x3);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    approve_committee(&mut new_committee, scenario.ctx());
    test_scenario::return_shared(new_committee);

    scenario.next_tx(@0x4);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    approve_committee(&mut new_committee, scenario.ctx());
    test_scenario::return_shared(new_committee);

    // Finalize committee
    scenario.next_tx(@0x1);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    let old_committee = scenario.take_shared_by_id<Committee>(old_committee_id);

    // Get the KeyServer from old committee
    let ks_ticket = test_scenario::most_recent_receiving_ticket<KeyServer>(&old_committee_id);

    finalize_committee_for_rotation(
        &mut new_committee,
        old_committee,  // Will be destroyed
        ks_ticket,
        scenario.ctx()
    );

    // Verify new committee finalized state.
    assert!(match (&new_committee.state) {
        State::Finalized => true,
        _ => false,
    }, 8);
    assert!(new_committee.threshold == 3, 9);
    assert!(new_committee.members == vector[@0x1, @0x0, @0x3, @0x4], 10);
    test_scenario::return_shared(new_committee);

    // ===== Phase 7: Verify key server and all partial PKs after rotation =====
    scenario.next_tx(@0x1);
    let ks_ticket_new = test_scenario::most_recent_receiving_ticket<KeyServer>(&new_committee_id);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    let key_server = transfer::public_receive(&mut new_committee.id, ks_ticket_new);

    // Verify master public key is preserved during rotation
    assert!(key_server::pk(&key_server) == &master_pk, 31);

    // Verify all partial key servers have correct PKs
    // @0x1 (continuing member, at index 0 in new committee)
    let pks1 = key_server::get_partial_key_server(&key_server, @0x1);
    assert!(key_server::partial_key_server_pk(pks1) == b"new_partial_pk_1", 22);

    // @0x0 (continuing member, at index 1 in new committee)
    let pks0 = key_server::get_partial_key_server(&key_server, @0x0);
    assert!(key_server::partial_key_server_pk(pks0) == b"new_partial_pk_0", 23);

    // @0x2 (removed member, should NOT have partial key server)
    assert!(!key_server::has_partial_key_server(&key_server, @0x2), 15);

    // @0x3 (new member, at index 2 in new committee)
    let pks3 = key_server::get_partial_key_server(&key_server, @0x3);
    assert!(key_server::partial_key_server_pk(pks3) == b"new_partial_pk_3", 20);

    // @0x4 (new member, at index 3 in new committee)
    let pks4 = key_server::get_partial_key_server(&key_server, @0x4);
    assert!(key_server::partial_key_server_pk(pks4) == b"new_partial_pk_4", 21);

    // Return the KeyServer back to the committee
    transfer::public_transfer(key_server, new_committee.id.to_address());
    test_scenario::return_shared(new_committee);

    scenario.end();
}

#[test]
#[expected_failure(abort_code = EAlreadyRegistered)]
fun test_register_fails_when_already_registered() {
    use sui::test_scenario;
    
    let mut scenario = test_scenario::begin(@0x1);
    
    init_committee(2, vector[@0x1, @0x2], scenario.ctx());
    scenario.next_tx(@0x1);
    
    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_1", b"signing_pk_1", &mut committee, scenario.ctx());
    
    // Try to register again - should fail with EAlreadyRegistered
    register(b"enc_pk_2", b"signing_pk_2", &mut committee, scenario.ctx());
    
    test_scenario::return_shared(committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = EInvalidThreshold)]
fun test_finalize_committee_fails_without_threshold() {
    use sui::test_scenario;
    
    let mut scenario = test_scenario::begin(@0x1);
    let ctx = scenario.ctx();
    
    // Create committee with threshold 3 and 3 members
    init_committee(3, vector[@0x1, @0x2, @0x3], ctx);
    scenario.next_tx(@0x1);
    
    // Register 3 members
    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_1", b"signing_pk_1", &mut committee, scenario.ctx());
    test_scenario::return_shared(committee);
    scenario.next_tx(@0x2);
    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_2", b"signing_pk_2", &mut committee, scenario.ctx());
    test_scenario::return_shared(committee);
    scenario.next_tx(@0x3);
    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_3", b"signing_pk_3", &mut committee, scenario.ctx());
    
    // Propose committee with partial keys and full pk
    scenario.next_tx(@0x1);
    let partial_pks = vector[b"partial_pk_1", b"partial_pk_2", b"partial_pk_3"];
    let pk = b"full_public_key";
    propose(&mut committee, partial_pks, pk, scenario.ctx());
    test_scenario::return_shared(committee);
    
    // Approve committee by only 2 members (less than threshold of 3)
    scenario.next_tx(@0x1);
    let mut committee = scenario.take_shared<Committee>();
    approve_committee(&mut committee, scenario.ctx());
    scenario.next_tx(@0x2);
    approve_committee(&mut committee, scenario.ctx());
    // Note: Not approving with the third member
    
    // Try to finalize committee - this should fail
    scenario.next_tx(@0x1);
    finalize_committee(&mut committee, scenario.ctx()); // Should abort with EInvalidThreshold
    
    test_scenario::return_shared(committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = ENotFinalized)]
fun test_rotation_fails_from_non_finalized_committee() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);

    // Create committee but don't finalize it
    init_committee(2, vector[@0x1, @0x2], scenario.ctx());
    scenario.next_tx(@0x1);

    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_1", b"signing_pk_1", &mut committee, scenario.ctx());

    // Try to rotate from non-finalized committee - should fail
    init_committee_for_rotation(
        2,
        vector[@0x1, @0x3],
        &committee,
        scenario.ctx()
    );

    test_scenario::return_shared(committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = EInvalidThreshold)]
fun test_rotation_fails_with_invalid_threshold() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);

    // Create, register, and finalize a basic committee
    init_committee(1, vector[@0x1], scenario.ctx());
    scenario.next_tx(@0x1);

    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_1", b"signing_pk_1", &mut committee, scenario.ctx());
    propose(&mut committee, vector[b"pk_1"], b"master", scenario.ctx());
    approve_committee(&mut committee, scenario.ctx());
    finalize_committee(&mut committee, scenario.ctx());

    // Try to rotate with threshold exceeding members - should fail
    init_committee_for_rotation(
        3,  // threshold > 2 members
        vector[@0x1, @0x2],
        &committee,
        scenario.ctx()
    );

    test_scenario::return_shared(committee);
    scenario.end();
}