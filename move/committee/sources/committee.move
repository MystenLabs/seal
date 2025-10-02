// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Implementation of committee based key server operations. Each committee should deploy this package itself,
/// so that the committee can manage its own upgrade and the key rotation. The key server object is owned by
/// the committee.
module committee::committee;

use seal_testnet::key_server::{Self, KeyServer};
use std::string::String;
use sui::{dynamic_field as df, transfer::Receiving, vec_set::{Self, VecSet}};

// ===== Errors =====
const ENotMember: u64 = 0;
const EDuplicateMember: u64 = 1;
const EInvalidThreshold: u64 = 2;
const EAlreadyApproved: u64 = 4;
const EInvalidProposal: u64 = 5;
const EAlreadyRegistered: u64 = 6;
const EInvalidState: u64 = 7;
const ENotFinalized: u64 = 8;
const EInsufficientApprovals: u64 = 9;
const EInsufficientOldMembers: u64 = 10;

// ===== Structs =====

/// Candidate data for a member to register before dkg.
public struct CandidateData has drop, store {
    enc_pk: vector<u8>,
    signing_pk: vector<u8>,
    url: String,
}

public enum State has drop, store {
    Init,
    PreDKG,
    PostDKG {
        approvals: VecSet<address>,
        partial_pks: vector<vector<u8>>,
        pk: option::Option<vector<u8>>, // Needed for dkg init, not needed for rotation
    },
    Finalized,
}

/// MPC committee with defined threshold and members. The state is an enum
/// in different stages.
public struct Committee has key {
    id: UID,
    threshold: u16,
    members: vector<address>, // 'party id' used in the dkg protocols is the index of this vector
    state: State,
    // For rotation: reference to old committee
    old_committee_id: Option<ID>,
}

// ===== Functions =====

/// Create a committee for fresh DKG with a list of members and threshold.
public fun init_committee(threshold: u16, members: vector<address>, ctx: &mut TxContext) {
    assert!(threshold > 0, EInvalidThreshold);
    assert!(members.length() >= threshold as u64, EInvalidThreshold);

    let member_set = vec_set::from_keys(members);
    assert!(vec_set::length(&member_set) == members.length(), EDuplicateMember);

    transfer::share_object(Committee {
        id: object::new(ctx),
        threshold,
        members,
        state: State::Init,
        old_committee_id: option::none(),
    });
}

/// Create a committee for rotation from an existing finalized old committee.
public fun init_committee_for_rotation(
    threshold: u16,
    members: vector<address>,
    old_committee: &Committee,
    ctx: &mut TxContext,
) {
    assert!(threshold > 0, EInvalidThreshold);
    assert!(members.length() >= threshold as u64, EInvalidThreshold);

    let member_set = vec_set::from_keys(members);
    assert!(vec_set::length(&member_set) == members.length(), EDuplicateMember);

    // Verify old committee is finalized for rotation.
    assert!(
        match (&old_committee.state) {
            State::Finalized => true,
            _ => false,
        },
        ENotFinalized,
    );

    // Check that new committee has at least threshold of old committee members
    let mut old_members_count: u64 = 0;
    let mut i = 0;
    while (i < members.length()) {
        if (old_committee.members.contains(&members[i])) {
            old_members_count = old_members_count + 1;
        };
        i = i + 1;
    };
    assert!(old_members_count >= (old_committee.threshold as u64), EInsufficientOldMembers);

    transfer::share_object(Committee {
        id: object::new(ctx),
        threshold,
        members,
        state: State::Init,
        old_committee_id: option::some(object::id(old_committee)),
    });
}

/// Register as a candidate with ecies pk and signing pk to candidates
/// list. Transition state to PreDKG if not already.
public fun register(
    enc_pk: vector<u8>,
    signing_pk: vector<u8>,
    url: String,
    committee: &mut Committee,
    ctx: &mut TxContext,
) {
    // todo: add checks for enc_pk, signing_pk to be valid element, maybe PoP
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    let sender = ctx.sender();
    match (&committee.state) {
        State::Init => {
            // Transition from Init to PreDKG
            committee.state = State::PreDKG;
            // Store candidate data as dynamic field
            df::add(&mut committee.id, sender, CandidateData { enc_pk, signing_pk, url });
        },
        State::PreDKG => {
            // Already in PreDKG, just add the candidate
            assert!(!df::exists_(&committee.id, sender), EAlreadyRegistered);
            df::add(&mut committee.id, sender, CandidateData { enc_pk, signing_pk, url });
        },
        _ => abort EInvalidState,
    }
}

/// Propose a committee with partial pks and master pk after DKG.
/// Add the caller to approvals list. If already in PostDKG state,
/// check the submitted partial_pks and pk are consistent with the
/// onchain state, then add the caller to approvals list.
public fun propose(
    committee: &mut Committee,
    partial_pks: vector<vector<u8>>,
    pk: vector<u8>,
    ctx: &mut TxContext,
) {
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    assert!(partial_pks.length() == committee.members.length(), EInvalidProposal);

    match (&mut committee.state) {
        State::PreDKG => {
            // Ensure all members have registered
            let mut i = 0;
            while (i < committee.members.length()) {
                assert!(df::exists_(&committee.id, committee.members[i]), ENotMember);
                i = i + 1;
            };

            committee.state =
                State::PostDKG {
                    approvals: vec_set::singleton(ctx.sender()),
                    partial_pks,
                    pk: option::some(pk),
                };
        },
        State::PostDKG { approvals, partial_pks: existing_partial_pks, pk: existing_pk } => {
            // Check that submitted partial_pks and pk are consistent
            assert!(partial_pks == *existing_partial_pks, EInvalidProposal);
            let pk_value = option::borrow(existing_pk);
            assert!(pk == *pk_value, EInvalidProposal);
            assert!(!vec_set::contains(approvals, &ctx.sender()), EAlreadyApproved);
            vec_set::insert(approvals, ctx.sender());
        },
        _ => abort EInvalidState,
    }
}

/// Propose a rotation from old committee to new one with a list of partial pks.
/// Add the caller to approvals list. If already in PostDKG state, checks that
/// submitted partial_pks are consistent with the onchain state, then add the
/// caller to approvals list.
public fun propose_for_rotation(
    old_committee: &Committee,
    committee: &mut Committee,
    partial_pks: vector<vector<u8>>,
    ctx: &mut TxContext,
) {
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    assert!(partial_pks.length() == committee.members.length(), EInvalidProposal);
    assert!(committee.old_committee_id.is_some(), EInvalidState);
    assert!(object::id(old_committee) == *committee.old_committee_id.borrow(), EInvalidState);

    // Ensure old committee is finalized
    assert!(
        match (&old_committee.state) {
            State::Finalized => true,
            _ => false,
        },
        ENotFinalized,
    );

    match (&mut committee.state) {
        State::PreDKG => {
            // Ensure all members have registered
            let mut i = 0;
            while (i < committee.members.length()) {
                assert!(df::exists_(&committee.id, committee.members[i]), ENotMember);
                i = i + 1;
            };
            committee.state =
                State::PostDKG {
                    approvals: vec_set::singleton(ctx.sender()),
                    partial_pks,
                    pk: option::none(),
                };
        },
        State::PostDKG { approvals, partial_pks: existing_partial_pks, .. } => {
            // Check that partial_pks are consistent
            assert!(partial_pks == *existing_partial_pks, EInvalidProposal);
            assert!(!vec_set::contains(approvals, &ctx.sender()), EAlreadyApproved);
            vec_set::insert(approvals, ctx.sender());
        },
        _ => abort EInvalidState,
    }
}

/// Finalize the committee, creates new KeyServer for fresh DKG
public fun finalize_committee(committee: &mut Committee, ctx: &mut TxContext) {
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    assert!(committee.old_committee_id.is_none(), EInvalidState); // Only for fresh DKG

    match (&committee.state) {
        State::PostDKG { approvals, partial_pks, pk: some_pk } => {
            assert!(
                vec_set::length(approvals) == committee.members.length(),
                EInsufficientApprovals,
            );
            assert!(some_pk.is_some(), EInvalidState);
            assert!(partial_pks.length() == committee.members.length(), EInvalidProposal);

            // Fresh DKG - create new KeyServer
            let mut key_server = key_server::create_committee_v2(
                committee.id.to_address().to_string(),
                committee.threshold,
                *option::borrow(some_pk),
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
        _ => abort EInvalidState,
    }
}

/// Finalize rotation for the committe. Transfer the KeyServer from old
/// committee to the new committee and destroys the old committee object.
/// Add all new partial key server as df to key server.
public fun finalize_committee_for_rotation(
    committee: &mut Committee,
    mut old_committee: Committee,
    key_server: Receiving<KeyServer>,
    ctx: &mut TxContext,
) {
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    assert!(committee.old_committee_id.is_some(), EInvalidState);
    assert!(object::id(&old_committee) == *committee.old_committee_id.borrow(), EInvalidState);

    // Verify old committee is finalized
    assert!(
        match (&old_committee.state) {
            State::Finalized => true,
            _ => false,
        },
        ENotFinalized,
    );

    match (&committee.state) {
        State::PostDKG { approvals, partial_pks, pk: some_pk } => {
            assert!(
                vec_set::length(approvals) == committee.members.length(),
                EInsufficientApprovals,
            );
            assert!(some_pk.is_none(), EInvalidState);
            assert!(partial_pks.length() == committee.members.length(), EInvalidProposal);
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
                let candidate_data: &CandidateData = df::borrow(
                    &committee.id,
                    committee.members[j],
                );
                key_server::add_partial_key_server(
                    &mut key_server,
                    committee.members[j],
                    partial_pks[j],
                    j as u16,
                    candidate_data.url,
                    ctx,
                );
                j = j + 1;
            };

            // Transfer KeyServer to new committee
            transfer::public_transfer(key_server, committee.id.to_address());

            // Finalize new committee (master pk is preserved in KeyServer)
            committee.state = State::Finalized;

            // Destroy old committee
            let Committee {
                id,
                threshold: _,
                members: _,
                state: _,
                old_committee_id: _,
            } = old_committee;
            object::delete(id);
        },
        _ => abort EInvalidState,
    }
}

/// Update the url of the partial key server object corresponding to the sender.
public fun update_partial_ks_url(
    ks: Receiving<KeyServer>,
    committee: &mut Committee,
    url: String,
    ctx: &mut TxContext,
) {
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    let mut key_server = transfer::public_receive(&mut committee.id, ks);
    key_server::update_partial_ks_url(&mut key_server, url, ctx);
    transfer::public_transfer(key_server, committee.id.to_address());
}

// todo: handle package upgrade with threshold approvals of the committee.

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
    register(
        b"enc_pk_0",
        b"signing_pk_0",
        b"https://url0.com".to_string(),
        &mut committee,
        scenario.ctx(),
    );
    test_scenario::return_shared(committee);

    scenario.next_tx(@0x1);
    let mut committee = scenario.take_shared<Committee>();
    register(
        b"enc_pk_1",
        b"signing_pk_1",
        b"https://url1.com".to_string(),
        &mut committee,
        scenario.ctx(),
    );
    test_scenario::return_shared(committee);

    scenario.next_tx(@0x2);
    let mut committee = scenario.take_shared<Committee>();
    register(
        b"enc_pk_2",
        b"signing_pk_2",
        b"https://url2.com".to_string(),
        &mut committee,
        scenario.ctx(),
    );

    // DKG is done offline, member @0x03 proposes a committee with partial keys and master pk.
    let partial_pks = vector[b"partial_pk_0", b"partial_pk_1", b"partial_pk_2"];
    let master_pk = b"master_public_key_2of3";
    propose(&mut committee, partial_pks, master_pk, scenario.ctx());
    test_scenario::return_shared(committee);

    // Propose with remaining members.
    scenario.next_tx(@0x1);
    let mut committee = scenario.take_shared<Committee>();
    propose(&mut committee, partial_pks, master_pk, scenario.ctx());

    scenario.next_tx(@0x0);
    propose(&mut committee, partial_pks, master_pk, scenario.ctx());

    // A member finalizes it.
    finalize_committee(&mut committee, scenario.ctx());
    assert!(
        match (&committee.state) {
            State::Finalized => true,
            _ => false,
        },
        0,
    );
    let old_committee_id = object::id(&committee);
    test_scenario::return_shared(committee);

    // Initialize rotation to 3-of-4 committee.
    // Old committee (2-of-3): @0x0=party0, @0x1=party1, @0x2=party2
    // New committee (3-of-4): @0x1=party0, @0x0=party1, @0x3=party3, @0x4=party4
    // party 0 and party 1 are continuing members, swapped.
    scenario.next_tx(@0x1);
    let old_committee = scenario.take_shared_by_id<Committee>(old_committee_id);
    init_committee_for_rotation(
        3, // New threshold
        vector[@0x1, @0x0, @0x3, @0x4], // @0x0 and @0x1 continue but swap positions
        &old_committee,
        scenario.ctx(),
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
    assert!(new_committee.threshold == 3, 2);
    assert!(new_committee.members.length() == 4, 3);
    assert!(
        match (&new_committee.state) {
            State::Init => true,
            _ => false,
        },
        32,
    );

    // Register all 4 members.
    scenario.next_tx(@0x0);
    register(
        b"enc_pk_0",
        b"signing_pk_0",
        b"https://new_url0.com".to_string(),
        &mut new_committee,
        scenario.ctx(),
    );
    test_scenario::return_shared(new_committee);

    scenario.next_tx(@0x1);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    register(
        b"enc_pk_1",
        b"signing_pk_1",
        b"https://new_url1.com".to_string(),
        &mut new_committee,
        scenario.ctx(),
    );
    test_scenario::return_shared(new_committee);

    scenario.next_tx(@0x3);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    register(
        b"enc_pk_3",
        b"signing_pk_3",
        b"https://new_url3.com".to_string(),
        &mut new_committee,
        scenario.ctx(),
    );
    test_scenario::return_shared(new_committee);

    scenario.next_tx(@0x4);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    register(
        b"enc_pk_4",
        b"signing_pk_4",
        b"https://new_url4.com".to_string(),
        &mut new_committee,
        scenario.ctx(),
    );

    // Verify committee PreDKG state
    assert!(
        match (&new_committee.state) {
            State::PreDKG => true,
            _ => false,
        },
        34,
    );
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
        b"new_partial_pk_1", // @0x1
        b"new_partial_pk_0", // @0x0
        b"new_partial_pk_3", // @0x3
        b"new_partial_pk_4", // @0x4
    ];

    // Propose rotation with all partial pks.
    propose_for_rotation(
        &old_committee,
        &mut new_committee,
        new_partial_pks,
        scenario.ctx(),
    );

    // Verify PostDKG state.
    assert!(
        match (&new_committee.state) {
            State::PostDKG { approvals: _, partial_pks: _, pk: _ } => true,
            _ => false,
        },
        33,
    );

    test_scenario::return_shared(old_committee);
    test_scenario::return_shared(new_committee);

    // Approve new committee by remaining 3 members using propose_for_rotation
    scenario.next_tx(@0x0);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    let old_committee = scenario.take_shared_by_id<Committee>(old_committee_id);
    propose_for_rotation(&old_committee, &mut new_committee, new_partial_pks, scenario.ctx());
    test_scenario::return_shared(old_committee);
    test_scenario::return_shared(new_committee);

    scenario.next_tx(@0x3);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    let old_committee = scenario.take_shared_by_id<Committee>(old_committee_id);
    propose_for_rotation(&old_committee, &mut new_committee, new_partial_pks, scenario.ctx());
    test_scenario::return_shared(old_committee);
    test_scenario::return_shared(new_committee);

    scenario.next_tx(@0x4);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    let old_committee = scenario.take_shared_by_id<Committee>(old_committee_id);
    propose_for_rotation(&old_committee, &mut new_committee, new_partial_pks, scenario.ctx());
    test_scenario::return_shared(old_committee);
    test_scenario::return_shared(new_committee);

    // Finalize committee
    scenario.next_tx(@0x1);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    let old_committee = scenario.take_shared_by_id<Committee>(old_committee_id);

    // Get the KeyServer from old committee
    let ks_ticket = test_scenario::most_recent_receiving_ticket<KeyServer>(&old_committee_id);

    finalize_committee_for_rotation(
        &mut new_committee,
        old_committee, // Will be destroyed
        ks_ticket,
        scenario.ctx(),
    );

    // Verify new committee finalized state.
    assert!(
        match (&new_committee.state) {
            State::Finalized => true,
            _ => false,
        },
        8,
    );
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

    // Verify all partial key servers have correct PKs and URLs
    // @0x1 (continuing member, at index 0 in new committee)
    let pks1 = key_server::get_partial_key_server(&key_server, @0x1);
    assert!(key_server::partial_key_server_pk(pks1) == b"new_partial_pk_1", 22);
    assert!(key_server::partial_key_server_url(pks1) == b"https://new_url1.com".to_string(), 24);

    // @0x0 (continuing member, at index 1 in new committee)
    let pks0 = key_server::get_partial_key_server(&key_server, @0x0);
    assert!(key_server::partial_key_server_pk(pks0) == b"new_partial_pk_0", 23);
    assert!(key_server::partial_key_server_url(pks0) == b"https://new_url0.com".to_string(), 25);

    // @0x2 (removed member, should NOT have partial key server)
    assert!(!key_server::has_partial_key_server(&key_server, @0x2), 15);

    // @0x3 (new member, at index 2 in new committee)
    let pks3 = key_server::get_partial_key_server(&key_server, @0x3);
    assert!(key_server::partial_key_server_pk(pks3) == b"new_partial_pk_3", 20);
    assert!(key_server::partial_key_server_url(pks3) == b"https://new_url3.com".to_string(), 26);

    // @0x4 (new member, at index 3 in new committee)
    let pks4 = key_server::get_partial_key_server(&key_server, @0x4);
    assert!(key_server::partial_key_server_pk(pks4) == b"new_partial_pk_4", 21);
    assert!(key_server::partial_key_server_url(pks4) == b"https://new_url4.com".to_string(), 27);

    // Return the KeyServer back to the committee
    transfer::public_transfer(key_server, new_committee.id.to_address());
    test_scenario::return_shared(new_committee);

    // Test update_partial_ks_url
    scenario.next_tx(@0x1);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    let ks_ticket = test_scenario::most_recent_receiving_ticket<KeyServer>(&new_committee_id);
    update_partial_ks_url(
        ks_ticket,
        &mut new_committee,
        b"https://example.com".to_string(),
        scenario.ctx(),
    );
    test_scenario::return_shared(new_committee);

    scenario.end();
}

#[test]
#[expected_failure(abort_code = ENotMember)]
fun test_update_partial_ks_url_fails_for_non_member() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    let ctx = scenario.ctx();

    // Create initial 2-of-2 committee with @0x1 and @0x2
    init_committee(2, vector[@0x1, @0x2], ctx);

    // Register all members
    scenario.next_tx(@0x1);
    let mut committee = scenario.take_shared<Committee>();
    register(
        b"enc_pk_1",
        b"signing_pk_1",
        b"https://url1.com".to_string(),
        &mut committee,
        scenario.ctx(),
    );
    test_scenario::return_shared(committee);

    scenario.next_tx(@0x2);
    let mut committee = scenario.take_shared<Committee>();
    register(
        b"enc_pk_2",
        b"signing_pk_2",
        b"https://url2.com".to_string(),
        &mut committee,
        scenario.ctx(),
    );

    // Propose and finalize
    let partial_pks = vector[b"partial_pk_1", b"partial_pk_2"];
    let master_pk = b"master_pk";
    propose(&mut committee, partial_pks, master_pk, scenario.ctx());
    test_scenario::return_shared(committee);

    scenario.next_tx(@0x1);
    let mut committee = scenario.take_shared<Committee>();
    propose(&mut committee, partial_pks, master_pk, scenario.ctx());
    finalize_committee(&mut committee, scenario.ctx());
    let committee_id = object::id(&committee);
    test_scenario::return_shared(committee);

    // @0x3 (non-member) tries to update a partial key server URL - should fail with ENotMember
    scenario.next_tx(@0x3);
    let mut committee = scenario.take_shared_by_id<Committee>(committee_id);
    let ks_ticket = test_scenario::most_recent_receiving_ticket<KeyServer>(&committee_id);

    // This should fail because @0x3 is not a committee member
    update_partial_ks_url(
        ks_ticket,
        &mut committee,
        b"https://malicious.com".to_string(),
        scenario.ctx(),
    );

    test_scenario::return_shared(committee);
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
    register(b"enc_pk_1", b"signing_pk_1", b"url1".to_string(), &mut committee, scenario.ctx());

    // Try to register again - should fail with EAlreadyRegistered
    register(b"enc_pk_2", b"signing_pk_2", b"url2".to_string(), &mut committee, scenario.ctx());

    test_scenario::return_shared(committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = EInsufficientApprovals)]
fun test_finalize_committee_fails_without_all_approvals() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    let ctx = scenario.ctx();

    // Create committee with threshold 3 and 3 members
    init_committee(3, vector[@0x1, @0x2, @0x3], ctx);
    scenario.next_tx(@0x1);

    // Register 3 members
    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_1", b"signing_pk_1", b"url1".to_string(), &mut committee, scenario.ctx());
    test_scenario::return_shared(committee);
    scenario.next_tx(@0x2);
    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_2", b"signing_pk_2", b"url2".to_string(), &mut committee, scenario.ctx());
    test_scenario::return_shared(committee);
    scenario.next_tx(@0x3);
    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_3", b"signing_pk_3", b"url3".to_string(), &mut committee, scenario.ctx());

    // Propose committee with partial keys and full pk
    scenario.next_tx(@0x1);
    let partial_pks = vector[b"partial_pk_1", b"partial_pk_2", b"partial_pk_3"];
    let pk = b"full_public_key";
    propose(&mut committee, partial_pks, pk, scenario.ctx());
    test_scenario::return_shared(committee);

    // Approve committee 1 more (but not enough to meet threshold of 3)
    scenario.next_tx(@0x2);
    let mut committee = scenario.take_shared<Committee>();
    propose(&mut committee, partial_pks, pk, scenario.ctx());

    // Try to finalize committee - this should fail with EInsufficientApprovals
    scenario.next_tx(@0x1);
    finalize_committee(&mut committee, scenario.ctx());

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
    register(b"enc_pk_1", b"signing_pk_1", b"url1".to_string(), &mut committee, scenario.ctx());

    // Try to rotate from non-finalized committee - should fail
    init_committee_for_rotation(
        2,
        vector[@0x1, @0x3],
        &committee,
        scenario.ctx(),
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
    register(b"enc_pk_1", b"signing_pk_1", b"url1".to_string(), &mut committee, scenario.ctx());
    propose(&mut committee, vector[b"pk_1"], b"master", scenario.ctx());
    finalize_committee(&mut committee, scenario.ctx());

    // Try to rotate with threshold exceeding members - should fail
    init_committee_for_rotation(
        3, // threshold > 2 members
        vector[@0x1, @0x2],
        &committee,
        scenario.ctx(),
    );

    test_scenario::return_shared(committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = EInvalidProposal)]
fun test_propose_fails_with_wrong_partial_pks_count() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);

    init_committee(2, vector[@0x1, @0x2], scenario.ctx());
    scenario.next_tx(@0x1);

    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_1", b"signing_pk_1", b"url1".to_string(), &mut committee, scenario.ctx());
    test_scenario::return_shared(committee);

    scenario.next_tx(@0x2);
    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_2", b"signing_pk_2", b"url2".to_string(), &mut committee, scenario.ctx());

    // Propose with only 1 partial_pk instead of 2
    let partial_pks = vector[b"partial_pk_1"];
    let pk = b"master_pk";
    propose(&mut committee, partial_pks, pk, scenario.ctx());

    test_scenario::return_shared(committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = ENotMember)]
fun test_register_fails_for_non_member() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);

    init_committee(2, vector[@0x1, @0x2], scenario.ctx());
    scenario.next_tx(@0x3); // @0x3 is not a member

    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_3", b"signing_pk_3", b"url3".to_string(), &mut committee, scenario.ctx());

    test_scenario::return_shared(committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = ENotMember)]
fun test_propose_fails_when_not_all_registered() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);

    init_committee(2, vector[@0x1, @0x2], scenario.ctx());
    scenario.next_tx(@0x1);

    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_1", b"signing_pk_1", b"url1".to_string(), &mut committee, scenario.ctx());

    // Try to propose when @0x2 hasn't registered yet
    let partial_pks = vector[b"partial_pk_1", b"partial_pk_2"];
    let pk = b"master_pk";
    propose(&mut committee, partial_pks, pk, scenario.ctx());

    test_scenario::return_shared(committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = EAlreadyApproved)]
fun test_propose_fails_on_duplicate_approval() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);

    init_committee(2, vector[@0x1, @0x2], scenario.ctx());
    scenario.next_tx(@0x1);

    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_1", b"signing_pk_1", b"url1".to_string(), &mut committee, scenario.ctx());
    test_scenario::return_shared(committee);

    scenario.next_tx(@0x2);
    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_2", b"signing_pk_2", b"url2".to_string(), &mut committee, scenario.ctx());

    // First proposal from @0x2
    let partial_pks = vector[b"partial_pk_1", b"partial_pk_2"];
    let pk = b"master_pk";
    propose(&mut committee, partial_pks, pk, scenario.ctx());

    // Try to propose again from same member @0x2
    propose(&mut committee, partial_pks, pk, scenario.ctx());

    test_scenario::return_shared(committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = EInvalidState)]
fun test_finalize_fails_from_predkg_state() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);

    init_committee(2, vector[@0x1, @0x2], scenario.ctx());
    scenario.next_tx(@0x1);

    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_1", b"signing_pk_1", b"url1".to_string(), &mut committee, scenario.ctx());

    // Try to finalize while still in PreDKG state
    finalize_committee(&mut committee, scenario.ctx());

    test_scenario::return_shared(committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = EInvalidState)]
fun test_finalize_committee_fails_on_rotation_committee() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);

    // Create and finalize old committee
    init_committee(1, vector[@0x1], scenario.ctx());
    scenario.next_tx(@0x1);

    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_1", b"signing_pk_1", b"url1".to_string(), &mut committee, scenario.ctx());
    propose(&mut committee, vector[b"pk_1"], b"master", scenario.ctx());
    finalize_committee(&mut committee, scenario.ctx());
    let old_committee_id = object::id(&committee);
    test_scenario::return_shared(committee);

    // Create rotation committee
    scenario.next_tx(@0x1);
    let old_committee = scenario.take_shared_by_id<Committee>(old_committee_id);
    init_committee_for_rotation(1, vector[@0x1], &old_committee, scenario.ctx());
    test_scenario::return_shared(old_committee);

    scenario.next_tx(@0x1);
    let mut new_committee = scenario.take_shared<Committee>();

    // Skip past the old committee check by ensuring we get the rotation one
    if (new_committee.old_committee_id.is_none()) {
        test_scenario::return_shared(new_committee);
        new_committee = scenario.take_shared<Committee>();
    };

    register(b"enc_pk_1", b"signing_pk_1", b"url1".to_string(), &mut new_committee, scenario.ctx());

    scenario.next_tx(@0x1);
    let old_committee = scenario.take_shared_by_id<Committee>(old_committee_id);
    propose_for_rotation(&old_committee, &mut new_committee, vector[b"pk_1"], scenario.ctx());
    test_scenario::return_shared(old_committee);

    // Try to use finalize_committee on rotation committee - should fail
    finalize_committee(&mut new_committee, scenario.ctx());

    test_scenario::return_shared(new_committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = EInsufficientOldMembers)]
fun test_init_rotation_fails_without_threshold_old_members() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);

    // Create and finalize a 2-of-3 committee with members @0x1, @0x2, @0x3
    init_committee(2, vector[@0x1, @0x2, @0x3], scenario.ctx());
    scenario.next_tx(@0x1);

    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_1", b"signing_pk_1", b"url1".to_string(), &mut committee, scenario.ctx());
    test_scenario::return_shared(committee);

    scenario.next_tx(@0x2);
    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_2", b"signing_pk_2", b"url2".to_string(), &mut committee, scenario.ctx());
    test_scenario::return_shared(committee);

    scenario.next_tx(@0x3);
    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_3", b"signing_pk_3", b"url3".to_string(), &mut committee, scenario.ctx());

    // Propose and finalize the committee
    let partial_pks = vector[b"partial_pk_1", b"partial_pk_2", b"partial_pk_3"];
    let pk = b"master_pk";
    propose(&mut committee, partial_pks, pk, scenario.ctx());
    test_scenario::return_shared(committee);

    scenario.next_tx(@0x2);
    let mut committee = scenario.take_shared<Committee>();
    propose(&mut committee, partial_pks, pk, scenario.ctx());
    test_scenario::return_shared(committee);

    scenario.next_tx(@0x1);
    let mut committee = scenario.take_shared<Committee>();
    propose(&mut committee, partial_pks, pk, scenario.ctx());
    finalize_committee(&mut committee, scenario.ctx());
    let old_committee_id = object::id(&committee);
    test_scenario::return_shared(committee);

    // Create rotation committee with only 1 member from old committee (need at least 2)
    // Old committee: @0x1, @0x2, @0x3 (threshold=2)
    // New committee: @0x1, @0x4, @0x5 (only @0x1 is from old committee)
    scenario.next_tx(@0x1);
    let old_committee = scenario.take_shared_by_id<Committee>(old_committee_id);
    init_committee_for_rotation(
        2,
        vector[@0x1, @0x4, @0x5], // Only @0x1 from old committee
        &old_committee,
        scenario.ctx(),
    );
    test_scenario::return_shared(old_committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = vec_set::EKeyAlreadyExists)]
fun test_init_committee_with_duplicate_members() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    init_committee(2, vector[@0x1, @0x1, @0x2], scenario.ctx());
    scenario.end();
}

#[test]
#[expected_failure(abort_code = EInvalidThreshold)]
fun test_init_committee_with_zero_threshold() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    init_committee(0, vector[@0x1, @0x2], scenario.ctx());
    scenario.end();
}

#[test]
#[expected_failure(abort_code = ENotMember)]
fun test_non_member_propose_fails() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    init_committee(2, vector[@0x1, @0x2], scenario.ctx());

    // Register members
    scenario.next_tx(@0x1);
    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_1", b"signing_pk_1", b"url1".to_string(), &mut committee, scenario.ctx());
    test_scenario::return_shared(committee);

    scenario.next_tx(@0x2);
    let mut committee = scenario.take_shared<Committee>();
    register(b"enc_pk_2", b"signing_pk_2", b"url2".to_string(), &mut committee, scenario.ctx());

    // Non-member @0x3 tries to propose
    scenario.next_tx(@0x3);
    propose(&mut committee, vector[b"pk_1", b"pk_2"], b"master", scenario.ctx());

    test_scenario::return_shared(committee);
    scenario.end();
}
