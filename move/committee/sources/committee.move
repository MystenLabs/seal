// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Implementation of committee based key server operations.
/// The admin that initializes the committee should deploy this
/// package itself, so that the committee can manage its own
/// upgrade and the key rotation. The key server object is owned
/// by the committee.

module committee::committee;

use seal_testnet::key_server::{
    KeyServer,
    create_partial_key_server,
    create_committee_v2,
    PartialKeyServer
};
use std::string::String;
use sui::{transfer::Receiving, vec_map::{Self, VecMap}, vec_set::{Self, VecSet}};

// ===== Errors =====
const ENotMember: u64 = 0;
const EDuplicateMember: u64 = 1;
const EInvalidThreshold: u64 = 2;
const EAlreadyProposed: u64 = 4;
const EInvalidProposal: u64 = 5;
const EAlreadyRegistered: u64 = 6;
const EInvalidState: u64 = 7;
const EInsufficientApprovals: u64 = 9;
const EInsufficientOldMembers: u64 = 10;
const ENotRegistered: u64 = 11;

// ===== Structs =====

/// Candidate data for a member to register with two public
/// keys and the key server URL.
public struct CandidateData has copy, drop, store {
    enc_pk: vector<u8>,
    signing_pk: vector<u8>,
    url: String,
}

public enum State has drop, store {
    Init {
        candidate_data: VecMap<address, CandidateData>,
    },
    PostDKG {
        candidate_data: VecMap<address, CandidateData>,
        partial_pks: vector<vector<u8>>,
        pk: vector<u8>,
        approvals: VecSet<address>,
    },
    Finalized {
        pk: vector<u8>,
    },
}

/// MPC committee with defined threshold and members. The state is an enum
/// in different stages that holds state specific infos.
public struct Committee has key {
    id: UID,
    threshold: u16,
    /// The members of the committee. The 'party_id' used in the dkg protocol
    /// is the index of this vector.
    members: vector<address>,
    state: State,
    /// For rotation: reference to old committee
    old_committee_id: Option<ID>,
}

// ===== Functions =====

/// Create a committee for fresh DKG with a list of members and threshold.
/// The committee is in Init state with empty candidate data.
public fun init_committee(threshold: u16, members: vector<address>, ctx: &mut TxContext) {
    assert!(threshold > 0, EInvalidThreshold);
    assert!(members.length() >= threshold as u64, EInvalidThreshold);

    // Verify no duplicate members.
    let member_set = vec_set::from_keys(members);
    assert!(member_set.length() == members.length(), EDuplicateMember);

    transfer::share_object(Committee {
        id: object::new(ctx),
        threshold,
        members,
        state: State::Init { candidate_data: vec_map::empty() },
        old_committee_id: option::none(),
    });
}

/// Create a committee for rotation from an existing finalized old committee.
/// The new committee must contain an old threshold of the old committee members.
public fun init_rotation(
    old_committee: &Committee,
    threshold: u16,
    new_members: vector<address>,
    ctx: &mut TxContext,
) {
    assert!(threshold > 0, EInvalidThreshold);
    assert!(new_members.length() >= threshold as u64, EInvalidThreshold);

    // Verify no duplicate members.
    let member_set = vec_set::from_keys(new_members);
    assert!(member_set.length() == new_members.length(), EDuplicateMember);

    // Verify the old committee is finalized for rotation.
    assert!(
        match (&old_committee.state) {
            State::Finalized { pk: _ } => true,
            _ => false,
        },
        EInvalidState,
    );

    // Check that new committee has at least the threshold of old committee members.
    let mut continuing_members_count: u64 = 0;
    let mut i = 0;
    while (i < new_members.length()) {
        if (old_committee.members.contains(&new_members[i])) {
            continuing_members_count = continuing_members_count + 1;
        };
        i = i + 1;
    };
    assert!(continuing_members_count >= (old_committee.threshold as u64), EInsufficientOldMembers);

    transfer::share_object(Committee {
        id: object::new(ctx),
        threshold,
        members: new_members,
        state: State::Init { candidate_data: vec_map::empty() },
        old_committee_id: option::some(old_committee.id()),
    });
}

/// Register a candidate with ecies pk, signing pk and URL. Append it to
/// candidate data map.
public fun register(
    committee: &mut Committee,
    enc_pk: vector<u8>,
    signing_pk: vector<u8>,
    url: String,
    ctx: &mut TxContext,
) {
    // TODO: add checks for enc_pk, signing_pk to be valid element, maybe PoP
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    let sender = ctx.sender();
    match (&mut committee.state) {
        State::Init { candidate_data } => {
            assert!(!candidate_data.contains(&sender), EAlreadyRegistered);
            candidate_data.insert(sender, CandidateData { enc_pk, signing_pk, url });
        },
        _ => abort EInvalidState,
    }
}

/// Propose a committee with a list partial pks (in the order of committee's members list)
/// and master pk after DKG. Add the caller to approvals list.
/// If already in PostDKG state, check the submitted partial_pks and pk are consistent with
/// the onchain state, then add the caller to approvals list.
public fun propose(
    committee: &mut Committee,
    partial_pks: vector<vector<u8>>,
    pk: vector<u8>,
    ctx: &mut TxContext,
) {
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    assert!(partial_pks.length() == committee.members.length(), EInvalidProposal);

    match (&mut committee.state) {
        State::Init { candidate_data } => {
            assert!(candidate_data.length() == committee.members.length(), ENotRegistered);
            let mut i = 0;
            while (i < committee.members.length()) {
                assert!(candidate_data.contains(&committee.members[i]), ENotRegistered);
                i = i + 1;
            };

            committee.state =
                State::PostDKG {
                    candidate_data: *candidate_data,
                    approvals: vec_set::singleton(ctx.sender()),
                    partial_pks,
                    pk,
                };
        },
        State::PostDKG {
            approvals,
            candidate_data: _,
            partial_pks: existing_partial_pks,
            pk: existing_pk,
        } => {
            // Check that submitted partial_pks and pk are consistent
            assert!(partial_pks == *existing_partial_pks, EInvalidProposal);
            assert!(pk == *existing_pk, EInvalidProposal);

            // Insert approval and make sure if approval was not inserted before
            assert!(!approvals.contains(&ctx.sender()), EAlreadyProposed);
            approvals.insert(ctx.sender());
        },
        _ => abort EInvalidState,
    }
}

/// Propose a rotation from old committee to new one with a list of partial pks.
/// Add the caller to approvals list. If already in PostDKG state, checks that
/// submitted partial_pks are consistent with the onchain state, then add the
/// caller to approvals list.
public fun propose_for_rotation(
    committee: &mut Committee,
    old_committee: &Committee,
    partial_pks: vector<vector<u8>>,
    ctx: &mut TxContext,
) {
    assert!(committee.old_committee_id.is_some(), EInvalidState);
    assert!(old_committee.id() == *committee.old_committee_id.borrow(), EInvalidState);

    match (&old_committee.state) {
        State::Finalized { pk } => propose(committee, partial_pks, *pk, ctx),
        _ => abort EInvalidState,
    }
}

/// Finalize the committee for a fresh DKG, creates a new KeyServer and TTO to the committee.
public fun finalize(committee: &mut Committee, ctx: &mut TxContext) {
    assert!(committee.old_committee_id.is_none(), EInvalidState);

    match (&committee.state) {
        State::PostDKG { approvals, candidate_data, partial_pks, pk } => {
            assert!(approvals.length() == committee.members.length(), EInsufficientApprovals);

            // Creates new KeyServerV2 with partial key servers VecMap.
            let partial_key_servers = build_partial_key_servers(
                committee,
                candidate_data,
                partial_pks,
            );
            let key_server = create_committee_v2(
                committee.id.to_address().to_string(),
                committee.threshold,
                *pk,
                partial_key_servers,
                ctx,
            );

            // Transfer the key server object to the Committee object via TTO.
            transfer::public_transfer(key_server, committee.id.to_address());
            committee.state = State::Finalized { pk: *pk };
        },
        _ => abort EInvalidState,
    }
}

/// Finalize rotation for the committe. Transfer the KeyServer from old
/// committee to the new committee and destroys the old committee object.
/// Add all new partial key server as df to key server.
public fun finalize_for_rotation(
    committee: &mut Committee,
    mut old_committee: Committee,
    key_server: Receiving<KeyServer>,
    ctx: &mut TxContext,
) {
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    assert!(committee.old_committee_id.is_some(), EInvalidState);
    assert!(old_committee.id() == *committee.old_committee_id.borrow(), EInvalidState);

    // Verify old committee is finalized.
    assert!(
        match (&old_committee.state) {
            State::Finalized { pk: _ } => true,
            _ => false,
        },
        EInvalidState,
    );

    match (&committee.state) {
        State::PostDKG { approvals, candidate_data, partial_pks, pk } => {
            assert!(approvals.length() == committee.members.length(), EInsufficientApprovals);

            // Receive the KeyServer from old committee and set its new partial key servers VecMap.
            let mut key_server = transfer::public_receive(&mut old_committee.id, key_server);
            let partial_key_servers = build_partial_key_servers(
                committee,
                candidate_data,
                partial_pks,
            );
            key_server.set_partial_key_servers(partial_key_servers);
            // Transfer KeyServer to new committee
            transfer::public_transfer(key_server, committee.id.to_address());

            // Finalize new committee (master pk is preserved in KeyServer)
            committee.state = State::Finalized { pk: *pk };

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
    committee: &mut Committee,
    ks: Receiving<KeyServer>,
    url: String,
    ctx: &mut TxContext,
) {
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    let mut key_server = transfer::public_receive(&mut committee.id, ks);
    key_server.update_partial_key_server_url(url, ctx.sender());
    transfer::public_transfer(key_server, committee.id.to_address());
}

/// Get the ID of the committee.
public(package) fun id(committee: &Committee): ID {
    committee.id.to_inner()
}

/// Helper function to build the partial key servers VecMap for the list of committee members.
public(package) fun build_partial_key_servers(
    committee: &Committee,
    candidate_data: &VecMap<address, CandidateData>,
    partial_pks: &vector<vector<u8>>,
): VecMap<address, PartialKeyServer> {
    let mut partial_key_servers = vec_map::empty();
    let mut i = 0;
    while (i < committee.members.length()) {
        let member = committee.members[i];
        partial_key_servers.insert(
            member,
            create_partial_key_server(
                partial_pks[i],
                candidate_data.get(&member).url,
                i as u16,
                member,
            ),
        );
        i = i + 1;
    };
    partial_key_servers
}

// TODO: handle package upgrade with threshold approvals of the committee.

#[test]
fun test_committee_rotation_2of3_to_3of4() {
    use sui::test_scenario;
    let mut scenario = test_scenario::begin(@0x1);

    // Create initial 2-of-3 committee. Members: @0x0, @0x1, @0x2, Threshold: 2
    init_committee(2, vector[@0x0, @0x1, @0x2], scenario.ctx());

    // Register all 3 members
    scenario.next_tx(@0x0);
    let mut committee = scenario.take_shared<Committee>();
    committee.register(
        b"enc_pk_0",
        b"signing_pk_0",
        b"https://url0.com".to_string(),
        scenario.ctx(),
    );
    test_scenario::return_shared(committee);

    scenario.next_tx(@0x1);
    let mut committee = scenario.take_shared<Committee>();
    committee.register(
        b"enc_pk_1",
        b"signing_pk_1",
        b"https://url1.com".to_string(),
        scenario.ctx(),
    );
    test_scenario::return_shared(committee);

    scenario.next_tx(@0x2);
    let mut committee = scenario.take_shared<Committee>();
    committee.register(
        b"enc_pk_2",
        b"signing_pk_2",
        b"https://url2.com".to_string(),
        scenario.ctx(),
    );

    // DKG is done offline, member @0x03 proposes a committee with partial keys and master pk.
    let partial_pks = vector[b"partial_pk_0", b"partial_pk_1", b"partial_pk_2"];
    let master_pk = b"master_pk";
    committee.propose(partial_pks, master_pk, scenario.ctx());
    test_scenario::return_shared(committee);

    // Propose with remaining members.
    scenario.next_tx(@0x1);
    let mut committee = scenario.take_shared<Committee>();
    committee.propose(partial_pks, master_pk, scenario.ctx());
    test_scenario::return_shared(committee);

    scenario.next_tx(@0x0);
    let mut committee = scenario.take_shared<Committee>();
    committee.propose(partial_pks, master_pk, scenario.ctx());
    test_scenario::return_shared(committee);

    // A member finalizes it.
    scenario.next_tx(@0x0);
    let mut committee = scenario.take_shared<Committee>();
    committee.finalize(scenario.ctx());
    match (&committee.state) {
        State::Finalized { pk } => assert!(pk == master_pk, 0),
        _ => abort EInvalidState,
    };
    let old_committee_id = committee.id();
    test_scenario::return_shared(committee);

    // Initialize rotation to 3-of-4 committee.
    // Old committee (2-of-3): @0x0=party0, @0x1=party1, @0x2=party2
    // New committee (3-of-4): @0x1=party0, @0x0=party1, @0x3=party3, @0x4=party4
    // party 0 and party 1 are continuing members, swapped.
    scenario.next_tx(@0x1);
    let old_committee = scenario.take_shared_by_id<Committee>(old_committee_id);
    old_committee.init_rotation(
        3, // New threshold
        vector[@0x1, @0x0, @0x3, @0x4], // @0x0 and @0x1 continue but swap positions
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
        new_committee_id = new_committee.id();
    } else {
        test_scenario::return_shared(committee1);
        new_committee = scenario.take_shared<Committee>();
        new_committee_id = new_committee.id();
    };

    // Check new committee init state.
    assert!(new_committee.old_committee_id == option::some(old_committee_id), 0);

    // Register all 4 members.
    scenario.next_tx(@0x0);
    new_committee.register(
        b"enc_pk_0",
        b"signing_pk_0",
        b"https://new_url0.com".to_string(),
        scenario.ctx(),
    );
    test_scenario::return_shared(new_committee);

    scenario.next_tx(@0x1);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    new_committee.register(
        b"enc_pk_1",
        b"signing_pk_1",
        b"https://new_url1.com".to_string(),
        scenario.ctx(),
    );
    test_scenario::return_shared(new_committee);

    scenario.next_tx(@0x3);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    new_committee.register(
        b"enc_pk_3",
        b"signing_pk_3",
        b"https://new_url3.com".to_string(),
        scenario.ctx(),
    );
    test_scenario::return_shared(new_committee);

    scenario.next_tx(@0x4);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    new_committee.register(
        b"enc_pk_4",
        b"signing_pk_4",
        b"https://new_url4.com".to_string(),
        scenario.ctx(),
    );
    test_scenario::return_shared(new_committee);

    scenario.next_tx(@0x1);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    let old_committee = scenario.take_shared_by_id<Committee>(old_committee_id);
    let new_partial_pks = vector[b"pk1", b"pk0", b"pk3", b"pk4"];

    // Propose rotation with all partial pks.
    new_committee.propose_for_rotation(
        &old_committee,
        new_partial_pks,
        scenario.ctx(),
    );
    test_scenario::return_shared(old_committee);
    test_scenario::return_shared(new_committee);

    // Approve new committee by remaining 3 members using propose_for_rotation
    scenario.next_tx(@0x0);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    let old_committee = scenario.take_shared_by_id<Committee>(old_committee_id);
    new_committee.propose_for_rotation(&old_committee, new_partial_pks, scenario.ctx());
    test_scenario::return_shared(old_committee);
    test_scenario::return_shared(new_committee);

    scenario.next_tx(@0x3);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    let old_committee = scenario.take_shared_by_id<Committee>(old_committee_id);
    new_committee.propose_for_rotation(&old_committee, new_partial_pks, scenario.ctx());
    test_scenario::return_shared(old_committee);
    test_scenario::return_shared(new_committee);

    scenario.next_tx(@0x4);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    let old_committee = scenario.take_shared_by_id<Committee>(old_committee_id);
    new_committee.propose_for_rotation(&old_committee, new_partial_pks, scenario.ctx());
    test_scenario::return_shared(old_committee);
    test_scenario::return_shared(new_committee);

    // Finalize committee for rotation.
    scenario.next_tx(@0x1);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    let old_committee = scenario.take_shared_by_id<Committee>(old_committee_id);
    let ks_ticket = test_scenario::most_recent_receiving_ticket<KeyServer>(&old_committee_id);
    new_committee.finalize_for_rotation(
        old_committee,
        ks_ticket,
        scenario.ctx(),
    );

    // Verify new committee.
    match (&new_committee.state) {
        State::Finalized { pk } => assert!(pk == master_pk, 0),
        _ => abort EInvalidState,
    };

    // Update URL.
    scenario.next_tx(@0x1);
    let ks_ticket_1 = test_scenario::most_recent_receiving_ticket<KeyServer>(&new_committee_id);
    new_committee.update_partial_ks_url(
        ks_ticket_1,
        b"https://new_url1.com".to_string(),
        scenario.ctx(),
    );

    // Verify URL.
    scenario.next_tx(@0x1);
    let ks_ticket_2 = test_scenario::most_recent_receiving_ticket<KeyServer>(&new_committee_id);
    let key_server = transfer::public_receive(&mut new_committee.id, ks_ticket_2);
    assert!(key_server.url_for_member(@0x1) == b"https://new_url1.com".to_string());
    transfer::public_transfer(key_server, new_committee.id.to_address());
    test_scenario::return_shared(new_committee);
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
#[expected_failure(abort_code = EInvalidThreshold)]
fun test_init_committee_with_threshold_exceeding_members() {
    use sui::test_scenario;
    let mut scenario = test_scenario::begin(@0x1);
    init_committee(3, vector[@0x1, @0x2], scenario.ctx());
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
#[expected_failure(abort_code = EInsufficientOldMembers)]
fun test_init_rotation_fails_with_not_enough_old_members() {
    use sui::test_scenario;
    let mut scenario = test_scenario::begin(@0x1);

    init_committee(1, vector[@0x1], scenario.ctx());
    scenario.next_tx(@0x1);

    let mut committee = scenario.take_shared<Committee>();
    committee.register(b"enc_pk_1", b"signing_pk_1", b"url1".to_string(), scenario.ctx());
    committee.propose(vector[b"pk_1"], b"master", scenario.ctx());
    committee.finalize(scenario.ctx());

    // Try to rotate with no continuing members - fails.
    committee.init_rotation(
        2,
        vector[@0x2, @0x3],
        scenario.ctx(),
    );

    test_scenario::return_shared(committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = EInvalidState)]
fun test_init_rotation_fails_with_non_finalized_old_committee() {
    use sui::test_scenario;
    let mut scenario = test_scenario::begin(@0x1);

    init_committee(1, vector[@0x1], scenario.ctx());
    scenario.next_tx(@0x1);

    let mut committee = scenario.take_shared<Committee>();
    committee.register(b"enc_pk_1", b"signing_pk_1", b"url1".to_string(), scenario.ctx());
    committee.propose(vector[b"pk_1"], b"master", scenario.ctx());

    // Try to rotate from PostDKG state - fails.
    committee.init_rotation(
        2,
        vector[@0x2, @0x3],
        scenario.ctx(),
    );

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
    committee.register(b"enc_pk_3", b"signing_pk_3", b"url3".to_string(), scenario.ctx());

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
    committee.register(b"enc_pk_1", b"signing_pk_1", b"url1".to_string(), scenario.ctx());
    // Register again as same member fails.
    committee.register(b"enc_pk_2", b"signing_pk_2", b"url2".to_string(), scenario.ctx());

    test_scenario::return_shared(committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = EInvalidState)]
fun test_register_fails_when_not_in_init_state() {
    use sui::test_scenario;
    let mut scenario = test_scenario::begin(@0x1);

    init_committee(1, vector[@0x1], scenario.ctx());
    scenario.next_tx(@0x1);

    let mut committee = scenario.take_shared<Committee>();
    committee.register(b"enc_pk_1", b"signing_pk_1", b"url1".to_string(), scenario.ctx());
    committee.propose(vector[b"pk_1"], b"master", scenario.ctx());

    // Try to register in PostDKG - fails.
    committee.register(b"enc_pk_2", b"signing_pk_2", b"url2".to_string(), scenario.ctx());
    test_scenario::return_shared(committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = ENotMember)]
fun test_propose_fails_for_non_member() {
    use sui::test_scenario;
    let mut scenario = test_scenario::begin(@0x1);
    init_committee(2, vector[@0x1, @0x2], scenario.ctx());

    // Register members
    scenario.next_tx(@0x1);
    let mut committee = scenario.take_shared<Committee>();
    committee.register(b"enc_pk_1", b"signing_pk_1", b"url1".to_string(), scenario.ctx());
    test_scenario::return_shared(committee);

    scenario.next_tx(@0x2);
    let mut committee = scenario.take_shared<Committee>();
    committee.register(b"enc_pk_2", b"signing_pk_2", b"url2".to_string(), scenario.ctx());

    // Non-member @0x3 tries to propose
    scenario.next_tx(@0x3);
    committee.propose(vector[b"pk_1", b"pk_2"], b"master", scenario.ctx());

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
    committee.register(b"enc_pk_1", b"signing_pk_1", b"url1".to_string(), scenario.ctx());
    test_scenario::return_shared(committee);

    scenario.next_tx(@0x2);
    let mut committee = scenario.take_shared<Committee>();
    committee.register(b"enc_pk_2", b"signing_pk_2", b"url2".to_string(), scenario.ctx());

    // Propose with only 1 partial_pk instead of 2 - fails.
    committee.propose(vector[b"partial_pk_1"], b"master_pk", scenario.ctx());

    test_scenario::return_shared(committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = ENotRegistered)]
fun test_propose_fails_when_not_all_registered() {
    use sui::test_scenario;
    let mut scenario = test_scenario::begin(@0x1);

    init_committee(2, vector[@0x1, @0x2], scenario.ctx());
    scenario.next_tx(@0x1);

    let mut committee = scenario.take_shared<Committee>();
    committee.register(b"enc_pk_3", b"signing_pk_3", b"url3".to_string(), scenario.ctx());

    // 0x2 not registered, propose fails.
    let partial_pks = vector[b"partial_pk_1", b"partial_pk_2"];
    let pk = b"master_pk";
    committee.propose(partial_pks, pk, scenario.ctx());

    test_scenario::return_shared(committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = EAlreadyProposed)]
fun test_propose_fails_on_duplicate_approval() {
    use sui::test_scenario;
    let mut scenario = test_scenario::begin(@0x1);

    init_committee(2, vector[@0x1, @0x2], scenario.ctx());
    scenario.next_tx(@0x1);

    let mut committee = scenario.take_shared<Committee>();
    committee.register(b"enc_pk_1", b"signing_pk_1", b"url1".to_string(), scenario.ctx());
    test_scenario::return_shared(committee);

    scenario.next_tx(@0x2);
    let mut committee = scenario.take_shared<Committee>();
    committee.register(b"enc_pk_2", b"signing_pk_2", b"url2".to_string(), scenario.ctx());

    // First proposal from @0x2
    let partial_pks = vector[b"partial_pk_1", b"partial_pk_2"];
    let pk = b"master_pk";
    committee.propose(partial_pks, pk, scenario.ctx());

    // Try to propose again from same member @0x2
    committee.propose(partial_pks, pk, scenario.ctx());

    test_scenario::return_shared(committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = EInvalidState)]
fun test_propose_for_rotation_fails_for_mismatch_committee() {
    use sui::test_scenario;
    let mut scenario = test_scenario::begin(@0x1);

    let old_committee = Committee {
        id: object::new(scenario.ctx()),
        threshold: 1,
        members: vector[@0x1],
        state: State::Finalized { pk: b"master_pk" },
        old_committee_id: option::none(),
    };

    // New committee does not point to old committee.
    let mut committee = Committee {
        id: object::new(scenario.ctx()),
        threshold: 1,
        members: vector[@0x1],
        state: State::Init { candidate_data: vec_map::empty() },
        old_committee_id: option::none(),
    };

    committee.propose_for_rotation(
        &old_committee,
        vector[b"partial_pk_1"],
        scenario.ctx(),
    );

    test_scenario::return_shared(committee);
    test_scenario::return_shared(old_committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = EInvalidState)]
fun test_propose_for_rotation_fails_for_invalid_old_committee_state() {
    use sui::test_scenario;
    let mut scenario = test_scenario::begin(@0x1);

    let old_committee = Committee {
        id: object::new(scenario.ctx()),
        threshold: 1,
        members: vector[@0x1],
        state: State::Init { candidate_data: vec_map::empty() },
        old_committee_id: option::none(),
    };

    // New committee does not point to old committee.
    let mut committee = Committee {
        id: object::new(scenario.ctx()),
        threshold: 1,
        members: vector[@0x1],
        state: State::Init { candidate_data: vec_map::empty() },
        old_committee_id: option::none(),
    };

    committee.propose_for_rotation(
        &old_committee,
        vector[b"partial_pk_1"],
        scenario.ctx(),
    );

    test_scenario::return_shared(committee);
    test_scenario::return_shared(old_committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = EInsufficientApprovals)]
fun test_finalize_fails_without_all_approvals() {
    use sui::test_scenario;
    let mut scenario = test_scenario::begin(@0x1);
    init_committee(1, vector[@0x1, @0x2], scenario.ctx());

    // Register 2 members
    scenario.next_tx(@0x1);
    let mut committee = scenario.take_shared<Committee>();
    committee.register(b"enc_pk_1", b"signing_pk_1", b"url1".to_string(), scenario.ctx());
    test_scenario::return_shared(committee);

    scenario.next_tx(@0x2);
    let mut committee = scenario.take_shared<Committee>();
    committee.register(b"enc_pk_2", b"signing_pk_2", b"url2".to_string(), scenario.ctx());
    test_scenario::return_shared(committee);

    // Propose committee with partial keys and full pk.
    scenario.next_tx(@0x1);
    let mut committee = scenario.take_shared<Committee>();
    let partial_pks = vector[b"partial_pk_1", b"partial_pk_2"];
    let pk = b"full_public_key";
    committee.propose(partial_pks, pk, scenario.ctx());

    // Try to finalize committee with only 1 approval - fails.
    committee.finalize(scenario.ctx());

    test_scenario::return_shared(committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = EInvalidState)]
fun test_finalize_fails_from_non_post_dkg_state() {
    use sui::test_scenario;
    let mut scenario = test_scenario::begin(@0x1);

    init_committee(2, vector[@0x1, @0x2], scenario.ctx());
    scenario.next_tx(@0x1);

    let mut committee = scenario.take_shared<Committee>();
    committee.register(b"enc_pk_1", b"signing_pk_1", b"url1".to_string(), scenario.ctx());

    // Try to finalize from Init (not Post DKG) state - fails.
    committee.finalize(scenario.ctx());
    test_scenario::return_shared(committee);
    scenario.end();
}

// TODO: add more tests
// - test finalize_for_rotation
// - test update_partial_ks_url for non members
