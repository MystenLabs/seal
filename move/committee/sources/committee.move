// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module committee::committee;

use std::string::String;
use sui::package::UpgradeCap;
use sui::table::{Self, Table};
use seal::key_server::{Self, KeyServer};
use sui::package::UpgradeTicket;
use sui::transfer::Receiving;

// ===== Errors =====
const ENotMember: u64 = 0;
const EAlreadyVoted: u64 = 1;
const EInvalidThreshold: u64 = 2;
const ENotCandidate: u64 = 3;
const EAlreadyApproved: u64 = 4;
const ENoProposalForDigest: u64 = 5;
const EInvalidPartialPks: u64 = 6;
const EInvalidMembers: u64 = 7;
const EAlreadyRegistered: u64 = 8;
const EInsufficientVotes: u64 = 9;

// ===== Structs =====

/// Candidate data for a member to register before dkg. 
public struct CandidateData has store, drop {
    enc_pk: vector<u8>,
    signing_pk: vector<u8>,
}

/// Initial committee before DKG. Anyone can add themselves to it. 
public struct InitCommittee has key {
    id: UID,
    candidates: Table<address, CandidateData>,
    members: vector<address>, // party id = the index in members
    threshold: u16,
}

/// Anyone in InitCommittee can propose this. After threshold of approvals,
/// the committee is finalized and the committee owned KeyServer is created.
public struct Committee has key {
    id: UID,
    threshold: u16,
    members: vector<address>, // party id is the index of this vector
    partial_pks: vector<vector<u8>>, // pks corresponding to members
    approvals: vector<address>,
}

/// Upgrade manager that holds the upgrade cap. 
public struct UpgradeManager has key {
    id: UID,
    cap: UpgradeCap,
    upgrade_proposals: Table<vector<u8>, UpgradeProposal>,
}

/// Upgrade proposal that contains the digest and voters. 
public struct UpgradeProposal has store, drop {
    digest: vector<u8>,
    voters: vector<address>
}

// ===== Functions =====

/// Create an init committee with threshold. 
public fun new_init_committee(
    threshold: u16,
    ctx: &mut TxContext,
) {
    transfer::share_object(InitCommittee { id: object::new(ctx), candidates: table::new(ctx), threshold, members: vector::empty() });
}

/// Register as a candidate for a InitCommittee with ecies pk and signing pk. 
public fun register(
    candidate_enc_pk: vector<u8>,
    candidate_signing_pk: vector<u8>,
    init_committee: &mut InitCommittee,
    ctx: &mut TxContext,
) {
    let sender = ctx.sender();
    assert!(!init_committee.candidates.contains(sender), EAlreadyRegistered);
    init_committee.candidates.add(sender, CandidateData { enc_pk: candidate_enc_pk, signing_pk: candidate_signing_pk });
    init_committee.members.push_back(sender);
}

/// Propose a committee with a list of member address and their partial pks 
/// after dkg. These are known to all parties that participated at dkg 
/// finalization step. 
public fun propose_committee(
    init_committee: &InitCommittee,
    members: vector<address>, // todo: check this, can be a subset
    partial_pks: vector<vector<u8>>,
    ctx: &mut TxContext,
) { 
    assert!(init_committee.members.length() >= init_committee.threshold as u64, EInvalidThreshold);
    assert!(init_committee.candidates.contains(ctx.sender()), ENotCandidate);
    assert!(members.length() == partial_pks.length(), EInvalidPartialPks);
    
    let mut i = 0;
    while (i < members.length()) {
        assert!(init_committee.candidates.contains(members[i]), EInvalidMembers);
        i = i + 1;
    };

    let committee = Committee {
        id: object::new(ctx),
        threshold: init_committee.threshold,
        members,
        partial_pks,
        approvals: vector::empty(),
    };
    transfer::share_object(committee);
}

/// Approve the proposed committee after checking all partial pks 
/// in the committee object matches with the member's dkg finalization 
/// locally. This can be called by any members of committee.
public fun approve_committee(
    committee: &mut Committee,
    ctx: &mut TxContext,
) {
    let sender = ctx.sender();
    assert!(committee.members.contains(&sender), ENotMember);
    assert!(!committee.approvals.contains(&sender), EAlreadyApproved);
    
    committee.approvals.push_back(sender);
}

/// Finalize the committee and create the key server object and all partial 
/// key server objects. It can be called by any members of committee when 
/// threshold of approvals is reached.
public fun finalize_committee(
    committee: &mut Committee,
    ctx: &mut TxContext,
) {
    assert!(committee.approvals.length() >= committee.threshold as u64, EInvalidThreshold);
    assert!(committee.members.contains(&ctx.sender()), ENotMember);

    let mut key_server = key_server::create_v2(
        committee.id.to_address().to_string(),
        0,
        committee.threshold,
        ctx,
    );
    
    key_server::add_all_partial_key_servers(
        &mut key_server,
        committee,
        &committee.members,
        &committee.partial_pks,
        ctx,
    );

    // transfer the key server object to the Committee object via TTO
    transfer::public_transfer(key_server, committee.id.to_address());
}

/// Update the url of the key server object. Only 
public fun update_url(
    ks: Receiving<KeyServer>,
    committee: &mut Committee,
    url: String,
    ctx: &mut TxContext,
) {
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    let mut key_server = transfer::public_receive(&mut committee.id, ks);
    key_server::update_url(&mut key_server, committee, url, ctx);
    transfer::public_transfer(key_server, committee.id.to_address());
}

// ===== Upgrade Management =====

public(package) fun new_upgrade_manager(cap: UpgradeCap, ctx: &mut TxContext) {
    let upgrade_manager = UpgradeManager {
        id: object::new(ctx),
        cap,
        upgrade_proposals: table::new(ctx),
    };
    transfer::share_object(upgrade_manager);
}

public fun vote_upgrade(
    self: &mut UpgradeManager,
    digest: vector<u8>,
    committee: &Committee,
    ctx: &mut TxContext,
) {
    assert!(committee.members.contains(&ctx.sender()), ENotMember);

    if (self.upgrade_proposals.contains(digest)) {
        let proposal = self.upgrade_proposals.borrow_mut(digest);
        assert!(!proposal.voters.contains(&ctx.sender()), EAlreadyVoted);
        proposal.voters.push_back(ctx.sender());
    } else {
        let mut proposal = UpgradeProposal {
            digest,
            voters: vector::empty(),
        };
        proposal.voters.push_back(ctx.sender());
        self.upgrade_proposals.add(digest, proposal);
    }
}

public fun authorize_upgrade(
    self: &mut UpgradeManager,
    digest: vector<u8>,
    committee: &Committee,
): UpgradeTicket {
    assert!(self.upgrade_proposals.contains(digest), ENoProposalForDigest);
    let proposal = self.upgrade_proposals.borrow(digest);
    assert!(proposal.voters.length() >= committee.threshold as u64, EInsufficientVotes);
    self.upgrade_proposals.remove(digest);

    let policy = self.cap.policy();
    self.cap.authorize(policy, digest)
}

#[test]
fun test_committee() {
    use sui::test_scenario;
    
    let mut scenario = test_scenario::begin(@0x1);
    let ctx = scenario.ctx();
    
    // Create init committee with threshold 3
    new_init_committee(3, ctx);
    scenario.next_tx(@0x1);
    
    // Register 3 members
    let mut init_committee = scenario.take_shared<InitCommittee>();
    register(b"enc_pk_1", b"signing_pk_1", &mut init_committee, scenario.ctx());
    scenario.next_tx(@0x2);
    register(b"enc_pk_2", b"signing_pk_2", &mut init_committee, scenario.ctx());
    scenario.next_tx(@0x3);
    register(b"enc_pk_3", b"signing_pk_3", &mut init_committee, scenario.ctx());
    
    // Propose committee with members and partial keys
    scenario.next_tx(@0x1);
    let addresses = vector[@0x1, @0x2, @0x3];
    let partial_pks = vector[b"partial_pk_1", b"partial_pk_2", b"partial_pk_3"];
    propose_committee(&init_committee, addresses, partial_pks, scenario.ctx());
    test_scenario::return_shared(init_committee);
    
    // Approve committee by threshold members
    scenario.next_tx(@0x1);
    let mut committee = scenario.take_shared<Committee>();
    approve_committee(&mut committee, scenario.ctx());
    scenario.next_tx(@0x2);
    approve_committee(&mut committee, scenario.ctx());
    scenario.next_tx(@0x3);
    approve_committee(&mut committee, scenario.ctx());
    
    // Finalize committee
    scenario.next_tx(@0x1);
    finalize_committee(&mut committee, scenario.ctx());
    
    // Store committee ID before returning it
    let committee_id = object::id(&committee);
    test_scenario::return_shared(committee);
    
    // Update URL using Receiving pattern
    scenario.next_tx(@0x1);
    
    // Create a receiving ticket for the KeyServer owned by the committee
    let receiving_ticket = test_scenario::most_recent_receiving_ticket<KeyServer>(&committee_id);
    
    // Now call update_url with the receiving ticket
    let mut committee = scenario.take_shared<Committee>();
    update_url(receiving_ticket, &mut committee, b"https://example.com".to_string(), scenario.ctx());
    
    test_scenario::return_shared(committee);
    scenario.end();
}

#[test]
fun test_upgrade() {
    // todo
}

#[test]
#[expected_failure(abort_code = EAlreadyRegistered)]
fun test_register_fails_when_already_registered() {
    use sui::test_scenario;
    
    let mut scenario = test_scenario::begin(@0x1);
    
    new_init_committee(2, scenario.ctx());
    scenario.next_tx(@0x1);
    
    let mut init_committee = scenario.take_shared<InitCommittee>();
    register(b"enc_pk_1", b"signing_pk_1", &mut init_committee, scenario.ctx());
    
    // Try to register again - should fail with EAlreadyRegistered
    register(b"enc_pk_2", b"signing_pk_2", &mut init_committee, scenario.ctx());
    
    test_scenario::return_shared(init_committee);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = EInvalidThreshold)]
fun test_finalize_committee_fails_without_threshold() {
    use sui::test_scenario;
    
    let mut scenario = test_scenario::begin(@0x1);
    let ctx = scenario.ctx();
    
    // Create init committee with threshold 3
    new_init_committee(3, ctx);
    scenario.next_tx(@0x1);
    
    // Register 3 members
    let mut init_committee = scenario.take_shared<InitCommittee>();
    register(b"enc_pk_1", b"signing_pk_1", &mut init_committee, scenario.ctx());
    scenario.next_tx(@0x2);
    register(b"enc_pk_2", b"signing_pk_2", &mut init_committee, scenario.ctx());
    scenario.next_tx(@0x3);
    register(b"enc_pk_3", b"signing_pk_3", &mut init_committee, scenario.ctx());
    
    // Propose committee with members and partial keys
    scenario.next_tx(@0x1);
    let addresses = vector[@0x1, @0x2, @0x3];
    let partial_pks = vector[b"partial_pk_1", b"partial_pk_2", b"partial_pk_3"];
    propose_committee(&init_committee, addresses, partial_pks, scenario.ctx());
    test_scenario::return_shared(init_committee);
    
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