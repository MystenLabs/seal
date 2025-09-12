// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module committee::committee;

use std::string::String;
use sui::package::UpgradeCap;
use sui::dynamic_field as df;
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
const EAlreadyRegistered: u64 = 8;
const EInsufficientVotes: u64 = 9;
const EInvalidState: u64 = 10;
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
    state: State
}

/// Upgrade manager that holds the upgrade cap. 
public struct UpgradeManager has key {
    id: UID,
    cap: UpgradeCap,
    upgrade_proposals: Table<vector<u8>, UpgradeProposal>
}

/// Upgrade proposal that contains the digest and voters. 
public struct UpgradeProposal has store, drop {
    digest: vector<u8>,
    voters: vector<address>
}

// ===== Functions =====

/// Anyone can create a committee in init state with defined members list and threhold.
public fun init_committee(
    threshold: u16,
    members: vector<address>,
    ctx: &mut TxContext,
) {
    assert!(threshold > 0, EInvalidThreshold);
    assert!(members.length() >= threshold as u64, EInvalidThreshold);
    transfer::share_object(Committee { 
        id: object::new(ctx), 
        threshold, 
        members, 
        state: State::Init
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

/// Propose a committee with a list of member address and their partial pks 
/// after dkg. These are known to all parties that participated at dkg 
/// finalization step. 
public fun propose_committee(
    committee: &mut Committee,
    partial_pks: vector<vector<u8>>,
    pk: vector<u8>,
    ctx: &mut TxContext,
) { 
    assert!(match (&committee.state) {
        State::PreDKG => true,
        _ => false,
    }, EInvalidState);

    assert!(committee.members.contains(&ctx.sender()), ENotCandidate);
    assert!(partial_pks.length() == committee.members.length(), EInvalidPartialPks);
    committee.state = State::PostDKG { approvals: vector::empty(), partial_pks, pk };
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

/// Finalize the committee and create the key server object and all partial 
/// key server objects. It can be called by any members of committee when 
/// threshold of approvals is reached.
public fun finalize_committee(
    committee: &mut Committee,
    ctx: &mut TxContext,
) {
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    match (&committee.state) {
        State::PostDKG { approvals, partial_pks, pk } => {
            assert!(approvals.length() >= committee.threshold as u64, EInvalidThreshold);
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

            // transfer the key server object to the Committee object via TTO
            transfer::public_transfer(key_server, committee.id.to_address());
            
            committee.state = State::Finalized;
        },
        _ => {
            assert!(false, EInvalidState);
        }
    }
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
    key_server::update_url(&mut key_server, url, ctx);
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
    propose_committee(&mut committee, partial_pks, pk, scenario.ctx());
    test_scenario::return_shared(committee);
    
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
    propose_committee(&mut committee, partial_pks, pk, scenario.ctx());
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