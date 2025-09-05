// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module committee::committee;

use std::string::String;
use sui::package::UpgradeCap;
use sui::table::{Self, Table};
use seal::key_server::{Self, KeyServer};
use sui::package::UpgradeTicket;
use sui::transfer::Receiving;
use seal::key_server::PartialKeyServer;

// ===== Errors =====
const ENotMember: u64 = 0;
const EAlreadyVoted: u64 = 1;
const EInvalidThreshold: u64 = 2;
const ENotCandidate: u64 = 3;
const EInvalidVSSPK: u64 = 4;
const EAlreadyApproved: u64 = 5;
const ENoProposalForDigest: u64 = 6;

// ===== Structs =====

public struct CandidateData has store, drop {
    enc_pk: vector<u8>,
    signing_pk: vector<u8>,
}

/// Initial committee before DKG
public struct InitCommittee has key {
    id: UID,
    candidates: Table<address, CandidateData>,
    members: vector<address>,
    threshold: u16,
}

/// Anyone in InitCommittee can propose this. After threshold of approvals,
/// the committee is finalized and a KeyServer is created and owned by it. 
public struct Committee has key {
    id: UID,
    vss_pk: vector<u8>,
    threshold: u16,
    members: vector<address>,
    approvals: vector<address>,
}

public struct UpgradeManager has key {
    id: UID,
    cap: UpgradeCap,
    upgrade_proposals: Table<vector<u8>, UpgradeProposal>,
}

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

/// Anyone can add themselves as a candidate with their ecies pk. 
public fun register(
    candidate_enc_pk: vector<u8>,
    candidate_signing_pk: vector<u8>,
    init_committee: &mut InitCommittee,
    ctx: &mut TxContext,
) {
    let sender = ctx.sender();
    assert!(!init_committee.candidates.contains(sender), ENotCandidate);
    init_committee.candidates.add(sender, CandidateData { enc_pk: candidate_enc_pk, signing_pk: candidate_signing_pk });
    init_committee.members.push_back(sender);
}

/// A candidate can remove themselves from an InitCommittee. 
public fun remove(
    init_committee: &mut InitCommittee,
    ctx: &mut TxContext,
) {
    let sender = ctx.sender();
    let _candidate: CandidateData = init_committee.candidates.remove(sender);
    let mut i = 0;
    while (i < init_committee.members.length()) {
        if (init_committee.members[i] == sender) {
            init_committee.members.remove(i);
            break
        };
        i = i + 1;
    };
}

/// Anyone in InitCommitee can propose a vss_pk. This is returned after DKG local completion.
public fun propose_committee(
    init_committee: &InitCommittee,
    vss_pk: vector<u8>,
    ctx: &mut TxContext,
) { 
    assert!(init_committee.members.length() >= init_committee.threshold as u64, EInvalidThreshold);
    assert!(init_committee.candidates.contains(ctx.sender()), ENotCandidate);

    let committee = Committee {
        id: object::new(ctx),
        vss_pk,
        threshold: init_committee.threshold,
        members: init_committee.members,
        approvals: vector::empty(),
    };
    transfer::share_object(committee);
}

/// Approve proposed committee, can be called by any members of committee. 
public fun approve_committee(
    committee: &mut Committee,
    vss_pk: vector<u8>,
    ctx: &TxContext,
) {
    if (vss_pk != committee.vss_pk) {
        abort EInvalidVSSPK
    };
    let sender = ctx.sender();
    assert!(committee.members.contains(&sender), ENotMember);
    assert!(!committee.approvals.contains(&sender), EAlreadyApproved);
    
    committee.approvals.push_back(sender);
}

/// key server created and transferred to committee via TTO.
public fun finalize_committee(
    committee: &mut Committee,
    ctx: &mut TxContext,
) {
    assert!(committee.approvals.length() >= committee.threshold as u64, EInvalidThreshold);
    
    // Create KeyServer using the committee's VSS public key
    let keyserver = key_server::create_v2(
        b"Committee KeyServer".to_string(),
        0,
        committee.vss_pk,
        committee.threshold,
        committee.members,
        ctx,
    );
    
    // Transfer the KeyServer to the Committee object via TTO
    transfer::public_transfer(keyserver, committee.id.to_address());
}

// todo: partial key server url can be updated with the cap, defined here
// todo: all pks of all members are known to all party
/// Committee member creates their partial keyserver through the committee
public fun create_partial_key_server(
    committee: &mut Committee,
    keyserver: Receiving<KeyServer>,
    party_id: u16,
    partial_pk: vector<u8>,
    server_url: String,
    ctx: &mut TxContext,
): PartialKeyServer {
    // Verify sender is a committee member
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    
    // Receive the KeyServer temporarily
    let mut ks = transfer::public_receive(&mut committee.id, keyserver);
    
    // Create the partial keyserver and transfer to the sender
    let partial_key_server = key_server::new_partial_key_server(
        &mut ks,
        party_id,
        partial_pk,
        server_url,
        ctx,
    );
       
    // Transfer the KeyServer back to the committee
    transfer::public_transfer(ks, committee.id.to_address());
    partial_key_server
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
    ctx: &TxContext,
) {
    assert!(committee.members.contains(&ctx.sender()), ENotMember);

    if (self.upgrade_proposals.contains(digest)) {
        let proposal = self.upgrade_proposals.borrow_mut(digest);
        assert!(!proposal.voters.contains(&ctx.sender()), EAlreadyVoted);
        proposal.voters.push_back(ctx.sender());
    } else {
        let proposal = UpgradeProposal {
            digest,
            voters: vector::empty(),
        };
        self.upgrade_proposals.add(digest, proposal);
    }
}

public fun authorize_upgrade(
    self: &mut UpgradeManager,
    digest: vector<u8>,
): UpgradeTicket {
    assert!(self.upgrade_proposals.contains(digest), ENoProposalForDigest);
    self.upgrade_proposals.remove(digest);

    let policy = self.cap.policy();
    self.cap.authorize(policy, digest)
}