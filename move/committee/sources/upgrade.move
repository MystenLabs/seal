// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Package upgrade management for committee
module seal_committee::upgrade;

use seal_committee::seal_committee::Committee;
use sui::{package::{UpgradeCap, UpgradeTicket, UpgradeReceipt}, vec_set::{Self, VecSet}};

// ===== Errors =====

const ENotAuthorized: u64 = 10;
const EDuplicateVote: u64 = 11;
const EInvalidPackageDigest: u64 = 12;
const ENoProposalForDigest: u64 = 13;
const ENotEnoughVotes: u64 = 14;
const EWrongVersion: u64 = 15;
const EUpgradeManagerAlreadySet: u64 = 16;
const EInvalidState: u64 = 17;
const ECannotResetAfterThreshold: u64 = 18;

// ===== Structs =====

/// Newtype for package digests, ensures that the digest is always 32 bytes long.
public struct PackageDigest(vector<u8>) has copy, drop, store;

/// An upgrade proposal containing the digest of the package to upgrade to and the votes on the
/// proposal.
public struct UpgradeProposal has drop, store {
    /// The digest of the package to upgrade to.
    digest: PackageDigest,
    /// The version of the package to upgrade to.
    version: u64,
    /// The committee members that have voted for this proposal.
    voters: VecSet<address>,
}

/// The upgrade manager object.
///
/// This object contains the upgrade cap for the package and is used to authorize upgrades.
public struct UpgradeManager has key {
    id: UID,
    cap: UpgradeCap,
    /// The current active upgrade proposal. Only one proposal at a time.
    upgrade_proposal: Option<UpgradeProposal>,
}

// ===== Public Functions =====

/// Create a new upgrade manager for the committee. This should be called after deploying the
/// package and obtaining the UpgradeCap.
public fun new_upgrade_manager(committee: &mut Committee, cap: UpgradeCap, ctx: &mut TxContext) {
    assert!(!committee.has_upgrade_manager_set(), EUpgradeManagerAlreadySet);

    let upgrade_manager = UpgradeManager {
        id: object::new(ctx),
        cap,
        upgrade_proposal: option::none(),
    };
    let upgrade_manager_id = object::id(&upgrade_manager);
    committee.set_upgrade_manager_id(upgrade_manager_id);
    transfer::share_object(upgrade_manager);
}

/// Vote for an upgrade given the digest of the package to upgrade to as a committee member.
public fun vote_for_upgrade(
    upgrade_manager: &mut UpgradeManager,
    committee: &Committee,
    digest: vector<u8>,
    ctx: &TxContext,
) {
    assert!(committee.is_member(ctx.sender()), ENotAuthorized);
    assert!(committee.is_finalized(), EInvalidState);

    let upgrade_manager_id = object::id(upgrade_manager);
    assert!(committee.has_upgrade_manager(upgrade_manager_id), ENotAuthorized);

    // Get or create the proposal.
    let cap_version = upgrade_manager.cap.version();
    if (upgrade_manager.upgrade_proposal.is_none()) {
        let parsed_digest = package_digest!(digest);
        upgrade_manager.upgrade_proposal =
            option::some(UpgradeProposal {
                digest: parsed_digest,
                version: cap_version + 1,
                voters: vec_set::empty(),
            });
    };

    let proposal = upgrade_manager.upgrade_proposal.borrow_mut();

    // Validate digest and version.
    let parsed_digest = package_digest!(digest);
    assert!(proposal.digest.0 == parsed_digest.0, ENoProposalForDigest);
    assert!(proposal.version == cap_version + 1, EWrongVersion);

    // Check not duplicate vote and add vote.
    assert!(!proposal.voters.contains(&ctx.sender()), EDuplicateVote);
    proposal.voters.insert(ctx.sender());
}

/// Authorizes an upgrade that has reached threshold. Anyone can call this.
public fun authorize_upgrade(
    upgrade_manager: &mut UpgradeManager,
    committee: &Committee,
    digest: vector<u8>,
): UpgradeTicket {
    assert!(committee.is_finalized(), EInvalidState);
    assert!(upgrade_manager.upgrade_proposal.is_some(), ENoProposalForDigest);

    let upgrade_manager_id = object::id(upgrade_manager);
    assert!(committee.has_upgrade_manager(upgrade_manager_id), ENotAuthorized);

    let proposal = upgrade_manager.upgrade_proposal.extract();

    // Validate digest and version.
    let parsed_digest = package_digest!(digest);
    assert!(proposal.digest.0 == parsed_digest.0, ENoProposalForDigest);
    assert!(proposal.version == upgrade_manager.cap.version() + 1, EWrongVersion);

    // Check threshold.
    assert!(proposal.voters.length() as u16 >= committee.threshold(), ENotEnoughVotes);

    let policy = upgrade_manager.cap.policy();
    upgrade_manager.cap.authorize(policy, parsed_digest.0)
}

/// Commits an upgrade after authorize to finalize the upgrade.
public fun commit_upgrade(upgrade_manager: &mut UpgradeManager, receipt: UpgradeReceipt) {
    upgrade_manager.cap.commit(receipt)
}

/// Resets the current proposal if it hasn't reached threshold yet.
public fun reset_proposal(
    upgrade_manager: &mut UpgradeManager,
    committee: &Committee,
    ctx: &TxContext,
) {
    assert!(committee.is_member(ctx.sender()), ENotAuthorized);
    assert!(upgrade_manager.upgrade_proposal.is_some(), ENoProposalForDigest);

    let proposal = upgrade_manager.upgrade_proposal.borrow();
    assert!((proposal.voters.length() as u16) < committee.threshold(), ECannotResetAfterThreshold);

    // Clear the proposal.
    upgrade_manager.upgrade_proposal = option::none();
}

// ===== Helper Functions =====

/// Creates a new package digest given a byte vector and check length is 32 bytes.
macro fun package_digest($digest: vector<u8>): PackageDigest {
    let digest = $digest;
    assert!(digest.length() == 32, EInvalidPackageDigest);
    PackageDigest(digest)
}
