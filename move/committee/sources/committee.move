// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Implementation of committee based key server operations. The admin that initializes the
/// committee should deploy this package itself, so that the committee can manage its own upgrade
/// and the key rotation. The key server object is owned by the committee.

module seal_committee::seal_committee;

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
const EInvalidMembers: u64 = 1;
const EInvalidThreshold: u64 = 2;
const EInsufficientOldMembers: u64 = 3;
const EAlreadyRegistered: u64 = 4;
const ENotRegistered: u64 = 5;
const EAlreadyProposed: u64 = 6;
const EInvalidProposal: u64 = 7;
const EInvalidState: u64 = 8;

// ===== Structs =====

/// Member information to register with two public keys and the key server URL.
public struct MemberInfo has copy, drop, store {
    /// ECIES encryption public key, used during offchain DKG.
    enc_pk: vector<u8>,
    /// Signing PK, used during offchain DKG.
    signing_pk: vector<u8>,
    /// URL that the partial key server is running at.
    url: String,
}

/// Valid states of the committee that holds state specific infos.
public enum State has drop, store {
    Init {
        members_info: VecMap<address, MemberInfo>,
    },
    PostDKG {
        members_info: VecMap<address, MemberInfo>,
        partial_pks: vector<vector<u8>>,
        pk: vector<u8>,
        approvals: VecSet<address>,
    },
    Finalized,
}

/// MPC committee with defined threshold and members with its state.
public struct Committee has key {
    id: UID,
    threshold: u16,
    /// The members of the committee. The 'party_id' used in the DKG protocol is the index of this
    /// vector.
    members: vector<address>,
    state: State,
    /// Old committee ID that this committee rotates from.
    old_committee_id: Option<ID>,
}

// ===== Public Functions =====

/// Create a committee for fresh DKG with a list of members and threshold. The committee is in Init
/// state with empty members_info.
public fun init_committee(threshold: u16, members: vector<address>, ctx: &mut TxContext) {
    init_internal(threshold, members, option::none(), ctx)
}

/// Create a committee for rotation from an existing finalized old committee. The new committee must
/// contain an old threshold of the old committee members.
public fun init_rotation(
    old_committee: &Committee,
    threshold: u16,
    members: vector<address>,
    ctx: &mut TxContext,
) {
    // Verify the old committee is finalized for rotation.
    assert!(old_committee.is_finalized(), EInvalidState);

    // Check that new committee has at least the threshold of old committee members.
    let mut continuing_members = 0;
    members.do!(|member| if (old_committee.members.contains(&member)) {
        continuing_members = continuing_members + 1;
    });
    assert!(continuing_members >= (old_committee.threshold), EInsufficientOldMembers);

    init_internal(threshold, members, option::some(old_committee.id()), ctx);
}

/// Register a member with ecies pk, signing pk and URL. Append it to members_info.
public fun register(
    committee: &mut Committee,
    enc_pk: vector<u8>,
    signing_pk: vector<u8>,
    url: String,
    ctx: &mut TxContext,
) {
    // TODO: add checks for enc_pk, signing_pk to be valid elements, maybe PoP.
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    match (&mut committee.state) {
        State::Init { members_info } => {
            let sender = ctx.sender();
            assert!(!members_info.contains(&sender), EAlreadyRegistered);
            members_info.insert(sender, MemberInfo { enc_pk, signing_pk, url });
        },
        _ => abort EInvalidState,
    }
}

/// Propose a fresh DKG committee with a list partial pks (in the order of committee's members list)
/// and master pk. Add the caller to approvals list. If already in PostDKG state, check the submitted
/// partial_pks and pk are consistent with the onchain state, then add the caller to approvals list.
/// If all members have approved, finalize the committee by creating a KeyServerV2 and transfer it
/// to the committee.
public fun propose(
    committee: &mut Committee,
    partial_pks: vector<vector<u8>>,
    pk: vector<u8>,
    ctx: &mut TxContext,
) {
    // For fresh DKG committee only.
    assert!(committee.old_committee_id.is_none(), EInvalidState);
    committee.propose_internal(partial_pks, pk, ctx);
    committee.try_finalize(ctx);
}

/// Propose a rotation from old committee to new one with a list of partial pks. Add the caller to
/// approvals list. If already in PostDKG state, checks that submitted partial_pks are consistent
/// with the onchain state, then add the caller to approvals list.
public fun propose_for_rotation(
    committee: &mut Committee,
    partial_pks: vector<vector<u8>>,
    mut old_committee: Committee,
    key_server: Receiving<KeyServer>,
    ctx: &mut TxContext,
) {
    committee.check_rotation_consistency(&old_committee);
    let key_server = transfer::public_receive(&mut old_committee.id, key_server);
    key_server.assert_committee_server_v2();
    committee.propose_internal(partial_pks, *key_server.pk(), ctx);
    committee.try_finalize_for_rotation(old_committee, key_server);
}

/// Update the url of the partial key server object corresponding to the sender.
public fun update_member_url(
    committee: &mut Committee,
    ks: Receiving<KeyServer>,
    url: String,
    ctx: &mut TxContext,
) {
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    let mut key_server = transfer::public_receive(&mut committee.id, ks);
    key_server.update_member_url(url, ctx.sender());
    transfer::public_transfer(key_server, committee.id.to_address());
}

// TODO: handle package upgrade with threshold approvals of the committee.

// ===== Internal Functions =====

/// Internal function to initialize a shared committee object with optional old committee id.
fun init_internal(
    threshold: u16,
    members: vector<address>,
    old_committee_id: Option<ID>,
    ctx: &mut TxContext,
) {
    assert!(threshold > 0, EInvalidThreshold);
    assert!(members.length() as u16 < std::u16::max_value!(), EInvalidMembers);
    assert!(members.length() as u16 >= threshold, EInvalidThreshold);

    // Verify no duplicate members.
    let members_set = vec_set::from_keys(members);
    assert!(members_set.length() == members.length(), EInvalidMembers);

    transfer::share_object(Committee {
        id: object::new(ctx),
        threshold,
        members,
        state: State::Init { members_info: vec_map::empty() },
        old_committee_id,
    });
}

/// Internal function to handle propose logic for both fresh DKG and rotation.
fun propose_internal(
    committee: &mut Committee,
    partial_pks: vector<vector<u8>>,
    pk: vector<u8>,
    ctx: &TxContext,
) {
    // TODO: add sanity check for partial pks and pk as valid elements.
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    assert!(partial_pks.length() == committee.members.length(), EInvalidProposal);

    match (&mut committee.state) {
        State::Init { members_info } => {
            // Check that all members have registered.
            assert!(members_info.length() == committee.members.length(), ENotRegistered);

            // Move to PostDKG state with the proposal and the caller as the first approval.
            committee.state =
                State::PostDKG {
                    members_info: *members_info,
                    approvals: vec_set::singleton(ctx.sender()),
                    partial_pks,
                    pk,
                };
        },
        State::PostDKG {
            approvals,
            members_info: _,
            partial_pks: existing_partial_pks,
            pk: existing_pk,
        } => {
            // Check that submitted partial_pks and pk are consistent.
            assert!(partial_pks == *existing_partial_pks, EInvalidProposal);
            assert!(pk == *existing_pk, EInvalidProposal);

            // Insert approval and make sure if approval was not inserted before.
            assert!(!approvals.contains(&ctx.sender()), EAlreadyProposed);
            approvals.insert(ctx.sender());
        },
        _ => abort EInvalidState,
    };
}

/// Helper function to finalize the committee for a fresh DKG, creates a new KeyServer and TTO to
/// the committee.
fun try_finalize(committee: &mut Committee, ctx: &mut TxContext) {
    // Sanity check, only for fresh DKG committee.
    assert!(committee.old_committee_id.is_none(), EInvalidState);

    match (&committee.state) {
        State::PostDKG { approvals, members_info, partial_pks, pk } => {
            // Approvals count not reached, exit immediately.
            if (approvals.length() != committee.members.length()) {
                return
            };

            // Build partial key servers from PostDKG state.
            let partial_key_servers = build_partial_key_servers(
                committee.members,
                members_info,
                partial_pks,
            );
            // Create the KeyServerV2 object and transfer it to the committee.
            let ks = create_committee_v2(
                committee.id.to_address().to_string(),
                committee.threshold,
                *pk,
                partial_key_servers,
                ctx,
            );
            transfer::public_transfer(ks, committee.id.to_address());
            committee.state = State::Finalized;
        },
        _ => abort EInvalidState,
    }
}

/// Helper function to finalize rotation for the committee. Transfer the KeyServer from old
/// committee to the new committee and destroys the old committee object. Add all new partial key
/// server as df to key server.
fun try_finalize_for_rotation(
    committee: &mut Committee,
    old_committee: Committee,
    mut key_server: KeyServer,
) {
    committee.check_rotation_consistency(&old_committee);

    match (&committee.state) {
        State::PostDKG { approvals, members_info, partial_pks, .. } => {
            // Approvals count not reached, return key server back to old committee.
            if (approvals.length() != committee.members.length()) {
                transfer::public_transfer(key_server, old_committee.id.to_address());
                transfer::share_object(old_committee);
                return
            };

            // Build partial key servers from PostDKG state and update in key server object.
            let partial_key_servers = build_partial_key_servers(
                committee.members,
                members_info,
                partial_pks,
            );
            key_server.set_partial_key_servers(partial_key_servers);
            transfer::public_transfer(key_server, committee.id.to_address());
            committee.state = State::Finalized;

            // Destroy the old committee object.
            let Committee { id, .. } = old_committee;
            object::delete(id);
        },
        _ => abort EInvalidState,
    }
}

/// Helper function to build the partial key servers VecMap for the list of committee members.
fun build_partial_key_servers(
    members: vector<address>,
    members_info: &VecMap<address, MemberInfo>,
    partial_pks: &vector<vector<u8>>,
): VecMap<address, PartialKeyServer> {
    assert!(members.length() > 0, EInvalidMembers);
    assert!(members.length() == partial_pks.length(), EInvalidMembers);
    assert!(members.length() == members_info.length(), EInvalidMembers);

    let mut partial_key_servers = vec_map::empty();
    let mut i = 0;
    members.do!(|member| {
        partial_key_servers.insert(
            member,
            create_partial_key_server(
                partial_pks[i],
                members_info.get(&member).url,
                i as u16,
            ),
        );
        i = i + 1;
    });
    partial_key_servers
}

/// Helper function to check committee and old committee state for rotation.
fun check_rotation_consistency(self: &Committee, old_committee: &Committee) {
    assert!(self.old_committee_id.is_some(), EInvalidState);
    assert!(old_committee.id() == *self.old_committee_id.borrow(), EInvalidState);
    assert!(old_committee.is_finalized(), EInvalidState);
}

/// Helper function to get the committee ID.
public(package) fun id(committee: &Committee): ID {
    committee.id.to_inner()
}

/// Helper function to check if a committee is finalized.
public(package) fun is_finalized(committee: &Committee): bool {
    match (&committee.state) {
        State::Finalized => true,
        _ => false,
    }
}
