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
use sui::{
    bls12381::{g1_from_bytes, g2_from_bytes},
    dynamic_object_field as dof,
    vec_map::{Self, VecMap},
    vec_set::{Self, VecSet}
};

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
const ENameAlreadyTaken: u64 = 9;

// ===== Structs =====

/// Member information to register with two public keys and the key server URL.
public struct MemberInfo has copy, drop, store {
    /// ECIES encryption public key, used during offchain DKG.
    enc_pk: vector<u8>,
    /// Signing PK, used during offchain DKG.
    signing_pk: vector<u8>,
    /// URL that the partial key server is running at.
    url: String,
    /// Name of member key server.
    name: String,
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

    init_internal(threshold, members, option::some(object::id(old_committee)), ctx);
}

/// Register a member with ecies pk, signing pk and URL. Append it to members_info.
public fun register(
    committee: &mut Committee,
    enc_pk: vector<u8>,
    signing_pk: vector<u8>,
    url: String,
    name: String,
    ctx: &mut TxContext,
) {
    // TODO: maybe check PoP for the public keys.
    let _ = g1_from_bytes(&enc_pk);
    let _ = g2_from_bytes(&signing_pk);

    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    match (&mut committee.state) {
        State::Init { members_info } => {
            let sender = ctx.sender();
            assert!(!members_info.contains(&sender), EAlreadyRegistered);

            // Check unique name
            members_info.keys().do!(|member_addr| {
                let existing_info = members_info.get(&member_addr);
                assert!(existing_info.name != name, ENameAlreadyTaken);
            });

            members_info.insert(sender, MemberInfo { enc_pk, signing_pk, url, name });
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
    ctx: &mut TxContext,
) {
    committee.check_rotation_consistency(&old_committee);
    let old_committee_id = object::id(&old_committee);
    let key_server = dof::remove<ID, KeyServer>(&mut old_committee.id, old_committee_id);
    key_server.assert_committee_server_v2();
    committee.propose_internal(partial_pks, *key_server.pk(), ctx);
    committee.try_finalize_for_rotation(old_committee, key_server);
}

/// Update the url of the partial key server object corresponding to the sender.
public fun update_member_url(committee: &mut Committee, url: String, ctx: &mut TxContext) {
    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    let committee_id = object::id(committee);
    let key_server = dof::borrow_mut<ID, KeyServer>(&mut committee.id, committee_id);
    key_server.update_member_url(url, ctx.sender());
}

// TODO: handle package upgrade with threshold approvals of the committee.

/// Helper function to check if a committee is finalized.
public(package) fun is_finalized(committee: &Committee): bool {
    match (&committee.state) {
        State::Finalized => true,
        _ => false,
    }
}

// ===== Internal Functions =====

/// Internal function to initialize a shared committee object with optional old committee id.
fun init_internal(
    threshold: u16,
    members: vector<address>,
    old_committee_id: Option<ID>,
    ctx: &mut TxContext,
) {
    assert!(threshold > 1, EInvalidThreshold);
    assert!(members.length() as u16 < std::u16::max_value!(), EInvalidMembers);
    assert!(members.length() as u16 >= threshold, EInvalidThreshold);

    // Throws EKeyAlreadyExists if duplicate members are found.
    let _ = vec_set::from_keys(members);

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
    // Validate partial pks and pk as valid G2 elements.
    let _ = g2_from_bytes(&pk);
    partial_pks.do_ref!(|partial_pk| {
        let _ = g2_from_bytes(partial_pk);
    });

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
            let partial_key_servers = committee.build_partial_key_servers(
                members_info,
                partial_pks,
            );
            // Create the KeyServerV2 object and attach it to the committee as dynamic object field.
            let ks = create_committee_v2(
                committee.id.to_address().to_string(),
                committee.threshold,
                *pk,
                partial_key_servers,
                ctx,
            );
            let committee_id = object::id(committee);
            dof::add<ID, KeyServer>(&mut committee.id, committee_id, ks);
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
    mut old_committee: Committee,
    mut key_server: KeyServer,
) {
    committee.check_rotation_consistency(&old_committee);

    match (&committee.state) {
        State::PostDKG { approvals, members_info, partial_pks, .. } => {
            // Approvals count not reached, return key server back to old committee as dynamic object field.
            if (approvals.length() != committee.members.length()) {
                let old_committee_id = object::id(&old_committee);
                dof::add<ID, KeyServer>(&mut old_committee.id, old_committee_id, key_server);
                transfer::share_object(old_committee);
                return
            };

            // Build partial key servers from PostDKG state and update in key server object.
            let partial_key_servers = committee.build_partial_key_servers(
                members_info,
                partial_pks,
            );
            key_server.update_partial_key_servers(committee.threshold, partial_key_servers);
            let committee_id = object::id(committee);
            dof::add<ID, KeyServer>(&mut committee.id, committee_id, key_server);
            committee.state = State::Finalized;

            // Destroy the old committee object.
            let Committee { id, .. } = old_committee;
            id.delete();
        },
        _ => abort EInvalidState,
    }
}

/// Helper function to build the partial key servers VecMap for the list of committee members.
fun build_partial_key_servers(
    committee: &Committee,
    members_info: &VecMap<address, MemberInfo>,
    partial_pks: &vector<vector<u8>>,
): VecMap<address, PartialKeyServer> {
    let members = committee.members;
    assert!(members.length() > 0, EInvalidMembers);
    assert!(members.length() == partial_pks.length(), EInvalidMembers);
    assert!(members.length() == members_info.length(), EInvalidMembers);

    let mut partial_key_servers = vec_map::empty();
    let mut i = 0;
    members.do!(|member| {
        partial_key_servers.insert(
            member,
            create_partial_key_server(
                members_info.get(&member).name,
                members_info.get(&member).url,
                partial_pks[i],
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
    assert!(object::id(old_committee) == *self.old_committee_id.borrow(), EInvalidState);
    assert!(old_committee.is_finalized(), EInvalidState);
}

/// Test-only function to borrow the KeyServer dynamic object field.
#[test_only]
public(package) fun borrow_key_server(committee: &Committee): &KeyServer {
    dof::borrow<ID, KeyServer>(&committee.id, object::id(committee))
}
