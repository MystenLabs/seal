// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
#[allow(unused_mut_ref, unused_variable, dead_code)]
module seal_committee::seal_committee_tests;

use seal_committee::seal_committee::{Self, Committee, propose_for_rotation, init_rotation};
use seal_testnet::key_server::KeyServer;
use std::string;
use sui::test_scenario::{Self, Scenario};

const ALICE: address = @0x0;
const BOB: address = @0x1;
const CHARLIE: address = @0x2;
const DAVE: address = @0x3;
const EVE: address = @0x4;

#[test]
fun test_scenario_2of3_to_3of4_to_1of3() {
    test_tx!(|scenario| {
        // Create initial 2-of-3 committee.
        seal_committee::init_committee(2, vector[ALICE, BOB, CHARLIE], scenario.ctx());

        // Register all 3 members.
        register_member!(scenario, ALICE, b"enc_pk_0", b"signing_pk_0", b"https://url0.com");
        register_member!(scenario, BOB, b"enc_pk_1", b"signing_pk_1", b"https://url1.com");
        register_member!(scenario, CHARLIE, b"enc_pk_2", b"signing_pk_2", b"https://url2.com");

        // Assuming DKG is completed, all members propose with correct partial keys and master pk.
        let partial_pks = vector[b"partial_pk_0", b"partial_pk_1", b"partial_pk_2"];
        let master_pk = b"master_pk";
        propose_member!(scenario, CHARLIE, partial_pks, master_pk);
        propose_member!(scenario, BOB, partial_pks, master_pk);

        // Committee not finalized, only 2 proposals so far.
        scenario.next_tx(ALICE);
        let committee = scenario.take_shared<Committee>();
        assert!(!committee.is_finalized(), 0);
        test_scenario::return_shared(committee);

        // All 3 proposals, committee finalized.
        propose_member!(scenario, ALICE, partial_pks, master_pk);
        scenario.next_tx(ALICE);
        let committee = scenario.take_shared<Committee>();
        assert!(committee.is_finalized(), 0);
        let old_committee_id = object::id(&committee);
        test_scenario::return_shared(committee);

        // Verify KeyServer is attached to committee as dynamic field object.
        scenario.next_tx(ALICE);
        let committee = scenario.take_shared_by_id<Committee>(old_committee_id);
        let key_server = committee.borrow_key_server();

        assert_key_server_version!(key_server, 0);

        // Verify partial key servers (ALICE=party0, BOB=party1, CHARLIE=party2).
        assert_partial_key_server!(key_server, ALICE, b"https://url0.com", b"partial_pk_0", 0);
        assert_partial_key_server!(key_server, BOB, b"https://url1.com", b"partial_pk_1", 1);
        assert_partial_key_server!(key_server, CHARLIE, b"https://url2.com", b"partial_pk_2", 2);
        test_scenario::return_shared(committee);

        // Initialize rotation from old committee (2-of-3): A, B, C to new committee (3-of-4): B, A, D, E.
        scenario.next_tx(BOB);
        let old_committee = scenario.take_shared_by_id<Committee>(old_committee_id);
        old_committee.init_rotation(
            3,
            vector[BOB, ALICE, DAVE, EVE],
            scenario.ctx(),
        );
        test_scenario::return_shared(old_committee);

        // Get the new committee shared obj.
        scenario.next_tx(BOB);
        let committee = scenario.take_shared<Committee>();
        let committee_id = object::id(&committee);
        let new_committee = if (committee_id == old_committee_id) {
            test_scenario::return_shared(committee);
            scenario.take_shared<Committee>()
        } else {
            committee
        };
        let new_committee_id = object::id(&new_committee);
        test_scenario::return_shared(new_committee);

        // Register all 4 members (2 continuing, 2 new) for the new committee.
        register_member_by_id!(
            scenario,
            ALICE,
            new_committee_id,
            b"enc_pk_0",
            b"signing_pk_0",
            b"https://new_url0.com",
        );
        register_member_by_id!(
            scenario,
            BOB,
            new_committee_id,
            b"enc_pk_1",
            b"signing_pk_1",
            b"https://new_url1.com",
        );
        register_member_by_id!(
            scenario,
            DAVE,
            new_committee_id,
            b"enc_pk_3",
            b"signing_pk_3",
            b"https://new_url3.com",
        );
        register_member_by_id!(
            scenario,
            EVE,
            new_committee_id,
            b"enc_pk_4",
            b"signing_pk_4",
            b"https://new_url4.com",
        );

        // Propose rotation with all 4 members.
        let new_partial_pks = vector[b"pk1", b"pk0", b"pk3", b"pk4"];
        propose_for_rotation_member!(
            scenario,
            BOB,
            new_committee_id,
            old_committee_id,
            new_partial_pks,
        );
        propose_for_rotation_member!(
            scenario,
            ALICE,
            new_committee_id,
            old_committee_id,
            new_partial_pks,
        );
        propose_for_rotation_member!(
            scenario,
            DAVE,
            new_committee_id,
            old_committee_id,
            new_partial_pks,
        );
        propose_for_rotation_member!(
            scenario,
            EVE,
            new_committee_id,
            old_committee_id,
            new_partial_pks,
        );

        // New committee finalized.
        scenario.next_tx(BOB);
        let new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
        assert!(new_committee.is_finalized(), 0);
        test_scenario::return_shared(new_committee);

        // Verify old committee has been destroyed.
        assert!(!test_scenario::has_most_recent_shared<Committee>(), 0);
        scenario.next_tx(BOB);
        // New committee has the key server as df.
        let new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
        let key_server = new_committee.borrow_key_server();

        // Version incremented to 1.
        assert_key_server_version!(key_server, 1);

        // Verify each member's URL, partial PK, and party ID (BOB=party0, ALICE=party1, DAVE=party2, EVE=party3).
        assert_partial_key_server!(key_server, BOB, b"https://new_url1.com", b"pk1", 0);
        assert_partial_key_server!(key_server, ALICE, b"https://new_url0.com", b"pk0", 1);
        assert_partial_key_server!(key_server, DAVE, b"https://new_url3.com", b"pk3", 2);
        assert_partial_key_server!(key_server, EVE, b"https://new_url4.com", b"pk4", 3);
        test_scenario::return_shared(new_committee);

        // BOB updates URL.
        scenario.next_tx(BOB);
        let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
        new_committee.update_member_url(
            string::utf8(b"https://new_url1.com"),
            scenario.ctx(),
        );
        test_scenario::return_shared(new_committee);

        // Initialize rotation to 1-of-3 committee with shuffled order: EVE, ALICE, and BOB.
        scenario.next_tx(BOB);
        let second_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
        second_committee.init_rotation(
            1,
            vector[EVE, ALICE, BOB],
            scenario.ctx(),
        );
        test_scenario::return_shared(second_committee);

        // Get the third committee shared obj.
        scenario.next_tx(BOB);
        let committee = scenario.take_shared<Committee>();
        let committee_id = object::id(&committee);
        let third_committee = if (committee_id == new_committee_id) {
            test_scenario::return_shared(committee);
            scenario.take_shared<Committee>()
        } else {
            committee
        };
        let third_committee_id = object::id(&third_committee);
        test_scenario::return_shared(third_committee);

        // Register all 3 members for the third committee.
        register_member_by_id!(
            scenario,
            EVE,
            third_committee_id,
            b"enc_pk_eve_3",
            b"signing_pk_eve_3",
            b"https://eve_url_3.com",
        );
        register_member_by_id!(
            scenario,
            ALICE,
            third_committee_id,
            b"enc_pk_alice_3",
            b"signing_pk_alice_3",
            b"https://alice_url_3.com",
        );
        register_member_by_id!(
            scenario,
            BOB,
            third_committee_id,
            b"enc_pk_bob_3",
            b"signing_pk_bob_3",
            b"https://bob_url_3.com",
        );

        // Propose rotation with all 3 members.
        let third_partial_pks = vector[b"eve_pk_3", b"alice_pk_3", b"bob_pk_3"];
        propose_for_rotation_member!(
            scenario,
            EVE,
            third_committee_id,
            new_committee_id,
            third_partial_pks,
        );
        propose_for_rotation_member!(
            scenario,
            ALICE,
            third_committee_id,
            new_committee_id,
            third_partial_pks,
        );

        // Committee not finalized yet, only 2 proposals so far.
        scenario.next_tx(BOB);
        let third_committee = scenario.take_shared_by_id<Committee>(third_committee_id);
        assert!(!third_committee.is_finalized(), 0);
        test_scenario::return_shared(third_committee);

        propose_for_rotation_member!(
            scenario,
            BOB,
            third_committee_id,
            new_committee_id,
            third_partial_pks,
        );

        // Third committee finalized.
        scenario.next_tx(BOB);
        let third_committee = scenario.take_shared_by_id<Committee>(third_committee_id);
        assert!(third_committee.is_finalized(), 0);
        test_scenario::return_shared(third_committee);

        // Verify second committee (new_committee) has been destroyed.
        assert!(!test_scenario::has_most_recent_shared<Committee>(), 0);
        scenario.next_tx(BOB);

        // Third committee has the key server as df.
        let third_committee = scenario.take_shared_by_id<Committee>(third_committee_id);
        let key_server = third_committee.borrow_key_server();

        // Version incremented to 2.
        assert_key_server_version!(key_server, 2);

        // Verify all members' URLs, partial PKs, and party IDs (EVE=party0, ALICE=party1, BOB=party2).
        assert_partial_key_server!(key_server, EVE, b"https://eve_url_3.com", b"eve_pk_3", 0);
        assert_partial_key_server!(key_server, ALICE, b"https://alice_url_3.com", b"alice_pk_3", 1);
        assert_partial_key_server!(key_server, BOB, b"https://bob_url_3.com", b"bob_pk_3", 2);
        test_scenario::return_shared(third_committee);
    });
}

#[test, expected_failure(abort_code = seal_committee::EInvalidThreshold)]
fun test_init_committee_with_zero_threshold() {
    test_tx!(|scenario| {
        seal_committee::init_committee(0, vector[BOB, CHARLIE], scenario.ctx());
    });
}

#[test, expected_failure(abort_code = seal_committee::EInvalidThreshold)]
fun test_init_committee_with_threshold_exceeding_members() {
    test_tx!(|scenario| {
        seal_committee::init_committee(3, vector[BOB, CHARLIE], scenario.ctx());
    });
}

#[test, expected_failure(abort_code = sui::vec_set::EKeyAlreadyExists)]
fun test_init_committee_with_duplicate_members() {
    test_tx!(|scenario| {
        seal_committee::init_committee(2, vector[BOB, BOB, CHARLIE], scenario.ctx());
    });
}

#[test, expected_failure(abort_code = seal_committee::EInvalidThreshold)]
fun test_init_committee_with_empty_members() {
    test_tx!(|scenario| {
        seal_committee::init_committee(1, vector[], scenario.ctx());
    });
}

#[test, expected_failure(abort_code = seal_committee::EInsufficientOldMembers)]
fun test_init_rotation_fails_with_not_enough_old_members() {
    test_tx!(|scenario| {
        // Init and finalize committee with BOB only.
        seal_committee::init_committee(1, vector[BOB], scenario.ctx());
        register_member!(scenario, BOB, b"enc_pk_1", b"signing_pk_1", b"url1");
        propose_member!(scenario, BOB, vector[b"pk_1"], b"master");

        scenario.next_tx(BOB);
        let committee = scenario.take_shared<Committee>();
        // Rotate with no continuing members - fails.
        committee.init_rotation(
            2,
            vector[CHARLIE, DAVE],
            scenario.ctx(),
        );

        test_scenario::return_shared(committee);
    });
}

#[test, expected_failure(abort_code = seal_committee::EInvalidState)]
fun test_init_rotation_fails_with_non_finalized_old_committee() {
    test_tx!(|scenario| {
        seal_committee::init_committee(2, vector[BOB, CHARLIE], scenario.ctx());

        register_member!(scenario, BOB, b"enc_pk_1", b"signing_pk_1", b"url1");
        register_member!(scenario, CHARLIE, b"enc_pk_2", b"signing_pk_2", b"url2");
        propose_member!(scenario, CHARLIE, vector[b"pk_1", b"pk_2"], b"master");
        scenario.next_tx(BOB);
        let committee = scenario.take_shared<Committee>();

        // Current committee in PostDKG state, not finalized - fails rotation.
        committee.init_rotation(
            2,
            vector[CHARLIE, DAVE],
            scenario.ctx(),
        );

        test_scenario::return_shared(committee);
    });
}

#[test, expected_failure(abort_code = seal_committee::ENotMember)]
fun test_register_fails_for_non_member() {
    test_tx!(|scenario| {
        seal_committee::init_committee(2, vector[BOB, CHARLIE], scenario.ctx());

        scenario.next_tx(DAVE);
        let mut committee = scenario.take_shared<Committee>();
        committee.register(b"enc_pk_3", b"signing_pk_3", string::utf8(b"url3"), scenario.ctx());

        test_scenario::return_shared(committee);
    });
}

#[test, expected_failure(abort_code = seal_committee::EAlreadyRegistered)]
fun test_register_fails_when_already_registered() {
    test_tx!(|scenario| {
        seal_committee::init_committee(2, vector[BOB, CHARLIE], scenario.ctx());
        scenario.next_tx(BOB);

        let mut committee = scenario.take_shared<Committee>();
        committee.register(b"enc_pk_1", b"signing_pk_1", string::utf8(b"url1"), scenario.ctx());
        // Register again as same member fails.
        committee.register(b"enc_pk_2", b"signing_pk_2", string::utf8(b"url2"), scenario.ctx());

        test_scenario::return_shared(committee);
    });
}

#[test, expected_failure(abort_code = seal_committee::EInvalidState)]
fun test_register_fails_when_not_in_init_state() {
    test_tx!(|scenario| {
        seal_committee::init_committee(1, vector[BOB], scenario.ctx());

        register_member!(scenario, BOB, b"enc_pk_1", b"signing_pk_1", b"url1");
        propose_member!(scenario, BOB, vector[b"pk_1"], b"master");

        // Now in Finalized state.
        scenario.next_tx(BOB);
        let mut committee = scenario.take_shared<Committee>();

        // Try to register in Finalized state - fails.
        committee.register(b"enc_pk_2", b"signing_pk_2", string::utf8(b"url2"), scenario.ctx());
        test_scenario::return_shared(committee);
    });
}

#[test, expected_failure(abort_code = seal_committee::ENotMember)]
fun test_propose_fails_for_non_member() {
    test_tx!(|scenario| {
        seal_committee::init_committee(2, vector[BOB, CHARLIE], scenario.ctx());

        // Register members.
        register_member!(scenario, BOB, b"enc_pk_1", b"signing_pk_1", b"url1");
        register_member!(scenario, CHARLIE, b"enc_pk_2", b"signing_pk_2", b"url2");

        // Non-member @0x3 tries to propose - fails.
        propose_member!(scenario, DAVE, vector[b"pk_1", b"pk_2"], b"master");
    });
}

#[test, expected_failure(abort_code = seal_committee::EInvalidProposal)]
fun test_propose_fails_with_wrong_partial_pks_count() {
    test_tx!(|scenario| {
        seal_committee::init_committee(2, vector[BOB, CHARLIE], scenario.ctx());

        register_member!(scenario, BOB, b"enc_pk_1", b"signing_pk_1", b"url1");
        register_member!(scenario, CHARLIE, b"enc_pk_2", b"signing_pk_2", b"url2");

        // Propose with only 1 partial_pk instead of 2 - fails.
        propose_member!(scenario, CHARLIE, vector[b"partial_pk_1"], b"master_pk");
    });
}

#[test, expected_failure(abort_code = seal_committee::EInvalidProposal)]
fun test_propose_fails_with_mismatched_pk() {
    test_tx!(|scenario| {
        seal_committee::init_committee(2, vector[BOB, CHARLIE], scenario.ctx());
        register_member!(scenario, BOB, b"enc_pk_1", b"signing_pk_1", b"url1");
        register_member!(scenario, CHARLIE, b"enc_pk_2", b"signing_pk_2", b"url2");

        propose_member!(scenario, CHARLIE, vector[b"partial_pk_1", b"partial_pk_2"], b"master_pk");
        // Propose with mismatched partial pk, fails.
        propose_member!(scenario, CHARLIE, vector[b"blah", b"partial_pk_2"], b"master_pk");
    });
}

#[test, expected_failure(abort_code = seal_committee::ENotRegistered)]
fun test_propose_fails_when_not_all_registered() {
    test_tx!(|scenario| {
        seal_committee::init_committee(2, vector[BOB, CHARLIE], scenario.ctx());

        register_member!(scenario, BOB, b"enc_pk_3", b"signing_pk_3", b"url3");

        // @0x2 not registered, propose fails.
        propose_member!(scenario, BOB, vector[b"partial_pk_1", b"partial_pk_2"], b"master_pk");
    });
}

#[test, expected_failure(abort_code = seal_committee::EAlreadyProposed)]
fun test_propose_fails_on_duplicate_approval() {
    test_tx!(|scenario| {
        seal_committee::init_committee(2, vector[BOB, CHARLIE], scenario.ctx());

        register_member!(scenario, BOB, b"enc_pk_1", b"signing_pk_1", b"url1");
        register_member!(scenario, CHARLIE, b"enc_pk_2", b"signing_pk_2", b"url2");

        // First proposal from CHARLIE.
        let partial_pks = vector[b"partial_pk_1", b"partial_pk_2"];
        let pk = b"master_pk";
        propose_member!(scenario, CHARLIE, partial_pks, pk);

        // Try to propose again from same member CHARLIE - fails.
        propose_member!(scenario, CHARLIE, partial_pks, pk);
    });
}

#[test, expected_failure(abort_code = seal_committee::EInvalidState)]
fun test_propose_fails_committee_has_old_committee_id() {
    test_tx!(|scenario| {
        // Create and finalize first committee (1-of-1 with BOB).
        seal_committee::init_committee(1, vector[BOB], scenario.ctx());
        register_member!(scenario, BOB, b"enc_pk_1", b"signing_pk_1", b"url1");
        propose_member!(scenario, BOB, vector[b"partial_pk_1"], b"master_pk");

        scenario.next_tx(BOB);
        let old_committee = scenario.take_shared<Committee>();
        let old_committee_id = object::id(&old_committee);
        test_scenario::return_shared(old_committee);

        // Initialize rotation committee from the old committee.
        scenario.next_tx(BOB);
        let old_committee = scenario.take_shared_by_id<Committee>(old_committee_id);
        old_committee.init_rotation(1, vector[BOB], scenario.ctx());
        test_scenario::return_shared(old_committee);

        // Get the new committee (which has old_committee_id.is_some()).
        scenario.next_tx(BOB);
        let new_committee = scenario.take_shared<Committee>();
        let new_committee_id = object::id(&new_committee);
        test_scenario::return_shared(new_committee);

        // Register BOB for the new committee.
        register_member_by_id!(
            scenario,
            BOB,
            new_committee_id,
            b"enc_pk_1",
            b"signing_pk_1",
            b"url1",
        );

        // Try to call propose (instead of propose_for_rotation) on rotation committee.
        // This should fail because propose is only for fresh DKG committees.
        scenario.next_tx(BOB);
        let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
        new_committee.propose(vector[b"partial_pk_1"], b"master_pk", scenario.ctx());
        test_scenario::return_shared(new_committee);
    });
}

#[test, expected_failure(abort_code = seal_committee::EInvalidState)]
fun test_finalize_for_rotation_mismatched_old_committee() {
    test_tx!(|scenario| {
        // Create first committee (1-of-1).
        seal_committee::init_committee(1, vector[ALICE], scenario.ctx());
        register_member!(scenario, ALICE, b"enc_pk_0", b"signing_pk_0", b"https://url0.com");

        let partial_pks = vector[b"partial_pk_0"];
        let master_pk = b"master_pk";
        propose_member!(scenario, ALICE, partial_pks, master_pk);

        scenario.next_tx(ALICE);
        let first_committee = scenario.take_shared<Committee>();
        let first_committee_id = object::id(&first_committee);
        test_scenario::return_shared(first_committee);

        // Create second unrelated committee (1-of-1).
        seal_committee::init_committee(1, vector[DAVE], scenario.ctx());
        register_member!(scenario, DAVE, b"enc_pk_3", b"signing_pk_3", b"https://url3.com");
        let partial_pks2 = vector[b"partial_pk_3"];
        propose_member!(scenario, DAVE, partial_pks2, master_pk);

        scenario.next_tx(DAVE);
        let second_committee = scenario.take_shared<Committee>();
        let second_committee_id = object::id(&second_committee);
        test_scenario::return_shared(second_committee);

        // Initialize rotation from first committee.
        scenario.next_tx(ALICE);
        let first_committee = scenario.take_shared_by_id<Committee>(first_committee_id);
        first_committee.init_rotation(2, vector[ALICE, BOB], scenario.ctx());
        test_scenario::return_shared(first_committee);

        // Get new committee created by rotation.
        scenario.next_tx(ALICE);
        let new_committee = scenario.take_shared<Committee>();
        let new_committee_id = object::id(&new_committee);
        test_scenario::return_shared(new_committee);

        // Register members for new committee.
        register_member_by_id!(
            scenario,
            ALICE,
            new_committee_id,
            b"enc_pk_0",
            b"signing_pk_0",
            b"https://new_url0.com",
        );
        register_member_by_id!(
            scenario,
            BOB,
            new_committee_id,
            b"enc_pk_1",
            b"signing_pk_1",
            b"https://new_url1.com",
        );

        // Try to propose rotation with wrong old committee, fails with EInvalidState.
        let new_partial_pks = vector[b"pk0", b"pk1"];
        scenario.next_tx(ALICE);
        let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
        let wrong_committee = scenario.take_shared_by_id<Committee>(second_committee_id);
        new_committee.propose_for_rotation(
            new_partial_pks,
            wrong_committee,
            scenario.ctx(),
        );
        test_scenario::return_shared(new_committee);
    });
}

#[test, expected_failure(abort_code = seal_committee::EInvalidState)]
fun test_finalize_for_rotation_invalid_state() {
    test_tx!(|scenario| {
        // Create first committee (1-of-1).
        seal_committee::init_committee(1, vector[ALICE], scenario.ctx());
        register_member!(scenario, ALICE, b"enc_pk_0", b"signing_pk_0", b"https://url0.com");

        let partial_pks = vector[b"partial_pk_0"];
        let master_pk = b"master_pk";
        propose_member!(scenario, ALICE, partial_pks, master_pk);

        scenario.next_tx(ALICE);
        let first_committee = scenario.take_shared<Committee>();
        let first_committee_id = object::id(&first_committee);
        test_scenario::return_shared(first_committee);

        // Create a second committee that is NOT a rotation (no old_committee_id) (1-of-1).
        seal_committee::init_committee(1, vector[DAVE], scenario.ctx());
        register_member!(scenario, DAVE, b"enc_pk_3", b"signing_pk_3", b"https://url3.com");
        let partial_pks2 = vector[b"partial_pk_3"];
        propose_member!(scenario, DAVE, partial_pks2, master_pk);

        scenario.next_tx(DAVE);
        let second_committee = scenario.take_shared<Committee>();
        let second_committee_id = object::id(&second_committee);
        test_scenario::return_shared(second_committee);

        // Try to call propose_for_rotation on second_committee, fails with EInvalidState.
        let new_partial_pks = vector[b"pk3"];
        scenario.next_tx(DAVE);
        let mut second_committee = scenario.take_shared_by_id<Committee>(second_committee_id);
        let first_committee = scenario.take_shared_by_id<Committee>(first_committee_id);
        second_committee.propose_for_rotation(
            new_partial_pks,
            first_committee,
            scenario.ctx(),
        );
        test_scenario::return_shared(second_committee);
    });
}

#[test, expected_failure(abort_code = seal_committee::ENotMember)]
fun test_update_url_fails_for_non_member() {
    test_tx!(|scenario| {
        seal_committee::init_committee(1, vector[ALICE], scenario.ctx());
        register_member!(scenario, ALICE, b"enc_pk_0", b"signing_pk_0", b"https://url0.com");
        propose_member!(scenario, ALICE, vector[b"pk0"], b"master_pk");

        scenario.next_tx(ALICE);
        let committee = scenario.take_shared<Committee>();
        let committee_id = object::id(&committee);
        test_scenario::return_shared(committee);

        // BOB (non-member) tries to update URL, fails.
        scenario.next_tx(BOB);
        let mut committee = scenario.take_shared_by_id<Committee>(committee_id);
        committee.update_member_url(
            string::utf8(b"https://new_url.com"),
            scenario.ctx(),
        );
        test_scenario::return_shared(committee);
    });
}

// ===== Helper Macros =====

/// Scaffold a test tx that returns the test scenario.
public macro fun test_tx($f: |&mut Scenario|) {
    let mut scenario = test_scenario::begin(BOB);

    $f(&mut scenario);

    scenario.end();
}

/// Helper macro to register a member.
public macro fun register_member(
    $scenario: &mut Scenario,
    $member: address,
    $enc_pk: vector<u8>,
    $signing_pk: vector<u8>,
    $url: vector<u8>,
) {
    let scenario = $scenario;
    let member = $member;
    let enc_pk = $enc_pk;
    let signing_pk = $signing_pk;
    let url = $url;

    scenario.next_tx(member);
    let mut committee = scenario.take_shared<Committee>();
    committee.register(enc_pk, signing_pk, string::utf8(url), scenario.ctx());
    test_scenario::return_shared(committee);
}

/// Helper macro to register a member by committee ID.
public macro fun register_member_by_id(
    $scenario: &mut Scenario,
    $member: address,
    $committee_id: ID,
    $enc_pk: vector<u8>,
    $signing_pk: vector<u8>,
    $url: vector<u8>,
) {
    let scenario = $scenario;
    let member = $member;
    let committee_id = $committee_id;
    let enc_pk = $enc_pk;
    let signing_pk = $signing_pk;
    let url = $url;

    scenario.next_tx(member);
    let mut committee = scenario.take_shared_by_id<Committee>(committee_id);
    committee.register(enc_pk, signing_pk, string::utf8(url), scenario.ctx());
    test_scenario::return_shared(committee);
}

/// Helper macro to propose for a fresh DKG committee.
public macro fun propose_member(
    $scenario: &mut Scenario,
    $member: address,
    $partial_pks: vector<vector<u8>>,
    $pk: vector<u8>,
) {
    let scenario = $scenario;
    let member = $member;
    let partial_pks = $partial_pks;
    let pk = $pk;

    scenario.next_tx(member);
    let mut committee = scenario.take_shared<Committee>();
    committee.propose(partial_pks, pk, scenario.ctx());
    test_scenario::return_shared(committee);
}

/// Helper macro to propose for rotation.
public macro fun propose_for_rotation_member(
    $scenario: &mut Scenario,
    $member: address,
    $new_committee_id: ID,
    $old_committee_id: ID,
    $partial_pks: vector<vector<u8>>,
) {
    let scenario = $scenario;
    let member = $member;
    let new_committee_id = $new_committee_id;
    let old_committee_id = $old_committee_id;
    let partial_pks = $partial_pks;

    scenario.next_tx(member);
    let mut new_committee = scenario.take_shared_by_id<Committee>(new_committee_id);
    let old_committee = scenario.take_shared_by_id<Committee>(old_committee_id);
    new_committee.propose_for_rotation(partial_pks, old_committee, scenario.ctx());
    test_scenario::return_shared(new_committee);
}

/// Helper macro to assert partial key server URL, partial PK, and party ID.
public macro fun assert_partial_key_server(
    $key_server: &KeyServer,
    $member: address,
    $expected_url: vector<u8>,
    $expected_partial_pk: vector<u8>,
    $expected_party_id: u16,
) {
    let key_server = $key_server;
    let member = $member;
    let expected_url = $expected_url;
    let expected_partial_pk = $expected_partial_pk;
    let expected_party_id = $expected_party_id;

    let partial_ks = key_server.partial_key_server_for_member(member);
    assert!(partial_ks.partial_ks_url() == string::utf8(expected_url));
    assert!(partial_ks.partial_ks_pk() == expected_partial_pk);
    assert!(partial_ks.partial_ks_party_id() == expected_party_id);
}

/// Helper macro to assert key server version.
public macro fun assert_key_server_version($key_server: &KeyServer, $expected_version: u32) {
    let key_server = $key_server;
    let expected_version = $expected_version;

    assert!(key_server.committee_version() == expected_version);
}
