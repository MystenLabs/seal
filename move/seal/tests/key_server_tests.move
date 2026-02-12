// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module seal::key_server_tests;

use seal::key_server::{
    Self,
    KeyServer,
    EInvalidThreshold,
    EInvalidPartyId,
    ENotMember,
    EInvalidServerType,
    EInvalidVersion
};
use std::unit_test::assert_eq;
use sui::{bls12381::g2_generator, test_scenario::{Self, ctx}, vec_map};

// ==== Test Helper Functions ====

/// Helper function to create a committee v2 server with 2 members for testing.
public fun create_2_of_2_committee_server_v2(
    addr1: address,
    addr2: address,
    threshold: u16,
    ctx: &mut TxContext,
): KeyServer {
    let pk = g2_generator();
    let pk_bytes = *pk.bytes();

    let mut partial_key_servers = vec_map::empty();
    partial_key_servers.insert(
        addr1,
        key_server::create_partial_key_server(
            b"server1".to_string(),
            b"https://server1.com".to_string(),
            pk_bytes,
            0,
        ),
    );
    partial_key_servers.insert(
        addr2,
        key_server::create_partial_key_server(
            b"server2".to_string(),
            b"https://server2.com".to_string(),
            pk_bytes,
            1,
        ),
    );

    key_server::create_committee_v2(
        b"committee".to_string(),
        threshold,
        pk_bytes,
        partial_key_servers,
        ctx,
    )
}

/// Helper function to create and transfer a V1 key server for testing.
fun create_and_transfer_v1_test(ctx: &mut TxContext) {
    let pk = g2_generator();
    let pk_bytes = *pk.bytes();

    let key_server = key_server::create_v1_for_testing(
        b"mysten".to_string(),
        b"https:/mysten-labs.com".to_string(),
        0,
        pk_bytes,
        ctx,
    );
    transfer::public_transfer(key_server, ctx.sender());
}

// ==== Tests ====

#[test]
fun independent_server() {
    let addr1 = @0xA;
    let mut scenario = test_scenario::begin(addr1);

    create_and_transfer_v1_test(scenario.ctx());
    scenario.next_tx(addr1);

    let pk = g2_generator();
    let mut s: KeyServer = scenario.take_from_sender();
    assert_eq!(s.name(), b"mysten".to_string());
    assert_eq!(s.url(), b"https:/mysten-labs.com".to_string());
    assert_eq!(*s.pk(), *pk.bytes());

    s.update(b"https:/mysten-labs2.com".to_string());
    assert_eq!(s.url(), b"https:/mysten-labs2.com".to_string());

    s.upgrade_v1_to_independent_v2();
    assert_eq!(s.last_version(), 2);

    s.update(b"https:/mysten-labs3.com".to_string());
    assert_eq!(s.url(), b"https:/mysten-labs3.com".to_string());

    s.destroy_for_testing();
    scenario.end();
}

#[test]
fun committee_v2_server() {
    let addr1 = @0xA;
    let addr2 = @0xB;
    let mut scenario = test_scenario::begin(addr1);

    let s = create_2_of_2_committee_server_v2(addr1, addr2, 2, scenario.ctx());
    let pk = g2_generator();

    assert_eq!(s.name(), b"committee".to_string());
    assert_eq!(*s.pk(), *pk.bytes());
    assert_eq!(s.key_type(), 0);

    let (version, threshold) = s.committee_version_and_threshold();
    assert_eq!(version, 0);
    assert_eq!(threshold, 2);

    let partial1 = s.partial_key_server_for_member(addr1);
    assert_eq!(partial1.partial_ks_url(), b"https://server1.com".to_string());
    assert_eq!(partial1.partial_ks_party_id(), 0);

    let partial2 = s.partial_key_server_for_member(addr2);
    assert_eq!(partial2.partial_ks_url(), b"https://server2.com".to_string());
    assert_eq!(partial2.partial_ks_party_id(), 1);

    s.destroy_for_testing();
    scenario.end();
}

#[test, expected_failure(abort_code = EInvalidThreshold)]
fun create_committee_v2_invalid_threshold() {
    let addr1 = @0xA;
    let addr2 = @0xB;
    let mut scenario = test_scenario::begin(addr1);

    // Threshold of 1 should fail (must be > 1)
    let s = create_2_of_2_committee_server_v2(addr1, addr2, 1, scenario.ctx());
    s.destroy_for_testing();
    scenario.end();
}

#[test, expected_failure(abort_code = EInvalidPartyId)]
fun create_committee_v2_duplicate_party_ids() {
    let addr1 = @0xA;
    let addr2 = @0xB;
    let mut scenario = test_scenario::begin(addr1);

    let pk = g2_generator();
    let pk_bytes = *pk.bytes();

    let mut partial_key_servers = vec_map::empty();
    partial_key_servers.insert(
        addr1,
        key_server::create_partial_key_server(
            b"server1".to_string(),
            b"https://server1.com".to_string(),
            pk_bytes,
            0,
        ),
    );
    partial_key_servers.insert(
        addr2,
        key_server::create_partial_key_server(
            b"server2".to_string(),
            b"https://server2.com".to_string(),
            pk_bytes,
            0, // Duplicate party ID
        ),
    );

    let s = key_server::create_committee_v2(
        b"committee".to_string(),
        2,
        pk_bytes,
        partial_key_servers,
        scenario.ctx(),
    );
    s.destroy_for_testing();
    scenario.end();
}

#[test, expected_failure(abort_code = ENotMember)]
fun update_member_url_not_member() {
    let addr1 = @0xA;
    let addr2 = @0xB;
    let addr3 = @0xC;
    let mut scenario = test_scenario::begin(addr1);

    let mut s = create_2_of_2_committee_server_v2(addr1, addr2, 2, scenario.ctx());

    // Try to update URL for non-member should fail
    s.update_member_url(b"https://server3.com".to_string(), addr3);
    s.destroy_for_testing();
    scenario.end();
}

#[test, expected_failure(abort_code = EInvalidServerType)]
fun update_member_url_on_independent_server() {
    let addr1 = @0xA;
    let mut scenario = test_scenario::begin(addr1);

    create_and_transfer_v1_test(scenario.ctx());
    scenario.next_tx(addr1);

    let mut s: KeyServer = scenario.take_from_sender();
    s.upgrade_v1_to_independent_v2();

    // Try to update member URL on independent server should fail
    s.update_member_url(b"https://newurl.com".to_string(), addr1);
    s.destroy_for_testing();
    scenario.end();
}

#[test, expected_failure(abort_code = EInvalidVersion)]
fun upgrade_v1_to_v2_twice() {
    let addr1 = @0xA;
    let mut scenario = test_scenario::begin(addr1);

    create_and_transfer_v1_test(scenario.ctx());
    scenario.next_tx(addr1);

    let mut s: KeyServer = scenario.take_from_sender();
    s.upgrade_v1_to_independent_v2();

    // Try to upgrade again should fail
    s.upgrade_v1_to_independent_v2();
    s.destroy_for_testing();
    scenario.end();
}
