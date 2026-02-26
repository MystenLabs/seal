// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module seal::key_server_tests;

use seal::key_server::{
    Self,
    KeyServer,
    EInvalidThreshold,
    EInvalidPartyId,
    EInvalidServerType,
    EInvalidVersion,
    pk
};
use std::unit_test::assert_eq;
use sui::{bls12381::g2_generator, test_scenario::{Self, ctx}};

// ==== Test Helper Functions ====

/// Helper function to create a committee v2 server with 2 members for testing.
public fun create_2_of_2_committee_server_v2(threshold: u16, ctx: &mut TxContext): KeyServer {
    let pk = g2_generator();
    let pk_bytes = *pk.bytes();

    let mut partial_key_servers = vector::empty();
    partial_key_servers.push_back(
        key_server::create_partial_key_server(
            b"server1".to_string(),
            b"https://server1.com".to_string(),
            pk_bytes,
            0,
        ),
    );
    partial_key_servers.push_back(
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

// ==== Tests ====

#[test]
fun independent_server() {
    let addr1 = @0xA;
    let mut scenario = test_scenario::begin(addr1);

    // Test v1 create.
    let pk = g2_generator();
    key_server::create_and_transfer_v1(
        b"mysten".to_string(),
        b"https:/mysten-labs.com".to_string(),
        0,
        *pk.bytes(),
        scenario.ctx(),
    );
    scenario.next_tx(addr1);

    let mut s: KeyServer = scenario.take_from_sender();
    assert_eq!(s.name(), b"mysten".to_string());
    assert_eq!(s.url(), b"https:/mysten-labs.com".to_string());
    assert_eq!(*s.pk(), *pk.bytes());

    // Verify url update.
    s.update(b"https:/mysten-labs2.com".to_string());
    assert_eq!(s.url(), b"https:/mysten-labs2.com".to_string());

    // Test v1 upgrade to v2 independent.
    s.upgrade_v1_to_independent_v2();
    assert_eq!(s.last_version(), 2);

    s.update(b"https:/mysten-labs3.com".to_string());
    assert_eq!(s.url(), b"https:/mysten-labs3.com".to_string());

    s.destroy_for_testing();

    // Test fresh v2 independent create.
    let pk = g2_generator();
    key_server::create_and_transfer_v2_independent_server(
        b"mysten_v2".to_string(),
        b"https://mysten-labs-v2.com".to_string(),
        0,
        *pk.bytes(),
        scenario.ctx(),
    );
    scenario.next_tx(addr1);

    let mut s: KeyServer = scenario.take_from_sender();
    assert_eq!(s.name(), b"mysten_v2".to_string());
    assert_eq!(s.url(), b"https://mysten-labs-v2.com".to_string());
    assert_eq!(*s.pk(), *pk.bytes());
    assert_eq!(s.key_type(), 0);
    assert_eq!(s.last_version(), 2);

    // Verify url update.
    s.update(b"https://mysten-labs-updated.com".to_string());
    assert_eq!(s.url(), b"https://mysten-labs-updated.com".to_string());

    s.destroy_for_testing();
    scenario.end();
}

#[test]
fun committee_v2_server() {
    let addr1 = @0xA;
    let mut scenario = test_scenario::begin(addr1);

    let s = create_2_of_2_committee_server_v2(2, scenario.ctx());
    let pk = g2_generator();

    assert_eq!(s.name(), b"committee".to_string());
    assert_eq!(*s.pk(), *pk.bytes());
    assert_eq!(s.key_type(), 0);

    let (version, threshold) = s.committee_version_and_threshold();
    assert_eq!(version, 0);
    assert_eq!(threshold, 2);

    let partial1 = s.partial_key_server_for_party(0);
    assert_eq!(partial1.partial_ks_url(), b"https://server1.com".to_string());
    assert_eq!(partial1.partial_ks_party_id(), 0);

    let partial2 = s.partial_key_server_for_party(1);
    assert_eq!(partial2.partial_ks_url(), b"https://server2.com".to_string());
    assert_eq!(partial2.partial_ks_party_id(), 1);

    s.destroy_for_testing();
    scenario.end();
}

#[test, expected_failure(abort_code = EInvalidThreshold)]
fun create_committee_v2_invalid_threshold() {
    let addr1 = @0xA;
    let mut scenario = test_scenario::begin(addr1);

    // Threshold of 1 should fail.
    let s = create_2_of_2_committee_server_v2(1, scenario.ctx());
    s.destroy_for_testing();
    scenario.end();
}

#[test, expected_failure(abort_code = EInvalidPartyId)]
fun create_committee_v2_duplicate_party_ids() {
    let addr1 = @0xA;
    let mut scenario = test_scenario::begin(addr1);

    let pk = g2_generator();
    let pk_bytes = *pk.bytes();

    let mut partial_key_servers = vector::empty();
    partial_key_servers.push_back(
        key_server::create_partial_key_server(
            b"server1".to_string(),
            b"https://server1.com".to_string(),
            pk_bytes,
            0,
        ),
    );
    partial_key_servers.push_back(
        key_server::create_partial_key_server(
            b"server2".to_string(),
            b"https://server2.com".to_string(),
            pk_bytes,
            0, // Duplicate party ID (should be 1)
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

#[test, expected_failure(abort_code = EInvalidPartyId)]
fun update_member_url_invalid_party_id() {
    let addr1 = @0xA;
    let mut scenario = test_scenario::begin(addr1);

    let mut s = create_2_of_2_committee_server_v2(2, scenario.ctx());

    // Try to update URL for invalid party_id (out of range) should fail.
    s.update_member_url(b"https://server3.com".to_string(), 5);
    s.destroy_for_testing();
    scenario.end();
}

#[test, expected_failure(abort_code = EInvalidServerType)]
fun update_member_url_on_independent_server_fails() {
    let addr1 = @0xA;
    let mut scenario = test_scenario::begin(addr1);

    let pk = g2_generator();
    let pk_bytes = *pk.bytes();

    key_server::create_and_transfer_v2_independent_server(
        b"mysten_v2".to_string(),
        b"https://mysten-labs-v2.com".to_string(),
        0,
        pk_bytes,
        scenario.ctx(),
    );
    scenario.next_tx(addr1);

    // Try to update member URL on independent server should fail
    let mut s: KeyServer = scenario.take_from_sender();
    s.update_member_url(b"https://newurl.com".to_string(), 0);
    s.destroy_for_testing();
    scenario.end();
}

#[test, expected_failure(abort_code = EInvalidVersion)]
#[allow(deprecated_usage)]
fun upgrade_v1_to_v2_twice() {
    let addr1 = @0xA;
    let mut scenario = test_scenario::begin(addr1);

    let pk = g2_generator();
    let pk_bytes = *pk.bytes();

    key_server::create_and_transfer_v1(
        b"mysten".to_string(),
        b"https:/mysten-labs.com".to_string(),
        0,
        pk_bytes,
        scenario.ctx(),
    );
    scenario.next_tx(addr1);

    let mut s: KeyServer = scenario.take_from_sender();
    s.upgrade_v1_to_independent_v2();

    // Try to upgrade again should fail.
    s.upgrade_v1_to_independent_v2();
    s.destroy_for_testing();
    scenario.end();
}

#[test]
fun url_getter_works_across_v1_to_v2_upgrade() {
    let addr1 = @0xA;
    let mut scenario = test_scenario::begin(addr1);

    let pk = g2_generator();
    let pk_bytes = *pk.bytes();

    // Create v1 server with initial URL.
    key_server::create_and_transfer_v1(
        b"mysten".to_string(),
        b"https://v1-initial.com".to_string(),
        0,
        pk_bytes,
        scenario.ctx(),
    );
    scenario.next_tx(addr1);

    let mut s: KeyServer = scenario.take_from_sender();

    assert_eq!(s.url(), b"https://v1-initial.com".to_string());
    s.update(b"https://v1-updated.com".to_string());
    assert_eq!(s.url(), b"https://v1-updated.com".to_string());

    // Upgrade to v2.
    s.upgrade_v1_to_independent_v2();
    assert_eq!(s.url(), b"https://v1-updated.com".to_string());

    s.update(b"https://v2-updated.com".to_string());
    assert_eq!(s.url(), b"https://v2-updated.com".to_string());
    assert_eq!(s.v1_url(), b"https://v2-updated.com".to_string());

    s.destroy_for_testing();
    scenario.end();
}
