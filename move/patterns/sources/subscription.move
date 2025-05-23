// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Subscription pattern:
/// - Anyone can create a service that requires a subscription.
/// - Anyone can buy a subscription to the service for a certain period.
/// - Anyone with an active subscription can access its service related keys.
///
/// Use cases that can be built on top of this: subscription based access to content.
///
module patterns::subscription;

use sui::{clock::Clock, coin::Coin, sui::SUI};

const EInvalidFee: u64 = 12;
const ENoAccess: u64 = 77;

public struct Service has key {
    id: UID,
    fee: u64,
    ttl: u64,
    owner: address,
}

/// Subscription can only be transferred to another address (but not stored / shared / received, etc).
public struct Subscription has key {
    id: UID,
    service_id: ID,
    created_at: u64,
}

//////////////////////////////////////////
/////// Simple a service

/// Create a service.
/// The associated key-ids are [pkg id][service id][nonce] for any nonce (thus
/// many key-ids can be created for the same service).
public fun create_service(fee: u64, ttl: u64, ctx: &mut TxContext): Service {
    Service {
        id: object::new(ctx),
        fee: fee,
        ttl: ttl,
        owner: ctx.sender(),
    }
}

// convenience function to create a service and share it (simpler ptb for cli)
entry fun create_service_entry(fee: u64, ttl: u64, ctx: &mut TxContext) {
    transfer::share_object(create_service(fee, ttl, ctx));
}

public fun subscribe(
    fee: Coin<SUI>,
    service: &Service,
    c: &Clock,
    ctx: &mut TxContext,
): Subscription {
    assert!(fee.value() == service.fee, EInvalidFee);
    transfer::public_transfer(fee, service.owner);
    Subscription {
        id: object::new(ctx),
        service_id: object::id(service),
        created_at: c.timestamp_ms(),
    }
}

public fun transfer(sub: Subscription, to: address) {
    transfer::transfer(sub, to);
}

#[test_only]
public fun destroy_for_testing(ser: Service, sub: Subscription) {
    let Service { id, .. } = ser;
    object::delete(id);
    let Subscription { id, .. } = sub;
    object::delete(id);
}

//////////////////////////////////////////////////////////
/// Access control
/// key format: [pkg id][service id][random nonce]

/// All addresses can access all IDs with the prefix of the service
fun check_policy(id: vector<u8>, sub: &Subscription, service: &Service, c: &Clock): bool {
    if (object::id(service) != sub.service_id) {
        return false
    };
    if (c.timestamp_ms() > sub.created_at + service.ttl) {
        return false
    };

    // Check if the id has the right prefix
    let namespace = service.id.to_bytes();
    let mut i = 0;
    if (namespace.length() > id.length()) {
        return false
    };
    while (i < namespace.length()) {
        if (namespace[i] != id[i]) {
            return false
        };
        i = i + 1;
    };
    true
}

entry fun seal_approve(id: vector<u8>, sub: &Subscription, service: &Service, c: &Clock) {
    assert!(check_policy(id, sub, service, c), ENoAccess);
}

#[test]
fun test_approve() {
    use sui::clock;
    use sui::coin;

    let ctx = &mut tx_context::dummy();
    let mut c = clock::create_for_testing(ctx); // time = 0
    let coin = coin::mint_for_testing<SUI>(10, ctx);

    let ser = create_service(10, 2, ctx);
    let sub = subscribe(coin, &ser, &c, ctx);

    let mut obj_id = object::id(&ser).to_bytes();
    obj_id.push_back(11);

    // Work for time 0
    assert!(check_policy(obj_id, &sub, &ser, &c));
    c.increment_for_testing(1);
    assert!(check_policy(obj_id, &sub, &ser, &c));
    // time 3 should fail
    c.increment_for_testing(2);
    assert!(!check_policy(obj_id, &sub, &ser, &c));

    destroy_for_testing(ser, sub);
    c.destroy_for_testing();
}
