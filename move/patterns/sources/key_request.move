// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// KeyRequest pattern:
/// - Policy is checked onchain, and if granted, a KeyRequest object is returned to the user.
/// - The user can then use the KeyRequest object to access the associated key using Seal.
///
/// Dapp developers need to define how to contrust KeyRequest, and implement seal_approve that
/// only calls verify. Seal is agnostic to the actual policy.
///
/// Use cases that can be built on top of this: pay per key request, complex policies in which
/// safety during dryRun must be guaranteed.
///
/// See a test below for an example of how to use this pattern with a whitelist.
///
/// This pattern does NOT implement versioning, please see other patterns for
/// examples of versioning.
///
module patterns::key_request {
    use std::{ascii::String, type_name};
    use sui::clock::Clock;

    /// KeyRequest object has all the info needed to access a key.
    public struct KeyRequest has key, store {
        id: UID,
        package: String, // Hex
        inner_id: vector<u8>,
        user: address,
        valid_till: u64,
    }

    /// Any contract can create a KeyRequest object associated with a given witness T (inaccessible to other contracts).
    /// ttl is the number of milliseconds after which the KeyRequest object expires.
    public fun request_key<T: drop>(
        _w: T,
        id: vector<u8>,
        user: address,
        c: &Clock,
        ttl: u64,
        ctx: &mut TxContext,
    ): KeyRequest {
        // The package of the caller (via the witness T).
        let package = type_name::get_with_original_ids<T>().get_address();
        KeyRequest {
            id: object::new(ctx),
            package,
            inner_id: id,
            user,
            valid_till: c.timestamp_ms() + ttl,
        }
    }

    public fun destroy(req: KeyRequest) {
        let KeyRequest { id, .. } = req;
        object::delete(id);
    }

    /// Verify that the KeyRequest is consistent with the given parameters, and that it has not expired.
    /// The dapp needs to call only this function in seal_approve.
    public fun verify<T: drop>(
        req: &KeyRequest,
        _w: T,
        id: vector<u8>,
        user: address,
        c: &Clock,
    ): bool {
        let package = type_name::get_with_original_ids<T>().get_address();
        (req.package == package) && (req.inner_id == id) && (req.user == user) && (c.timestamp_ms() <= req.valid_till)
    }
}

/// Example of how to use the KeyRequest pattern with a whitelist.
#[test_only]
module patterns::key_request_whitelist_test {
    use patterns::key_request as kro;
    use sui::clock::Clock;

    const ENoAccess: u64 = 1;

    const TTL: u64 = 60_000; // 1 minute

    public struct Whitelist has key {
        id: UID,
        users: vector<address>,
    }

    // Just a static whitelist for the example, see the Whitelist pattern for a dynamic one.
    public fun create_whitelist(users: vector<address>, ctx: &mut TxContext): Whitelist {
        Whitelist {
            id: object::new(ctx),
            users: users,
        }
    }

    #[test_only]
    public fun destroy_for_testing(wl: Whitelist) {
        let Whitelist { id, .. } = wl;
        object::delete(id);
    }

    public struct WITNESS has drop {}

    /// Users request access using request_access.
    public fun request_access(wl: &Whitelist, c: &Clock, ctx: &mut TxContext): kro::KeyRequest {
        assert!(wl.users.contains(&ctx.sender()), ENoAccess);
        kro::request_key(WITNESS {}, wl.id.to_bytes(), ctx.sender(), c, TTL, ctx)
    }

    /// Seal only checks consistency of the request using req.verify.
    /// The actual policy is checked in request_access above.
    entry fun seal_approve(id: vector<u8>, req: &kro::KeyRequest, c: &Clock, ctx: &TxContext) {
        assert!(req.verify(WITNESS {}, id, ctx.sender(), c), ENoAccess);
    }

    #[test]
    fun test_e2e() {
        use sui::clock;

        let ctx = &mut tx_context::dummy(); // sender = 0x0
        let c = clock::create_for_testing(ctx); // time = 0

        let wl = create_whitelist(vector[@0x0, @0x1], ctx);
        let kr = request_access(&wl, &c, ctx);
        seal_approve(object::id(&wl).to_bytes(), &kr, &c, ctx);

        kr.destroy();
        destroy_for_testing(wl);
        c.destroy_for_testing();
    }
}
