// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Encrypted orders with a secret trigger price:
/// - The owner locks funds in an `Order` together with the encrypted order (here, the recipient of
///   the funds) and a secret minimum price, which only the key servers can decrypt.
/// - Once the price feed reaches the secret price, anyone can fetch the keys and call `execute`,
///   which decrypts the order on-chain and executes it.
///
/// Secret arguments: `seal_approve` takes the minimum price as a `Secret<u64>`, which only the key
/// servers learn. They get its encryption from `seal_secret_arguments`, called with the
/// requester's arguments. This policy lets an invalid secret release the key, so the owner cannot
/// block execution, and `seal_secret_arguments` only returns secrets set by the owner of the id.
///
/// Key format: [pkg id][owner address][nonce]. Only the owner can create orders for these ids.
///
/// `PriceFeed` is a stand-in for an oracle such as Pyth.
///
/// This pattern does NOT implement versioning, please see other patterns for
/// examples of versioning.
module patterns::secret_orders;

use seal::secret::Secret;
use seal::bf_hmac_encryption::{
    PublicKey,
    decrypt,
    new_public_key,
    parse_encrypted_object,
    verify_derived_keys
};
use sui::{balance::Balance, bcs, bls12381::g1_from_bytes, coin::{Self, Coin}, sui::SUI};

const ENoAccess: u64 = 77;
const EInvalidOrder: u64 = 78;

public struct PriceFeed has key {
    id: UID,
    price: u64,
}

public struct PriceFeedCap has key, store {
    id: UID,
    feed: ID,
}

public struct Order has key {
    id: UID,
    owner: address,
    key_id: vector<u8>,
    feed: ID,
    funds: Balance<SUI>,
    /// Encryption of the recipient's address under [pkg id][key_id].
    encrypted_order: vector<u8>,
    /// Public keys of the key servers in `encrypted_order`, in the same order.
    public_keys: vector<vector<u8>>,
    /// Encryption of the secret arguments to the key servers.
    secret_arguments: vector<u8>,
}

public fun create_price_feed(ctx: &mut TxContext): PriceFeedCap {
    let feed = PriceFeed { id: object::new(ctx), price: 0 };
    let cap = PriceFeedCap { id: object::new(ctx), feed: object::id(&feed) };
    transfer::share_object(feed);
    cap
}

public fun set_price(cap: &PriceFeedCap, feed: &mut PriceFeed, price: u64) {
    assert!(cap.feed == object::id(feed), ENoAccess);
    feed.price = price;
}

public fun create_order(
    key_id: vector<u8>,
    feed: ID,
    funds: Coin<SUI>,
    encrypted_order: vector<u8>,
    public_keys: vector<vector<u8>>,
    secret_arguments: vector<u8>,
    ctx: &mut TxContext,
) {
    // Only the owner can create orders for ids starting with their address.
    let owner = ctx.sender();
    let mut prefix = bcs::new(key_id);
    assert!(prefix.peel_address() == owner, EInvalidOrder);

    let parsed = parse_encrypted_object(encrypted_order);
    assert!(parsed.package_id() == @patterns, EInvalidOrder);
    assert!(parsed.id() == key_id, EInvalidOrder);
    assert!(parsed.services().length() == public_keys.length(), EInvalidOrder);

    transfer::share_object(Order {
        id: object::new(ctx),
        owner,
        key_id,
        feed,
        funds: funds.into_balance(),
        encrypted_order,
        public_keys,
        secret_arguments,
    });
}

/// Called by the key servers with the requester's arguments to `seal_approve`. Returns the
/// encrypted secret arguments, and that an invalid encryption should release the key.
public fun seal_secret_arguments(
    id: vector<u8>,
    order: &Order,
    feed: &PriceFeed,
): (vector<u8>, bool) {
    assert!(id == order.key_id && object::id(feed) == order.feed, ENoAccess);
    (order.secret_arguments, true)
}

/// Requesters call `seal_approve(id, order, feed)`. `min_price` is filled in by the key servers.
entry fun seal_approve(id: vector<u8>, min_price: Secret<u64>, order: &Order, feed: &PriceFeed) {
    assert!(id == order.key_id, ENoAccess);
    assert!(object::id(feed) == order.feed, ENoAccess);
    assert!(feed.price >= min_price.get(), ENoAccess);
}

/// Decrypt and execute the order using the derived keys from the key servers, given in the same
/// order as `key_servers`.
public fun execute(
    order: Order,
    derived_keys: vector<vector<u8>>,
    key_servers: vector<address>,
    ctx: &mut TxContext,
) {
    let Order { id, funds, key_id, encrypted_order, public_keys, .. } = order;
    let encrypted_order = parse_encrypted_object(encrypted_order);
    let services = encrypted_order.services();
    let verified_keys = verify_derived_keys(
        &derived_keys.map_ref!(|k| g1_from_bytes(k)),
        @patterns,
        key_id,
        &key_servers.map_ref!(|ks| public_key(services, &public_keys, *ks)),
    );
    let all_public_keys = services.map_ref!(|ks| public_key(services, &public_keys, *ks));
    let order = decrypt(&encrypted_order, &verified_keys, &all_public_keys);
    let recipient = bcs::new(order.destroy_some()).peel_address();

    transfer::public_transfer(coin::from_balance(funds, ctx), recipient);
    id.delete();
}

fun public_key(
    services: &vector<address>,
    public_keys: &vector<vector<u8>>,
    key_server: address,
): PublicKey {
    let i = services.find_index!(|s| *s == key_server).destroy_some();
    new_public_key(key_server.to_id(), public_keys[i])
}

public fun cancel(order: Order, ctx: &mut TxContext): Coin<SUI> {
    let Order { id, owner, funds, .. } = order;
    assert!(owner == ctx.sender(), ENoAccess);
    id.delete();
    coin::from_balance(funds, ctx)
}

#[test_only]
fun new_for_testing(ctx: &mut TxContext): (PriceFeedCap, PriceFeed, Order) {
    let feed = PriceFeed { id: object::new(ctx), price: 0 };
    let cap = PriceFeedCap { id: object::new(ctx), feed: object::id(&feed) };
    let order = Order {
        id: object::new(ctx),
        owner: ctx.sender(),
        key_id: bcs::to_bytes(&ctx.sender()),
        feed: object::id(&feed),
        funds: sui::balance::zero(),
        encrypted_order: vector[],
        public_keys: vector[],
        secret_arguments: x"0102",
    };
    (cap, feed, order)
}

#[test_only]
fun destroy_for_testing(cap: PriceFeedCap, feed: PriceFeed, order: Order, ctx: &mut TxContext) {
    let PriceFeedCap { id, .. } = cap;
    id.delete();
    let PriceFeed { id, .. } = feed;
    id.delete();
    cancel(order, ctx).destroy_zero();
}

#[test]
fun test_seal_approve() {
    let ctx = &mut tx_context::dummy();
    let (cap, mut feed, order) = new_for_testing(ctx);

    let (secret, open_if_invalid) = seal_secret_arguments(order.key_id, &order, &feed);
    assert!(secret == x"0102" && open_if_invalid);

    set_price(&cap, &mut feed, 100);
    seal_approve(order.key_id, seal::secret::new(100), &order, &feed);
    destroy_for_testing(cap, feed, order, ctx);
}

#[test, expected_failure(abort_code = ENoAccess)]
fun test_seal_approve_price_too_low() {
    let ctx = &mut tx_context::dummy();
    let (cap, mut feed, order) = new_for_testing(ctx);

    set_price(&cap, &mut feed, 99);
    seal_approve(order.key_id, seal::secret::new(100), &order, &feed);
    destroy_for_testing(cap, feed, order, ctx);
}
