// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Guessing game pattern, using key servers as an oracle over a secret:
/// - The creator picks a secret number, encrypts it as a secret argument to the key servers (see
///   `seal::secret`), and leaves. The creator knows the number, so they should not play.
/// - Players guess on-chain. For guess i, the hint is "higher", "lower" or "correct", and the key
///   servers only release the key for the id [pkg id][game id][i][hint] with the true hint.
/// - A derived key is a signature by its key server on the id, so anyone can submit the keys
///   from `threshold` key servers to `record_hint`, which verifies them on-chain and records the
///   hint. Nothing is decrypted, and nobody has to trust the creator or be online for them.
///
/// This pattern does NOT implement versioning, please see other patterns for
/// examples of versioning.
module patterns::guessing_game;

use seal::bf_hmac_encryption::{PublicKey, new_public_key, verify_derived_keys};
use seal::secret::Secret;
use sui::{bcs, bls12381::g1_from_bytes};

const ENoAccess: u64 = 1;
const EGameOver: u64 = 2;
const EInvalidKeys: u64 = 3;

/// The secret is higher than the guess.
const HIGHER: u8 = 0;
/// The secret is lower than the guess.
const LOWER: u8 = 1;
const CORRECT: u8 = 2;

public struct Game has key {
    id: UID,
    /// Encryption of the secret number to the key servers.
    encrypted_secret: vector<u8>,
    /// The key servers trusted to attest hints, their public keys and the threshold.
    key_servers: vector<address>,
    public_keys: vector<vector<u8>>,
    threshold: u64,
    guesses: vector<u64>,
    players: vector<address>,
    hints: vector<Option<u8>>,
    winner: Option<address>,
}

public fun create_game(
    encrypted_secret: vector<u8>,
    key_servers: vector<address>,
    public_keys: vector<vector<u8>>,
    threshold: u64,
    ctx: &mut TxContext,
) {
    assert!(key_servers.length() == public_keys.length() && threshold <= key_servers.length());
    transfer::share_object(Game {
        id: object::new(ctx),
        encrypted_secret,
        key_servers,
        public_keys,
        threshold,
        guesses: vector[],
        players: vector[],
        hints: vector[],
        winner: option::none(),
    });
}

public fun guess(game: &mut Game, value: u64, ctx: &TxContext) {
    assert!(game.winner.is_none(), EGameOver);
    game.guesses.push_back(value);
    game.players.push_back(ctx.sender());
    game.hints.push_back(option::none());
}

/// The key id for the hint of guess `index`: [game id][index][hint].
public fun hint_id(game: &Game, index: u64, hint: u8): vector<u8> {
    let mut id = game.id.to_bytes();
    id.append(bcs::to_bytes(&index));
    id.push_back(hint);
    id
}

entry fun seal_secret_args(id: vector<u8>, game: &Game): (vector<u8>, bool) {
    assert!(bcs::new(id).peel_address() == game.id.to_address(), ENoAccess);
    (game.encrypted_secret, false)
}

/// Requesters call `seal_approve(id, game)`. `secret` is filled in by the key servers.
entry fun seal_approve(id: vector<u8>, secret: Secret<u64>, game: &Game) {
    let mut parsed = bcs::new(id);
    assert!(parsed.peel_address() == game.id.to_address(), ENoAccess);
    let index = parsed.peel_u64();
    let hint = parsed.peel_u8();
    assert!(parsed.into_remainder_bytes().is_empty(), ENoAccess);
    assert!(index < game.guesses.length(), ENoAccess);
    assert!(hint == compute_hint(secret.get(), game.guesses[index]), ENoAccess);
}

fun compute_hint(secret: u64, guess: u64): u8 {
    if (guess < secret) HIGHER else if (guess > secret) LOWER else CORRECT
}

/// Record the hint for guess `index`, given derived keys for its id from at least `threshold`
/// distinct key servers, in the same order as `key_servers`.
public fun record_hint(
    game: &mut Game,
    index: u64,
    hint: u8,
    derived_keys: vector<vector<u8>>,
    key_servers: vector<address>,
) {
    assert!(game.winner.is_none(), EGameOver);
    assert!(
        derived_keys.length() == key_servers.length() && key_servers.length() >= game.threshold,
        EInvalidKeys,
    );
    key_servers.length().do!(|i| {
        assert!(!key_servers.take(i).contains(&key_servers[i]), EInvalidKeys);
    });

    // Aborts if a key is not valid for the hint's id.
    let _verified = verify_derived_keys(
        &derived_keys.map_ref!(|k| g1_from_bytes(k)),
        @patterns,
        hint_id(game, index, hint),
        &key_servers.map_ref!(|ks| public_key(game, *ks)),
    );

    *&mut game.hints[index] = option::some(hint);
    if (hint == CORRECT) game.winner = option::some(game.players[index]);
}

fun public_key(game: &Game, key_server: address): PublicKey {
    let i = game.key_servers.find_index!(|ks| *ks == key_server);
    assert!(i.is_some(), EInvalidKeys);
    new_public_key(key_server.to_id(), game.public_keys[i.destroy_some()])
}

#[test_only]
fun new_for_testing(ctx: &mut TxContext): Game {
    Game {
        id: object::new(ctx),
        encrypted_secret: x"0102",
        key_servers: vector[],
        public_keys: vector[],
        threshold: 0,
        guesses: vector[],
        players: vector[],
        hints: vector[],
        winner: option::none(),
    }
}

#[test_only]
fun destroy_for_testing(game: Game) {
    let Game { id, .. } = game;
    id.delete();
}

#[test]
fun test_seal_approve() {
    let ctx = &mut tx_context::dummy();
    let mut game = new_for_testing(ctx);
    game.guess(10, ctx);
    game.guess(42, ctx);

    let (secret, open_if_invalid) = seal_secret_args(hint_id(&game, 0, HIGHER), &game);
    assert!(secret == x"0102" && !open_if_invalid);

    seal_approve(hint_id(&game, 0, HIGHER), seal::secret::new(42), &game);
    seal_approve(hint_id(&game, 1, CORRECT), seal::secret::new(42), &game);
    destroy_for_testing(game);
}

#[test, expected_failure(abort_code = ENoAccess)]
fun test_seal_approve_wrong_hint() {
    let ctx = &mut tx_context::dummy();
    let mut game = new_for_testing(ctx);
    game.guess(10, ctx);

    seal_approve(hint_id(&game, 0, LOWER), seal::secret::new(42), &game);
    destroy_for_testing(game);
}

#[test, expected_failure(abort_code = ENoAccess)]
fun test_seal_approve_no_such_guess() {
    let ctx = &mut tx_context::dummy();
    let game = new_for_testing(ctx);

    seal_approve(hint_id(&game, 0, HIGHER), seal::secret::new(42), &game);
    destroy_for_testing(game);
}
