// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// A secret argument of a `seal_approve*` function. Only key servers learn its value: they decrypt
/// it from the ciphertext returned by the matching `seal_secret_args*` function and pass it
/// as a `Secret<T>` when evaluating the policy. `T` must be a primitive type, e.g. `u64`,
/// `address` or `vector<u8>`.
///
/// If the ciphertext is invalid, the secret is invalid and `value` aborts, which denies access.
/// A policy that should grant access in that case checks `is_invalid` first.
///
/// Anyone can create a `Secret` in a transaction, so it only means something inside a key
/// server's evaluation of `seal_approve*`.
module seal::secret;

/// The ciphertext holding the secret is invalid.
const EInvalidSecret: u64 = 1;

public struct Secret<T: copy + drop> has drop {
    value: Option<T>,
}

/// Called by key servers when evaluating a policy.
public fun new<T: copy + drop>(value: T): Secret<T> {
    Secret { value: option::some(value) }
}

/// Called by key servers when evaluating a policy if the ciphertext is invalid.
public fun none<T: copy + drop>(): Secret<T> {
    Secret { value: option::none() }
}

/// Whether the ciphertext holding the secret is invalid.
public fun is_invalid<T: copy + drop>(secret: &Secret<T>): bool {
    secret.value.is_none()
}

/// The secret value. Aborts with `EInvalidSecret` if the secret is invalid.
public fun value<T: copy + drop>(secret: &Secret<T>): T {
    assert!(secret.value.is_some(), EInvalidSecret);
    *secret.value.borrow()
}

#[test]
fun test_secret() {
    let secret = new(42u64);
    assert!(!secret.is_invalid() && secret.value() == 42);
    assert!(none<u64>().is_invalid());
}

#[test, expected_failure(abort_code = EInvalidSecret)]
fun test_invalid_secret_value() {
    none<u64>().value();
}
