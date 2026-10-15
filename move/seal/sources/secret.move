// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// A secret argument of a `seal_approve*` function. Only key servers learn its value: they decrypt
/// it from the ciphertext returned by the matching `seal_secret_args*` function and pass it
/// as a `Secret<T>` when evaluating the policy. `T` must be a primitive type, e.g. `u64`,
/// `address` or `vector<u8>`.
///
/// The value is `none` if the ciphertext is invalid, and the policy decides whether to grant access
/// in that case.
///
/// Anyone can create a `Secret` in a transaction, so it only means something inside a key
/// server's evaluation of `seal_approve*`.
module seal::secret;

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

/// The secret value, or `none` if the ciphertext is invalid.
public fun get<T: copy + drop>(secret: &Secret<T>): Option<T> {
    secret.value
}
