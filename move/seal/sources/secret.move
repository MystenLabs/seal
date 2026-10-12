// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// A secret argument of a `seal_approve*` function. Only key servers learn its value: they decrypt
/// it from the ciphertext returned by the matching `seal_secret_args*` function and pass it
/// as a `Secret<T>` when evaluating the policy. `T` must be a primitive type, e.g. `u64`,
/// `address` or `vector<u8>`.
module seal::secret;

public struct Secret<T: copy + drop> has drop {
    value: T,
}

/// Called by key servers when evaluating a policy.
public fun new<T: copy + drop>(value: T): Secret<T> {
    Secret { value }
}

public fun get<T: copy + drop>(secret: &Secret<T>): T {
    secret.value
}
