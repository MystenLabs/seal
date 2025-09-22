// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Pre-signed (time-limited) access to a Walrus blob.
/// - Anyone can create a time window for a specific `blob_id`.
/// - Anyone with the link/params can request decrypts until `expires_at_ms`.
/// - No per-user allowlist: it's a bearer, time-limited permit.
///
/// Key idea:
///   Encrypt with a key-id whose prefix includes `blob_id`.
///   Policy checks: (a) id starts with blob_id, (b) now <= expires_at_ms.

module patterns::presigned_blob;

use sui::clock;

const E_EXPIRED_OR_INVALID: u64 = 1;

/// A shared object that anchors the "pre-signed" window.
public struct PreSignedWindow has key {
    id: UID,
    /// Raw Walrus blob id bytes (fixed-length in your app).
    blob_id: vector<u8>,
    /// Unix time (ms) after which decrypts are no longer allowed.
    expires_at_ms: u64,
}

/// Create and share a window for a given Walrus `blob_id` until `expires_at_ms`.
public fun create(blob_id: vector<u8>, expires_at_ms: u64, ctx: &mut TxContext): PreSignedWindow {
    PreSignedWindow { id: object::new(ctx), blob_id, expires_at_ms }
}

/// Convenience: create then share.
entry fun create_entry(blob_id: vector<u8>, expires_at_ms: u64, ctx: &mut TxContext) {
    transfer::share_object(create(blob_id, expires_at_ms, ctx));
}

/// Decrypt gate: allow only if the key-id starts with `blob_id` and the window has not expired.
///
/// Expected key-id layout at encrypt time (recommended):
///   [package_id][blob_id][random_nonce]
fun check_policy(id: vector<u8>, w: &PreSignedWindow, c: &clock::Clock): bool {
    // Prefix match: id must start with the window's blob_id
    let prefix = &w.blob_id;
    let mut i = 0;
    if (prefix.length() > id.length()) {
        return false
    };
    while (i < prefix.length()) {
        if (id[i] != prefix[i]) { return false };
        i = i + 1;
    };
    // Time check: still within the pre-signed window
    c.timestamp_ms() <= w.expires_at_ms
}

/// Seal policy entry point.
/// Pass the encrypted object's key-id (`id`), the window object, and the on-chain Clock.
entry fun seal_approve(id: vector<u8>, w: &PreSignedWindow, c: &clock::Clock) {
    assert!(check_policy(id, w, c), E_EXPIRED_OR_INVALID);
}