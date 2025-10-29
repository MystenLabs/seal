// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module seal::kdf;

use std::hash::sha3_256;
use sui::{bls12381::{Self, G1, G2, GT}, group_ops::Element};

const DST_KDF: vector<u8> = b"SUI-SEAL-IBE-BLS12381-H2-00";
const DST_ID: vector<u8> = b"SUI-SEAL-IBE-BLS12381-00";

public(package) fun kdf(
    input: &Element<GT>,
    nonce: &Element<G2>,
    gid: &Element<G1>,
    object_id: address,
    index: u8,
): vector<u8> {
    let mut bytes = DST_KDF;
    append_ref(&mut bytes, input.bytes());
    append_ref(&mut bytes, nonce.bytes());
    append_ref(&mut bytes, gid.bytes());
    append_ref(&mut bytes, &object_id.to_bytes());
    bytes.push_back(index);
    sha3_256(bytes)
}

public(package) fun append_ref(bytes: &mut vector<u8>, value: &vector<u8>) {
    value.do_ref!(|v| bytes.push_back(*v));
}

public(package) fun hash_to_g1_with_dst(id: &vector<u8>): Element<G1> {
    let mut bytes = DST_ID;
    append_ref(&mut bytes, id);
    bls12381::hash_to_g1(&bytes)
}

#[test]
fun test_kdf() {
    use sui::bls12381::{scalar_from_u64, g2_generator, gt_generator, g2_mul, gt_mul};
    use std::unit_test::assert_eq;

    let r = scalar_from_u64(12345u64);
    let x = gt_mul(&r, &gt_generator());
    let nonce = g2_mul(&r, &g2_generator());
    let gid = hash_to_g1_with_dst(&vector[0]);
    let derived_key = kdf(&x, &nonce, &gid, @0x0, 42);
    let expected = x"89befdfd6aecdce1305ddbca891d1c29f0507cfd5225cd6b11e52e60f088ea87";
    assert_eq!(derived_key, expected);
}
