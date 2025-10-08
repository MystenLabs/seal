// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module seal::hmac256ctr;

use std::bcs;
use sui::hmac::hmac_sha3_256;

const ENC_TAG: vector<u8> = b"HMAC-CTR-ENC";
const MAC_TAG: vector<u8> = b"HMAC-CTR-MAC";

/// Decrypt a message that was encrypted in Hmac256Ctr mode.
public(package) fun decrypt(
    ciphertext: &vector<u8>,
    mac: &vector<u8>,
    aad: &vector<u8>,
    key: &vector<u8>,
): Option<vector<u8>> {
    if (mac(key, aad, ciphertext) != mac) {
        return option::none()
    };

    let mut next_block = 0;
    let mut i = 0;
    let mut current_mask = vector[];
    option::some(ciphertext.map_ref!(|b| {
        if (i == 0) {
            current_mask =
                hmac_sha3_256(key, &vector[ENC_TAG, bcs::to_bytes(&(next_block as u64))].flatten());
            next_block = next_block + 1;
        };
        let result = *b ^ current_mask[i];
        i = (i + 1) % 32;
        result
    }))
}

fun mac(key: &vector<u8>, aux: &vector<u8>, ciphertext: &vector<u8>): vector<u8> {
    let mut mac_input = MAC_TAG;
    mac_input.append(bcs::to_bytes(&aux.length()));
    mac_input.append(*aux);
    mac_input.append(*ciphertext);
    hmac_sha3_256(key, &mac_input)
}

#[test]
fun test_decrypt() {
    let key = x"76532ed510f487739f775afe6b64bc506e0097b9709f33fc5a18cb1c57fac66d";
    let ciphertext = x"711ec5be4348c6194475dd2a45";
    let mac = x"a94c5de42a5a0219fcd6871d379df4870c35e6406ebdfb7a51594fc18a1192bd";
    let aux = b"something";
    let decrypted = decrypt(&ciphertext, &mac, &aux, &key).borrow();
    assert!(decrypted == b"Hello, world!");
}

#[test]
fun test_decrypt_fail() {
    let key = x"4804597e77d5025ab89d8559fe826dbd5591aaa5a0a3ca19ea572350e2a08c6b";
    let ciphertext = x"98bf8da0ccbb35b6cf41effc83";
    let mac = x"6c3d7fdb9b3a16a552b43a3300d6493f328e97aebf0697645cd35348ac926ec2";
    let aux = b"something else";
    assert!(decrypt(&ciphertext, &mac, &aux, &key) == option::none());
}

#[test]
fun test_decrypt_long() {
    let key = x"5bfdfd7c814903f1311bebacfffa3c001cbeb1cbb3275baa9aafe21fadd9f396";
    let ciphertext =
        x"feadb8c8f781036f86b6a9f436cac6f9f68ba8fc8b8444f0331a5820f78580f32034f698f7ce15f25defae1749f0131c0a8b8c5e751b96aacf507d0dbd4d7790440d196a339fcb8498ca7dd236014e353729b7aa2cf524284a8d2305d2378494eadd6f";
    let mac = x"85d498365972c3dc7a53f94232f9cb10dcc94eff064d6835d41d7a7536b47b51";
    let aux = b"Mark Twain";
    let decrypted = decrypt(&ciphertext, &mac, &aux, &key).borrow();
    assert!(
        decrypted == b"The difference between a Miracle and a Fact is exactly the difference between a mermaid and a seal.",
    );
}
