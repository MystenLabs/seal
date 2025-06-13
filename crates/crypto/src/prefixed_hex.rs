// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::error::FastCryptoResult;

/// HexPrefix is a wrapper around the Hex encoding that adds a '0x' prefix to the encoded string.'
/// Decoding accepts strings with or without the '0x' prefix.
pub struct PrefixedHex;

impl Encoding for PrefixedHex {
    fn decode(s: &str) -> FastCryptoResult<Vec<u8>> {
        Hex::decode(s)
    }

    fn encode<T: AsRef<[u8]>>(data: T) -> String {
        Hex::encode_with_format(data.as_ref())
    }
}
