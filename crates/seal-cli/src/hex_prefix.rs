// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::error::FastCryptoResult;

pub(crate) struct HexPrefix;

impl Encoding for HexPrefix {
    fn decode(s: &str) -> FastCryptoResult<Vec<u8>> {
        Hex::decode(s)
    }

    fn encode<T: AsRef<[u8]>>(data: T) -> String {
        Hex::encode_with_format(data.as_ref())
    }
}
