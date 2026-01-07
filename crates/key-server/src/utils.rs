// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::types::IbeMasterKey;
use anyhow::anyhow;
use crypto::ibe::MASTER_KEY_LENGTH;
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::serde_helpers::ToFromByteArray;
use std::env;
use sui_types::base_types::{ObjectID, SUI_ADDRESS_LENGTH};

/// Read a byte array from an environment variable and decode it using the specified encoding.
pub fn decode_byte_array<E: Encoding, const N: usize>(env_name: &str) -> anyhow::Result<[u8; N]> {
    let hex_string =
        env::var(env_name).map_err(|_| anyhow!("Environment variable {} must be set", env_name))?;
    let bytes = E::decode(&hex_string)
        .map_err(|_| anyhow!("Environment variable {} should be hex encoded", env_name))?;
    bytes.try_into().map_err(|_| {
        anyhow!(
            "Invalid byte array length for environment variable {env_name}. Must be {N} bytes long"
        )
    })
}

/// Read a master key from an environment variable.
pub fn decode_master_key<E: Encoding>(env_name: &str) -> anyhow::Result<IbeMasterKey> {
    let bytes = decode_byte_array::<E, MASTER_KEY_LENGTH>(env_name)?;
    IbeMasterKey::from_byte_array(&bytes)
        .map_err(|_| anyhow!("Invalid master key for environment variable {env_name}"))
}

/// Read an ObjectID from an environment variable.
pub fn decode_object_id(env_name: &str) -> anyhow::Result<ObjectID> {
    decode_byte_array::<Hex, SUI_ADDRESS_LENGTH>(env_name).map(ObjectID::new)
}
