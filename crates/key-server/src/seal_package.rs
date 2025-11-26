// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use jsonrpsee::core::Serialize;
use serde::Deserialize;
use sui_types::base_types::ObjectID;

const TESTNET_PACKAGE_ID: &str =
    "0x4016869413374eaa71df2a043d1660ed7bc927ab7962831f8b07efbc7efdb2c3";
const MAINNET_PACKAGE_ID: &str =
    "0xcb83a248bda5f7a0a431e6bf9e96d184e604130ec5218696e3f1211113b447b7";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SealPackage {
    Testnet,
    Mainnet,
    Custom(ObjectID),
}

impl SealPackage {
    pub fn package_id(&self) -> ObjectID {
        match self {
            SealPackage::Testnet => ObjectID::from_hex_literal(TESTNET_PACKAGE_ID).unwrap(),
            SealPackage::Mainnet => ObjectID::from_hex_literal(MAINNET_PACKAGE_ID).unwrap(),
            SealPackage::Custom(seal_package) => *seal_package,
        }
    }
}
