// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use sui_types::base_types::ObjectID;

const TESTNET_PACKAGE_ID: &str =
    "0x4016869413374eaa71df2a043d1660ed7bc927ab7962831f8b07efbc7efdb2c3";
const MAINNET_PACKAGE_ID: &str =
    "0xcb83a248bda5f7a0a431e6bf9e96d184e604130ec5218696e3f1211113b447b7";

/// This should be equal to the corresponding error code from the staleness Seal Move package.
pub const STALENESS_ERROR_CODE: u64 = 93492;
pub const STALENESS_MODULE: &str = "time";
pub const STALENESS_FUNCTION: &str = "check_staleness";

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

    pub fn staleness_module(&self) -> String {
        format!("{}::{}", self.package_id(), STALENESS_MODULE)
    }
}
