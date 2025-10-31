// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Network enum for DKG and Seal CLI operations.
/// Only supports mainnet and testnet.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Network {
    Testnet,
    Mainnet,
}

impl FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mainnet" => Ok(Network::Mainnet),
            "testnet" => Ok(Network::Testnet),
            _ => Err(format!(
                "Unknown network: {s}. Only 'mainnet' and 'testnet' are supported"
            )),
        }
    }
}
