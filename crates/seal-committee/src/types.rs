// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr};

/// Network enum for DKG and Seal CLI operations.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Network {
    Testnet,
    Mainnet,
    Custom,
}

impl FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.to_lowercase();
        match lower.as_str() {
            "mainnet" => Ok(Network::Mainnet),
            "testnet" => Ok(Network::Testnet),
            "custom" => Ok(Network::Custom),
            _ => Err(format!(
                "Unknown network: {s}. Supported networks: 'mainnet', 'testnet', 'custom'"
            )),
        }
    }
}

impl Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Mainnet => write!(f, "Mainnet"),
            Network::Testnet => write!(f, "Testnet"),
            Network::Custom => write!(f, "Custom"),
        }
    }
}

impl Network {
    /// Get the default RPC URL for the network, if any.
    pub fn default_rpc_url(&self) -> Option<&'static str> {
        match self {
            Network::Mainnet => Some(sui_rpc::client::Client::MAINNET_FULLNODE),
            Network::Testnet => Some(sui_rpc::client::Client::TESTNET_FULLNODE),
            Network::Custom => None,
        }
    }
}
