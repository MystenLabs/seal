// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub use crate::common::Network;
use crate::seal_package::SealPackage;
use crate::utils::decode_object_id;
use crypto::ibe;
use std::str::FromStr;

/// The Identity-based encryption types.
pub type IbeMasterKey = ibe::MasterKey;

/// Proof-of-possession of a key-servers master key.
pub type MasterKeyPOP = ibe::ProofOfPossession;

impl FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "devnet" => Ok(Network::Devnet {
                seal_package: decode_object_id("SEAL_PACKAGE")
                    .expect("Seal package ID must be set as env var SEAL_PACKAGE"),
            }),
            "testnet" => Ok(Network::Testnet),
            "mainnet" => Ok(Network::Mainnet),
            _ => Err(format!("Unknown network: {s}")),
        }
    }
}

impl Network {
    pub fn seal_package(&self) -> SealPackage {
        match self {
            Network::Devnet { seal_package } => SealPackage::Custom(*seal_package),
            Network::Testnet => SealPackage::Testnet,
            Network::Mainnet => SealPackage::Mainnet,
            #[cfg(test)]
            Network::TestCluster { seal_package } => SealPackage::Custom(*seal_package),
        }
    }
}
