// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::key_server_options::SealPackage;
use crate::utils::decode_object_id;
use crypto::ibe;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use sui_types::base_types::ObjectID;

/// The Identity-based encryption types.
pub type IbeMasterKey = ibe::MasterKey;

/// Proof-of-possession of a key-servers master key.
pub type MasterKeyPOP = ibe::ProofOfPossession;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Network {
    Devnet {
        seal_package: SealPackage,
    },
    Testnet,
    Mainnet,
    #[cfg(test)]
    TestCluster {
        seal_package: SealPackage,
    },
}

impl Network {
    pub fn default_node_url(&self) -> &str {
        match self {
            Network::Devnet { .. } => "https://fullnode.devnet.sui.io:443",
            Network::Testnet => "https://fullnode.testnet.sui.io:443",
            Network::Mainnet => "https://fullnode.mainnet.sui.io:443",
            #[cfg(test)]
            Network::TestCluster { .. } => panic!(), // Currently not used, but can be found from cluster.rpc_url() if needed
        }
    }

    pub fn from_str(str: &str) -> Self {
        match str.to_ascii_lowercase().as_str() {
            "devnet" => Network::Devnet {
                seal_package: decode_object_id("SEAL_PACKAGE")
                    .map(SealPackage::Custom)
                    .unwrap(),
            },
            "testnet" => Network::Testnet,
            "mainnet" => Network::Mainnet,
            _ => panic!("Unknown network: {str}"),
        }
    }

    pub fn seal_package_id(&self) -> ObjectID {
        match self {
            Network::Devnet { seal_package } => seal_package,
            Network::Testnet => &SealPackage::Testnet,
            Network::Mainnet => &SealPackage::Mainnet,
            Network::TestCluster { seal_package } => seal_package,
        }
        .package_id()
    }
}
