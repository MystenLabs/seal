// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::key_server_options::SealPackage;
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
    Custom {
        node_url: Option<String>,
        use_default_mainnet_for_mvr: Option<bool>,
        seal_package: Option<SealPackage>,
    },
    #[cfg(test)]
    TestCluster {
        seal_package: SealPackage,
    },
}

impl Network {
    pub fn node_url(&self) -> String {
        match self {
            Network::Devnet { .. } => "https://fullnode.devnet.sui.io:443".into(),
            Network::Testnet => "https://fullnode.testnet.sui.io:443".into(),
            Network::Mainnet => "https://fullnode.mainnet.sui.io:443".into(),
            Network::Custom { node_url, .. } => node_url
                .as_ref()
                .expect("Custom network must have node_url set")
                .clone(),
            #[cfg(test)]
            Network::TestCluster { .. } => panic!(), // Currently not used, but can be found from cluster.rpc_url() if needed
        }
    }

    pub fn from_str(str: &str) -> Self {
        match str.to_ascii_lowercase().as_str() {
            "devnet" => Network::Devnet {
                seal_package: std::env::var("SEAL_PACKAGE")
                    .map(|s| SealPackage::Custom(ObjectID::from_str(&s).unwrap()))
                    .unwrap(),
            },
            "testnet" => Network::Testnet,
            "mainnet" => Network::Mainnet,
            "custom" => Network::Custom {
                node_url: std::env::var("NODE_URL").ok(),
                use_default_mainnet_for_mvr: None,
                seal_package: std::env::var("SEAL_PACKAGE")
                    .map(|s| SealPackage::Custom(ObjectID::from_str(&s).unwrap()))
                    .ok(),
            },
            _ => panic!("Unknown network: {str}"),
        }
    }

    pub fn get_seal_package(&self) -> ObjectID {
        match self {
            Network::Devnet { seal_package } => seal_package,
            Network::Testnet => &SealPackage::Testnet,
            Network::Mainnet => &SealPackage::Mainnet,
            // If no seal_package parameter is set, default to Mainnet
            Network::Custom { seal_package, .. } => {
                seal_package.as_ref().unwrap_or(&SealPackage::Mainnet)
            }
            #[cfg(test)]
            Network::TestCluster { seal_package } => seal_package,
        }
        .get_seal_package_id()
    }
}
