// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crypto::ibe;
use serde::{Deserialize, Serialize};

/// The Identity-based encryption types.
pub type IbeMasterKey = ibe::MasterKey;

/// Proof-of-possession of a key-servers master key.
pub type MasterKeyPOP = ibe::ProofOfPossession;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Network {
    Devnet,
    Testnet,
    Mainnet,
    Custom {
        node_url: Option<String>,
        use_default_mainnet_for_mvr: Option<bool>,
    },
    #[cfg(test)]
    TestCluster,
}

impl Network {
    pub fn node_url(&self) -> String {
        match self {
            Network::Devnet => "https://fullnode.devnet.sui.io:443".into(),
            Network::Testnet => "https://fullnode.testnet.sui.io:443".into(),
            Network::Mainnet => "https://fullnode.mainnet.sui.io:443".into(),
            Network::Custom { node_url, .. } => node_url
                .as_ref()
                .expect("Custom network must have node_url set")
                .clone(),
            #[cfg(test)]
            Network::TestCluster => panic!(), // Currently not used, but can be found from cluster.rpc_url() if needed
        }
    }

    pub fn from_str(str: &str) -> Self {
        match str.to_ascii_lowercase().as_str() {
            "devnet" => Network::Devnet,
            "testnet" => Network::Testnet,
            "mainnet" => Network::Mainnet,
            "custom" => Network::Custom {
                node_url: std::env::var("NODE_URL").ok(),
                use_default_mainnet_for_mvr: None,
            },
            _ => panic!("Unknown network: {}", str),
        }
    }
}
