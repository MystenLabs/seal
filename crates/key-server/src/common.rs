// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use axum::http::HeaderValue;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use sui_types::base_types::ObjectID;

/// Network configuration.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Network {
    Devnet {
        seal_package: ObjectID,
    },
    Testnet,
    Mainnet,
    #[cfg(test)]
    TestCluster {
        seal_package: ObjectID,
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
}

/// HTTP header name for client SDK version.
pub const HEADER_CLIENT_SDK_VERSION: &str = "Client-Sdk-Version";

/// HTTP header name for client SDK type.
pub const HEADER_CLIENT_SDK_TYPE: &str = "Client-Sdk-Type";

/// HTTP header name for key server version.
pub const HEADER_KEYSERVER_VERSION: &str = "X-KeyServer-Version";

/// HTTP header name for key server git version.
pub const HEADER_KEYSERVER_GIT_VERSION: &str = "X-KeyServer-GitVersion";

/// SDK type value for aggregator clients.
pub const SDK_TYPE_AGGREGATOR: &str = "aggregator";

/// SDK type value for TypeScript clients.
pub const SDK_TYPE_TYPESCRIPT: &str = "typescript";

/// Get the git version.
/// Based on https://github.com/MystenLabs/walrus/blob/7e282a681e6530ae4073210b33cac915fab439fa/crates/walrus-service/src/common/utils.rs#L69
#[macro_export]
macro_rules! git_version {
    () => {{
        /// The Git revision obtained through `git describe` at compile time.
        const GIT_REVISION: &str = {
            if let Some(revision) = option_env!("GIT_REVISION") {
                revision
            } else {
                let version = git_version::git_version!(
                    args = ["--always", "--abbrev=12", "--dirty", "--exclude", "*"],
                    fallback = ""
                );
                if version.is_empty() {
                    panic!("unable to query git revision");
                }
                version
            }
        };

        GIT_REVISION
    }};
}

/// Client SDK type for version validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientSdkType {
    Aggregator,
    TypeScript,
    Other,
}

impl ClientSdkType {
    pub fn from_header(header_value: Option<&str>) -> Self {
        match header_value {
            Some(SDK_TYPE_AGGREGATOR) => ClientSdkType::Aggregator,
            Some(SDK_TYPE_TYPESCRIPT) => ClientSdkType::TypeScript,
            Some(_) => ClientSdkType::Other,
            None => ClientSdkType::TypeScript, // Default to TypeScript for backward compatibility
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ClientSdkType::Aggregator => "aggregator",
            ClientSdkType::TypeScript => "typescript",
            ClientSdkType::Other => "other",
        }
    }
}

impl std::fmt::Display for ClientSdkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Trait for types that have network and node_url configuration.
/// Provides a common method to get the node URL.
pub trait NetworkConfig {
    fn network(&self) -> &Network;
    fn node_url_option(&self) -> &Option<String>;

    /// Get the node URL, using the custom value if set, otherwise the default for the network.
    fn node_url(&self) -> &str {
        self.node_url_option()
            .as_deref()
            .unwrap_or_else(|| self.network().default_node_url())
    }
}

/// Middleware to add key server version headers to all responses, used by key server and aggregator.
pub async fn add_response_headers(
    mut response: Response,
    package_version: &'static str,
    git_version: &'static str,
) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        HEADER_KEYSERVER_VERSION,
        HeaderValue::from_static(package_version),
    );
    headers.insert(
        HEADER_KEYSERVER_GIT_VERSION,
        HeaderValue::from_static(git_version),
    );
    response
}
