// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::BearerToken;
use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use tracing::info;

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ProxyConfig {
    /// Sets the maximum idle connection per host allowed in the pool.
    #[serde(default = "pool_max_idle_per_host_default")]
    pub pool_max_idle_per_host: usize,
    #[serde(default = "mimir_url_default")]
    pub mimir_url: String,
    /// what address to bind to
    #[serde(default = "listen_address_default")]
    pub listen_address: String,
    /// metrics address for the service itself
    #[serde(default = "metrics_address_default")]
    pub metrics_address: String,
}

/// the default idle worker per host (reqwest to remote write url call)
fn pool_max_idle_per_host_default() -> usize {
    8
}

/// the default mimir url
fn mimir_url_default() -> String {
    "http://localhost:9000/api/v1/metrics/write".to_string()
}

fn listen_address_default() -> String {
    "0.0.0.0:8000".to_string()
}

fn metrics_address_default() -> String {
    "0.0.0.0:9185".to_string()
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct BearerTokenConfigItem {
    pub token: BearerToken,
    pub name: String,
}

pub type BearerTokenConfig = Vec<BearerTokenConfigItem>;

/// load our config file from a path
pub fn load<P: AsRef<std::path::Path>, T: DeserializeOwned + Serialize + std::fmt::Debug>(
    path: P,
) -> Result<T> {
    let path = path.as_ref();
    info!("Reading config from {:?}", path);
    // deserialize the config file and put it into a BearerTokenConfig
    let config: T = serde_yaml::from_reader(
        std::fs::File::open(path).context(format!("cannot open {:?}", path))?,
    )?;
    Ok(config)
}
