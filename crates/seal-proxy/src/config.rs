// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::BearerToken;
use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::HashMap;
use tracing::info;

/// RemoteWriteConfig defines the mimir config items for connecting to mimir
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RemoteWriteConfig {
    /// the remote_write url to post data to
    pub url: String,
    /// username is used for posting data to the remote_write api
    pub username: String,
    /// password to submit metrics
    pub password: String,
    /// Sets the maximum idle connection per host allowed in the pool.
    #[serde(default = "pool_max_idle_per_host_default")]
    pub pool_max_idle_per_host: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum LabelModifier {
    Add,
    Remove,
}

pub type LabelActions = HashMap<LabelModifier, HashMap<String, String>>;

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ProxyConfig {
    /// Sets the maximum idle connection per host allowed in the pool.
    #[serde(default = "pool_max_idle_per_host_default")]
    pub pool_max_idle_per_host: usize,
    /// label actions to apply to the metrics
    #[serde(default = "default_label_actions")]
    pub label_actions: LabelActions,
    pub remote_write: RemoteWriteConfig,
    /// what address to bind to
    #[serde(default = "listen_address_default")]
    pub listen_address: String,
    /// metrics address for the service itself
    #[serde(default = "metrics_address_default")]
    pub metrics_address: String,
    /// histogram address for the service itself
    #[serde(default = "histogram_address_default")]
    pub histogram_address: String,
}

/// the default idle worker per host (reqwest to remote write url call)
fn pool_max_idle_per_host_default() -> usize {
    8
}

fn listen_address_default() -> String {
    "0.0.0.0:8000".to_string()
}

fn metrics_address_default() -> String {
    "0.0.0.0:9185".to_string()
}

fn histogram_address_default() -> String {
    "0.0.0.0:8001".to_string()
}

fn default_label_actions() -> LabelActions {
    HashMap::new()
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
