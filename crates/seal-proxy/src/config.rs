// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use anyhow::{Result, Context};
use serde_with::{serde_as};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tracing::debug;
use crate::BearerToken;
use serde_with::DurationSeconds;
use std::time::Duration;

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

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct BearerTokenConfigItem {
    pub bearer_token: BearerToken,
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct BearerTokenConfig {
    pub items: Vec<BearerTokenConfigItem>,
}

/// load our config file from a path
pub fn load<P: AsRef<std::path::Path>, T: DeserializeOwned + Serialize>(path: P) -> Result<T> {
    let path = path.as_ref();
    debug!("Reading config from {:?}", path);
    Ok(serde_yaml::from_reader(
        std::fs::File::open(path).context(format!("cannot open {:?}", path))?,
    )?)
}


#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct MetricsPushConfig {
    /// The interval of time we will allow to elapse before pushing metrics.
    #[serde_as(as = "DurationSeconds<u64>")]
    #[serde(
        rename = "push_interval_secs",
        default = "push_interval",
        skip_serializing_if = "is_push_interval_default"
    )]
    pub push_interval: Duration,
    /// The URL that we will push metrics to.
    pub push_url: String,
    /// Static labels to provide to the push process.
    #[serde(default, skip_serializing_if = "is_none")]
    pub labels: Option<HashMap<String, String>>,
}

/// Configure the default push interval for metrics.
pub fn push_interval() -> Duration {
    Duration::from_secs(60)
}

/// Returns true if the `duration` is equal to the default push interval for metrics.
pub fn is_push_interval_default(duration: &Duration) -> bool {
    duration == &push_interval()
}

/// Returns true iff the value is `None` and we don't run in test mode.
pub fn is_none<T>(t: &Option<T>) -> bool {
    // The `cfg!(test)` check is there to allow serializing the full configuration, specifically
    // to generate the example configuration files.
    !cfg!(test) && t.is_none()
}