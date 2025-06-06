// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::from_mins;
use crate::types::Network;
use duration_str::deserialize_duration;
use semver::VersionReq;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use sui_types::base_types::ObjectID;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyServerOptions {
    #[serde(default = "default_network")]
    pub network: Network,

    pub sdk_version_requirement: VersionReq,

    // TODO: remove this when the legacy key server is no longer needed
    pub legacy_key_server_object_id: ObjectID,

    pub key_server_object_id: ObjectID,

    #[serde(
        default = "default_checkpoint_update_interval",
        deserialize_with = "deserialize_duration"
    )]
    pub checkpoint_update_interval: Duration,

    #[serde(
        default = "default_rgp_update_interval",
        deserialize_with = "deserialize_duration"
    )]
    pub rgp_update_interval: Duration,

    #[serde(
        default = "default_allowed_staleness",
        deserialize_with = "deserialize_duration"
    )]
    pub allowed_staleness: Duration,

    #[serde(
        default = "default_session_key_ttl_max",
        deserialize_with = "deserialize_duration"
    )]
    pub session_key_ttl_max: Duration,
}

fn default_network() -> Network {
    Network::Testnet
}

fn default_checkpoint_update_interval() -> Duration {
    Duration::from_secs(10)
}

fn default_rgp_update_interval() -> Duration {
    Duration::from_secs(60)
}

fn default_session_key_ttl_max() -> Duration {
    from_mins(30)
}

fn default_allowed_staleness() -> Duration {
    from_mins(2)
}
