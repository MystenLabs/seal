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
    // TODO: remove this when the legacy key server is no longer needed
    /// The object ID of the legacy key server object.
    pub legacy_key_server_object_id: ObjectID,

    /// The object ID of the key server object.
    pub key_server_object_id: ObjectID,

    /// The network this key server is running on.
    pub network: Network,

    /// The minimum version of the SDK that is required to use this service.
    #[serde(default = "default_sdk_version_requirement")]
    pub sdk_version_requirement: VersionReq,

    #[serde(default = "default_metrics_host_port")]
    pub metrics_host_port: u16,

    /// The interval at which the latest checkpoint timestamp is updated.
    #[serde(
        default = "default_checkpoint_update_interval",
        deserialize_with = "deserialize_duration"
    )]
    pub checkpoint_update_interval: Duration,

    /// The interval at which the reference gas price is updated.
    #[serde(
        default = "default_rgp_update_interval",
        deserialize_with = "deserialize_duration"
    )]
    pub rgp_update_interval: Duration,

    /// The allowed staleness of the full node.
    /// When setting this duration, note a timestamp on Sui may be a bit late compared to
    /// the current time, but it shouldn't be more than a second.
    #[serde(
        default = "default_allowed_staleness",
        deserialize_with = "deserialize_duration"
    )]
    pub allowed_staleness: Duration,

    /// The maximum time to live for a session key.
    #[serde(
        default = "default_session_key_ttl_max",
        deserialize_with = "deserialize_duration"
    )]
    pub session_key_ttl_max: Duration,
}

impl KeyServerOptions {
    pub fn new_with_default_values(
        network: Network,
        legacy_key_server_object_id: ObjectID,
        key_server_object_id: ObjectID,
    ) -> Self {
        Self {
            network,
            sdk_version_requirement: default_sdk_version_requirement(),
            legacy_key_server_object_id,
            key_server_object_id,
            metrics_host_port: default_metrics_host_port(),
            checkpoint_update_interval: default_checkpoint_update_interval(),
            rgp_update_interval: default_rgp_update_interval(),
            allowed_staleness: default_allowed_staleness(),
            session_key_ttl_max: default_session_key_ttl_max(),
        }
    }
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

fn default_metrics_host_port() -> u16 {
    9184
}

fn default_sdk_version_requirement() -> VersionReq {
    VersionReq::parse(">=0.4.5").expect("Failed to parse default SDK version requirement")
}

#[test]
fn test_parse_config() {
    use std::str::FromStr;

    let valid_configuration =
        "network: Mainnet\nsdk_version_requirement: '>=0.2.7'\nmetrics_host_port: 1234\nlegacy_key_server_object_id: '0x0000000000000000000000000000000000000000000000000000000000000001'\nkey_server_object_id: '0x0000000000000000000000000000000000000000000000000000000000000002'\ncheckpoint_update_interval: '13s'";

    let options: KeyServerOptions =
        serde_yaml::from_str(valid_configuration).expect("Failed to parse valid configuration");
    assert_eq!(options.network, Network::Mainnet);
    assert_eq!(options.sdk_version_requirement.to_string(), ">=0.2.7");
    assert_eq!(options.metrics_host_port, 1234);
    assert_eq!(
        options.legacy_key_server_object_id,
        ObjectID::from_str("0x0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap()
    );
    assert_eq!(
        options.key_server_object_id,
        ObjectID::from_str("0x0x0000000000000000000000000000000000000000000000000000000000000002")
            .unwrap()
    );
    assert_eq!(options.checkpoint_update_interval, Duration::from_secs(13));

    let valid_configuration_custom_network =
        "network: !Custom\n  graphql_url: https://graphql.dk\n  node_url: https://node.dk\nlegacy_key_server_object_id: '0x0'\nkey_server_object_id: '0x0'\n";
    let options: KeyServerOptions = serde_yaml::from_str(valid_configuration_custom_network)
        .expect("Failed to parse valid configuration");
    assert_eq!(
        options.network,
        Network::Custom {
            graphql_url: "https://graphql.dk".to_string(),
            node_url: "https://node.dk".to_string(),
        }
    );

    let missing_object_id = "legacy_key_server_object_id: '0x0'\n";
    assert!(serde_yaml::from_str::<KeyServerOptions>(missing_object_id).is_err());

    let unknown_option = "a_complete_unknown: 'a rolling stone'\n";
    assert!(serde_yaml::from_str::<KeyServerOptions>(unknown_option).is_err());
}
