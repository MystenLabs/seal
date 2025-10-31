// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::metrics_push::MetricsPushConfig;
use crate::time::from_mins;
use crate::types::Network;
use anyhow::{anyhow, Result};
use duration_str::deserialize_duration;
use semver::VersionReq;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use sui_types::base_types::ObjectID;
use tracing::info;

/// ClientKeyType for a permissioned client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ClientKeyType {
    Derived {
        derivation_index: u64, // Must be unique
    },
    Imported {
        env_var: String, // Expected a BLS key
    },
    Exported {
        // Indicates that the derived master key was exported and should not be used
        deprecated_derivation_index: u64, // Must be unique
    },
}

/// ClientConfig for a permissioned client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientConfig {
    pub name: String, // Internal name for tracking purposes
    pub client_master_key: ClientKeyType,
    pub key_server_object_id: ObjectID, // Must be unique
    pub package_ids: Vec<ObjectID>,     // first versions only
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ServerMode {
    Open {
        // Master key is expected to be a BLS key.
        /// The object ID of the key server object.
        key_server_object_id: ObjectID,
    },
    Permissioned {
        // Master key is expected to by 32 byte HKDF seed
        client_configs: Vec<ClientConfig>,
    },
}

/// Configuration for the RPC client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    /// The timeout for RPC requests.
    pub timeout: Duration,

    /// The retry configuration for RPC requests.
    pub retry_config: RetryConfig,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            retry_config: RetryConfig::default(),
        }
    }
}

/// Configuration for the retry logic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// The maximum number of retries.
    pub max_retries: u32,

    /// The minimum delay between retries.
    pub min_delay: Duration,

    /// The maximum delay between retries.
    pub max_delay: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            min_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyServerOptions {
    /// The network this key server is running on.
    pub network: Network,

    /// If the server is open or permissioned.
    pub server_mode: ServerMode,

    /// The minimum version of the SDK that is required to use this service.
    #[serde(default = "default_sdk_version_requirement")]
    pub sdk_version_requirement: VersionReq,

    #[serde(default = "default_metrics_host_port")]
    pub metrics_host_port: u16,

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

    /// The configuration for the Sui RPC client.
    #[serde(default)]
    pub rpc_config: RpcConfig,

    /// Optional configuration for pushing metrics to an external endpoint (e.g., seal-proxy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics_push_config: Option<MetricsPushConfig>,

    /// Object ID for an instance of the Seal Move package.
    pub seal_package: ObjectID,
}

impl KeyServerOptions {
    pub fn new_open_server_with_default_values(
        network: Network,
        key_server_object_id: ObjectID,
    ) -> Self {
        Self {
            sdk_version_requirement: default_sdk_version_requirement(),
            server_mode: ServerMode::Open {
                key_server_object_id,
            },
            metrics_host_port: default_metrics_host_port(),
            rgp_update_interval: default_rgp_update_interval(),
            allowed_staleness: default_allowed_staleness(),
            session_key_ttl_max: default_session_key_ttl_max(),
            rpc_config: RpcConfig::default(),
            metrics_push_config: None,
            seal_package: default_seal_package(&network),
            network,
        }
    }

    #[cfg(test)]
    pub fn new_for_testing(network: Network) -> Self {
        Self {
            sdk_version_requirement: default_sdk_version_requirement(),
            server_mode: ServerMode::Open {
                key_server_object_id: ObjectID::random(),
            },
            metrics_host_port: default_metrics_host_port(),
            rgp_update_interval: default_rgp_update_interval(),
            allowed_staleness: default_allowed_staleness(),
            session_key_ttl_max: default_session_key_ttl_max(),
            rpc_config: RpcConfig::default(),
            metrics_push_config: None,
            seal_package: default_seal_package(&network),
            network,
        }
    }

    /// Validate a set of client configurations for a permissioned server:
    /// 1. Each client must have at least one package ID.
    /// 2. A package ID can only be used by one client.
    /// 3. Each client name must be unique.
    /// 4. Each derived key or deprecated key (in case of export) must have a unique derivation index.
    /// 5. The set of derivation indices must be incremental starting from 0.
    /// 6. The environment variable names for clients with imported keys must be unique.
    pub fn validate(&self) -> Result<()> {
        info!(
            "Validating KeyServerOptions:\n{}",
            serde_yaml::to_string(self).expect("should serialize")
        );

        if let ServerMode::Permissioned { client_configs } = &self.server_mode {
            let mut names = std::collections::HashSet::new();
            let mut derivation_indices = std::collections::HashSet::new();
            let mut env_vars = std::collections::HashSet::new();
            let mut obj_ids = std::collections::HashSet::new();

            for config in client_configs {
                if config.package_ids.is_empty() {
                    return Err(anyhow!(
                        "Client configuration must have at least one package ID: {}",
                        config.name
                    ));
                }
                if !names.insert(config.name.clone()) {
                    return Err(anyhow!("Duplicate client name: {}", config.name));
                }
                match &config.client_master_key {
                    ClientKeyType::Derived { derivation_index }
                    | ClientKeyType::Exported {
                        deprecated_derivation_index: derivation_index,
                    } => {
                        if !derivation_indices.insert(*derivation_index) {
                            return Err(anyhow!(
                                "Duplicate derivation index: {}",
                                derivation_index
                            ));
                        }
                    }
                    ClientKeyType::Imported { env_var } => {
                        if !env_vars.insert(env_var.clone()) {
                            return Err(anyhow!("Duplicate environment variable: {}", env_var));
                        }
                    }
                }
                if !obj_ids.insert(config.key_server_object_id) {
                    return Err(anyhow!(
                        "Duplicate key server object ID: {}",
                        config.key_server_object_id
                    ));
                }
                for pkg_id in &config.package_ids {
                    if !obj_ids.insert(*pkg_id) {
                        return Err(anyhow!("Duplicate package ID: {}", pkg_id));
                    }
                }
            }

            // Check that derivation_indices has all the numbers from 0
            if (0..derivation_indices.len())
                .any(|derivation_index| !derivation_indices.contains(&(derivation_index as u64)))
            {
                return Err(anyhow!(
                    "Derivation indexes must be incremental, starting from 0"
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn get_supported_key_server_object_ids(&self) -> Vec<ObjectID> {
        match &self.server_mode {
            ServerMode::Open {
                key_server_object_id,
            } => {
                vec![*key_server_object_id]
            }
            ServerMode::Permissioned { client_configs } => client_configs
                .iter()
                .filter(|c| {
                    matches!(
                        c.client_master_key,
                        ClientKeyType::Derived { .. } | ClientKeyType::Imported { .. }
                    )
                })
                .map(|c| c.key_server_object_id)
                .collect(),
        }
    }
}

fn default_seal_package(network: &Network) -> ObjectID {
    match network {
        Network::Testnet => ObjectID::from_hex_literal(
            "0x1b89aca0d34b1179c0a742de8a7d7c40af457053c7103b0622f55f1b8c9a6c38",
        )
        .unwrap(),
        _ => ObjectID::from_hex_literal("0x").unwrap(), // TODO
    }
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
fn test_parse_open_config() {
    use crate::mvr::resolve_network;
    use std::str::FromStr;
    let valid_configuration = r#"
network: Mainnet
sdk_version_requirement: '>=0.2.7'
metrics_host_port: 1234
server_mode: !Open
  key_server_object_id: '0x0000000000000000000000000000000000000000000000000000000000000002'
rgp_update_interval: '5s'
allowed_staleness: '2s'
session_key_ttl_max: '60s'
seal_package: '0x01'
"#;

    let options: KeyServerOptions =
        serde_yaml::from_str(valid_configuration).expect("Failed to parse valid configuration");
    assert_eq!(options.network, Network::Mainnet);
    assert_eq!(options.sdk_version_requirement.to_string(), ">=0.2.7");
    assert_eq!(options.metrics_host_port, 1234);

    let expected_server_mode = ServerMode::Open {
        key_server_object_id: ObjectID::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap(),
    };
    assert_eq!(options.server_mode, expected_server_mode);

    let valid_configuration_custom_network = r#"
network: !Custom
  node_url: https://node.dk
  use_default_mainnet_for_mvr: false
server_mode: !Open
  key_server_object_id: '0x0'
seal_package: '0x01'
"#;
    let options: KeyServerOptions = serde_yaml::from_str(valid_configuration_custom_network)
        .expect("Failed to parse valid configuration");

    assert_eq!(resolve_network(&options.network).unwrap(), Network::Testnet);
    assert_eq!(
        options.network,
        Network::Custom {
            node_url: Some("https://node.dk".to_string()),
            use_default_mainnet_for_mvr: Some(false),
        }
    );

    let unknown_option = "a_complete_unknown: 'a rolling stone'\n";
    assert!(serde_yaml::from_str::<KeyServerOptions>(unknown_option).is_err());
}

#[test]
fn test_parse_custom_network_with_env_var() {
    use crate::mvr::resolve_network;
    // Test that NODE_URL can be omitted from config when not set in env
    let config_without_url = r#"
network: !Custom {}
server_mode: !Open
  key_server_object_id: '0x0'
seal_package: '0x01'
"#;

    let options: KeyServerOptions = serde_yaml::from_str(config_without_url)
        .expect("Failed to parse configuration without node_url");

    assert!(resolve_network(&options.network).unwrap() == Network::Mainnet);
    match options.network {
        Network::Custom { node_url, .. } => {
            assert_eq!(node_url, None);
        }
        _ => panic!("Expected Custom network"),
    }
}

#[test]
fn test_parse_permissioned_config() {
    use std::str::FromStr;

    let valid_configuration = r#"
network: Mainnet
sdk_version_requirement: '>=0.2.7'
metrics_host_port: 1234
server_mode: !Permissioned
  client_configs:
    - name: "alice"
      client_master_key: !Derived
        derivation_index: 1
      key_server_object_id: "0xaaaa000000000000000000000000000000000000000000000000000000000001"
      package_ids:
      - "0x1111111111111111111111111111111111111111111111111111111111111111"
    - name: "bob"
      client_master_key: !Imported
        env_var: "BOB_BLS_KEY"
      key_server_object_id: "0xbbbb000000000000000000000000000000000000000000000000000000000002"
      package_ids:
        - "0x2222222222222222222222222222222222222222222222222222222222222222"
        - "0x2222222222222222222222222222222222222222222222222222222222222223"
    - name: "carol"
      client_master_key: !Exported
        deprecated_derivation_index: 3
      key_server_object_id: "0xcccc000000000000000000000000000000000000000000000000000000000003"
      package_ids:
      - "0x3333333333333333333333333333333333333333333333333333333333333333"
rgp_update_interval: '5s'
allowed_staleness: '2s'
session_key_ttl_max: '60s'
seal_package: '0x01'
"#;

    let options: KeyServerOptions =
        serde_yaml::from_str(valid_configuration).expect("Failed to parse valid configuration");

    assert_eq!(
        options.get_supported_key_server_object_ids(),
        vec![
            ObjectID::from_str(
                "0xaaaa000000000000000000000000000000000000000000000000000000000001"
            )
            .unwrap(),
            ObjectID::from_str(
                "0xbbbb000000000000000000000000000000000000000000000000000000000002"
            )
            .unwrap(),
        ]
    );
}

#[test]
fn test_validate() {
    let empty_pkg = r#"
network: Mainnet
server_mode: !Permissioned
  client_configs:
    - name: "alice"
      client_master_key: !Derived
        derivation_index: 0
      key_server_object_id: "0xaaaa000000000000000000000000000000000000000000000000000000000001"
      package_ids:
seal_package: '0x01'
"#;
    let empty_pkg_expected_error = "Client configuration must have at least one package ID: alice";

    let dup_ks_oid = r#"
network: Mainnet
server_mode: !Permissioned
  client_configs:
    - name: "alice"
      client_master_key: !Derived
        derivation_index: 0
      key_server_object_id: "0xaaaa000000000000000000000000000000000000000000000000000000000001"
      package_ids:
      - "0x1111111111111111111111111111111111111111111111111111111111111111"
    - name: "bob"
      client_master_key: !Imported
        env_var: "BOB_BLS_KEY"
      key_server_object_id: "0xaaaa000000000000000000000000000000000000000000000000000000000001"
      package_ids:
        - "0x2222222222222222222222222222222222222222222222222222222222222222"
        - "0x2222222222222222222222222222222222222222222222222222222222222223"
seal_package: '0x01'
"#;
    let dup_ks_oid_expected_error =
        "Duplicate key server object ID: 0xaaaa000000000000000000000000000000000000000000000000000000000001";

    let dup_pkg_id = r#"
network: Mainnet
server_mode: !Permissioned
  client_configs:
    - name: "alice"
      client_master_key: !Derived
        derivation_index: 0
      key_server_object_id: "0xaaaa000000000000000000000000000000000000000000000000000000000001"
      package_ids:
      - "0x1111111111111111111111111111111111111111111111111111111111111111"
    - name: "bob"
      client_master_key: !Imported
        env_var: "BOB_BLS_KEY"
      key_server_object_id: "0xaaaa000000000000000000000000000000000000000000000000000000000002"
      package_ids:
        - "0x1111111111111111111111111111111111111111111111111111111111111111"
        - "0x2222222222222222222222222222222222222222222222222222222222222223"
seal_package: '0x01'
"#;
    let dup_pkg_id_expected_error =
        "Duplicate package ID: 0x1111111111111111111111111111111111111111111111111111111111111111";

    let dup_env_var = r#"
network: Mainnet
server_mode: !Permissioned
  client_configs:
    - name: "alice"
      client_master_key: !Imported
        env_var: "BOB_BLS_KEY"
      key_server_object_id: "0xaaaa000000000000000000000000000000000000000000000000000000000001"
      package_ids:
        - "0x2222222222222222222222222222222222222222222222222222222222222220"
        - "0x2222222222222222222222222222222222222222222222222222222222222221"
    - name: "bob"
      client_master_key: !Imported
        env_var: "BOB_BLS_KEY"
      key_server_object_id: "0xaaaa000000000000000000000000000000000000000000000000000000000002"
      package_ids:
        - "0x2222222222222222222222222222222222222222222222222222222222222222"
        - "0x2222222222222222222222222222222222222222222222222222222222222223"
seal_package: '0x01'
"#;
    let dup_env_var_expected_error = "Duplicate environment variable: BOB_BLS_KEY";

    let dup_derivation_index = r#"
network: Mainnet
server_mode: !Permissioned
  client_configs:
    - name: "alice"
      client_master_key: !Derived
        derivation_index: 0
      key_server_object_id: "0xaaaa000000000000000000000000000000000000000000000000000000000001"
      package_ids:
      - "0x1111111111111111111111111111111111111111111111111111111111111111"
    - name: "bob"
      client_master_key: !Derived
        derivation_index: 0
      key_server_object_id: "0xaaaa000000000000000000000000000000000000000000000000000000000002"
      package_ids:
        - "0x2222222222222222222222222222222222222222222222222222222222222222"
        - "0x2222222222222222222222222222222222222222222222222222222222222223"
seal_package: '0x01'
"#;
    let dup_derivation_index_expected_error = "Duplicate derivation index: 0";

    let non_incrementing_derivation_index = r#"
network: Mainnet
server_mode: !Permissioned
  client_configs:
    - name: "alice"
      client_master_key: !Derived
        derivation_index: 0
      key_server_object_id: "0xaaaa000000000000000000000000000000000000000000000000000000000001"
      package_ids:
      - "0x1111111111111111111111111111111111111111111111111111111111111111"
    - name: "bob"
      client_master_key: !Derived
        derivation_index: 3
      key_server_object_id: "0xaaaa000000000000000000000000000000000000000000000000000000000002"
      package_ids:
        - "0x2222222222222222222222222222222222222222222222222222222222222222"
        - "0x2222222222222222222222222222222222222222222222222222222222222223"
seal_package: '0x01'
"#;
    let non_incrementing_index_expected_error =
        "Derivation indexes must be incremental, starting from 0";

    // load each of those yaml and call validate
    let test_cases = vec![
        (empty_pkg, empty_pkg_expected_error),
        (dup_ks_oid, dup_ks_oid_expected_error),
        (dup_pkg_id, dup_pkg_id_expected_error),
        (dup_env_var, dup_env_var_expected_error),
        (dup_derivation_index, dup_derivation_index_expected_error),
        (
            non_incrementing_derivation_index,
            non_incrementing_index_expected_error,
        ),
    ];
    for (yaml, expected_error) in test_cases {
        let options: KeyServerOptions =
            serde_yaml::from_str(yaml).expect("Failed to parse valid configuration");
        let result = options.validate();
        assert!(result.is_err(), "Expected validation to fail for: {yaml}");
        assert_eq!(result.unwrap_err().to_string(), expected_error);
    }
}
