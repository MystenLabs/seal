// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::errors::InternalError;
use crate::key_server_options::{ClientConfig, ClientKeyType, KeyServerOptions, ServerMode};
use crate::types::IbeMasterKey;
use crate::utils::{decode_byte_array, decode_master_key};
use crate::DefaultEncoding;
use anyhow::anyhow;
use crypto::ibe;
use crypto::ibe::SEED_LENGTH;
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::serde_helpers::ToFromByteArray;
use std::collections::HashMap;
use sui_types::base_types::ObjectID;
use tracing::info;

/// In Open mode, the key server has a single master key which should be set in the environment variable `MASTER_KEY`.
const MASTER_KEY_ENV_VAR: &str = "MASTER_KEY";

/// In Permissioned mode, the key server has a seed used to derive master keys for clients, which should be set in the environment variable `MASTER_SEED`.
const MASTER_SEED_ENV_VAR: &str = "MASTER_SEED";

/// Represents the set of master keys held by a key server.
#[derive(Clone)]
pub enum MasterKeys {
    /// In open mode, the key server has a single master key used for all packages.
    Open { master_key: IbeMasterKey },
    /// In permissioned mode, the key server has a mapping of package IDs to master keys.
    Permissioned {
        pkg_id_to_key: HashMap<ObjectID, IbeMasterKey>,
        key_server_oid_to_key: HashMap<ObjectID, IbeMasterKey>,
    },
}

impl MasterKeys {
    pub(crate) fn load(options: &KeyServerOptions) -> anyhow::Result<Self> {
        info!("Loading keys from env variables");
        match &options.server_mode {
            ServerMode::Open { .. } => {
                let master_key = match decode_master_key::<DefaultEncoding>(MASTER_KEY_ENV_VAR) {
                    Ok(master_key) => master_key,

                    // TODO: Fallback to Base64 encoding for backward compatibility.
                    Err(_) => crate::utils::decode_master_key::<Base64>(MASTER_KEY_ENV_VAR)?,
                };
                Ok(MasterKeys::Open { master_key })
            }
            ServerMode::Permissioned { client_configs } => {
                let mut pkg_id_to_key = HashMap::new();
                let mut key_server_oid_to_key = HashMap::new();
                let seed = decode_byte_array::<DefaultEncoding, SEED_LENGTH>(MASTER_SEED_ENV_VAR)?;
                for config in client_configs {
                    let master_key = match &config.client_master_key {
                        ClientKeyType::Derived { derivation_index } => {
                            ibe::derive_master_key(&seed, *derivation_index)
                        }
                        ClientKeyType::Imported { env_var } => {
                            decode_master_key::<DefaultEncoding>(env_var)?
                        }
                        ClientKeyType::Exported { .. } => continue,
                    };

                    info!(
                        "Client {:?} uses public key: {:?}",
                        config.name,
                        DefaultEncoding::encode(
                            ibe::public_key_from_master_key(&master_key).to_byte_array()
                        )
                    );

                    for pkg_id in &config.package_ids {
                        pkg_id_to_key.insert(*pkg_id, master_key);
                    }
                    key_server_oid_to_key.insert(config.key_server_object_id, master_key);
                }

                Self::log_unassigned_public_keys(client_configs, &seed);

                // No clients, can abort.
                if pkg_id_to_key.is_empty() {
                    return Err(anyhow!("No clients found in the configuration"));
                }

                Ok(MasterKeys::Permissioned {
                    pkg_id_to_key,
                    key_server_oid_to_key,
                })
            }
        }
    }

    /// Log the next 10 unassigned public keys.
    /// This is done to make it easier to find a public key of a derived key that's not yet assigned to a client.
    /// Can be removed once an endpoint to get public keys from derivation indices is implemented.
    fn log_unassigned_public_keys(client_configs: &[ClientConfig], seed: &[u8; SEED_LENGTH]) {
        // The derivation indices are in incremental order, so the next free index is the max + 1 or 0 if no derivation indices are used.
        let next_free_derivation_index = client_configs
            .iter()
            .filter_map(|c| match &c.client_master_key {
                ClientKeyType::Derived { derivation_index } => Some(*derivation_index),
                ClientKeyType::Exported {
                    deprecated_derivation_index,
                } => Some(*deprecated_derivation_index),
                _ => None,
            })
            .max()
            .map(|i| i + 1)
            .unwrap_or(0);
        for i in 0..10 {
            let key = ibe::derive_master_key(seed, next_free_derivation_index + i);
            info!(
                "Unassigned derived public key with index {}: {:?}",
                next_free_derivation_index + i,
                DefaultEncoding::encode(ibe::public_key_from_master_key(&key).to_byte_array())
            );
        }
    }

    pub(crate) fn has_key_for_package(&self, id: &ObjectID) -> anyhow::Result<(), InternalError> {
        self.get_key_for_package(id).map(|_| ())
    }

    pub(crate) fn get_key_for_package(
        &self,
        package_id: &ObjectID,
    ) -> anyhow::Result<&IbeMasterKey, InternalError> {
        match self {
            MasterKeys::Open { master_key } => Ok(master_key),
            MasterKeys::Permissioned { pkg_id_to_key, .. } => pkg_id_to_key
                .get(package_id)
                .ok_or(InternalError::UnsupportedPackageId),
        }
    }

    pub(crate) fn get_key_for_key_server(
        &self,
        key_server_object_id: &ObjectID,
    ) -> anyhow::Result<&IbeMasterKey, InternalError> {
        match self {
            MasterKeys::Open { master_key } => Ok(master_key),
            MasterKeys::Permissioned {
                key_server_oid_to_key,
                ..
            } => key_server_oid_to_key
                .get(key_server_object_id)
                .ok_or(InternalError::InvalidServiceId),
        }
    }
}

#[test]
fn test_master_keys_open_mode() {
    use crate::key_server_options::KeyServerOptions;
    use crate::types::{IbeMasterKey, Network};
    use crate::DefaultEncoding;
    use fastcrypto::encoding::Encoding;
    use fastcrypto::groups::GroupElement;
    use sui_types::base_types::ObjectID;
    use temp_env::with_vars;

    let options = KeyServerOptions::new_open_server_with_default_values(
        Network::Testnet,
        ObjectID::from_hex_literal("0x2").unwrap(),
    );

    with_vars([("MASTER_KEY", None::<&str>)], || {
        assert!(MasterKeys::load(&options).is_err());
    });

    let sk = IbeMasterKey::generator();
    let sk_as_bytes = DefaultEncoding::encode(bcs::to_bytes(&sk).unwrap());
    with_vars([("MASTER_KEY", Some(sk_as_bytes))], || {
        let mk = MasterKeys::load(&options);
        assert_eq!(
            mk.unwrap()
                .get_key_for_package(&ObjectID::from_hex_literal("0x1").unwrap())
                .unwrap(),
            &sk
        );
    });
}

#[test]
fn test_master_keys_permissioned_mode() {
    use crate::key_server_options::ClientConfig;
    use crate::types::Network;
    use fastcrypto::encoding::Encoding;
    use fastcrypto::groups::GroupElement;
    use temp_env::with_vars;

    let mut options = KeyServerOptions::new_open_server_with_default_values(
        Network::Testnet,
        ObjectID::from_hex_literal("0x2").unwrap(),
    );
    options.server_mode = ServerMode::Permissioned {
        client_configs: vec![
            ClientConfig {
                name: "alice".to_string(),
                package_ids: vec![ObjectID::from_hex_literal("0x1").unwrap()],
                key_server_object_id: ObjectID::from_hex_literal("0x2").unwrap(),
                client_master_key: ClientKeyType::Imported {
                    env_var: "ALICE_KEY".to_string(),
                },
            },
            ClientConfig {
                name: "bob".to_string(),
                package_ids: vec![ObjectID::from_hex_literal("0x3").unwrap()],
                key_server_object_id: ObjectID::from_hex_literal("0x4").unwrap(),
                client_master_key: ClientKeyType::Derived {
                    derivation_index: 100,
                },
            },
            ClientConfig {
                name: "dan".to_string(),
                package_ids: vec![ObjectID::from_hex_literal("0x5").unwrap()],
                key_server_object_id: ObjectID::from_hex_literal("0x6").unwrap(),
                client_master_key: ClientKeyType::Derived {
                    derivation_index: 200,
                },
            },
        ],
    };
    let sk = IbeMasterKey::generator();
    let sk_as_bytes = DefaultEncoding::encode(bcs::to_bytes(&sk).unwrap());
    let seed = [1u8; 32];
    with_vars(
        [
            ("MASTER_SEED", Some(sk_as_bytes.clone())),
            ("ALICE_KEY", Some(DefaultEncoding::encode(seed))),
        ],
        || {
            let mk = MasterKeys::load(&options).unwrap();
            let k1 = mk.get_key_for_key_server(&ObjectID::from_hex_literal("0x4").unwrap());
            let k2 = mk.get_key_for_key_server(&ObjectID::from_hex_literal("0x6").unwrap());
            assert!(k1.is_ok());
            assert_ne!(k1, k2);
        },
    );
    with_vars(
        [
            ("MASTER_SEED", None::<&str>),
            ("ALICE_KEY", Some(&DefaultEncoding::encode(seed))),
        ],
        || {
            assert!(MasterKeys::load(&options).is_err());
        },
    );
    with_vars(
        [
            ("MASTER_SEED", Some(&sk_as_bytes)),
            ("ALICE_KEY", None::<&String>),
        ],
        || {
            assert!(MasterKeys::load(&options).is_err());
        },
    );
}
