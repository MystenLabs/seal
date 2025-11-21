// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::errors::InternalError;
use crate::key_server_options::{
    ClientConfig, ClientKeyType, CommitteeState, KeyServerOptions, ServerMode,
};
use crate::types::IbeMasterKey;
use crate::utils::{decode_byte_array, decode_master_key};
use crate::DefaultEncoding;
use anyhow::anyhow;
use crypto::ibe;
use crypto::ibe::SEED_LENGTH;
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::serde_helpers::ToFromByteArray;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use sui_types::base_types::ObjectID;
use tracing::info;

const MASTER_KEY_ENV_VAR: &str = "MASTER_KEY";

/// Load a master share from environment variable of the version.
fn load_master_share(version: u32) -> anyhow::Result<IbeMasterKey> {
    decode_master_key::<DefaultEncoding>(&format!("MASTER_SHARE_V{version}"))
        .map_err(|e| anyhow!("Expected MASTER_SHARE_V{}: {}", version, e))
}

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
    /// In committee mode, contains key state and current onchain committee version.
    Committee {
        key_state: CommitteeKeyState,
        /// The current version, atomically updated when rotation completes.
        committee_version: Arc<AtomicU32>,
    },
}

/// Represents the state of committee master keys.
/// 1) Active state: master_share is always used.
/// 2) Rotation state: the master_share is used when current version is 1 behind target, and
///    next_master_share is used when they are equal.
#[derive(Clone)]
pub(crate) enum CommitteeKeyState {
    Active {
        master_share: IbeMasterKey,
    },
    Rotation {
        master_share: IbeMasterKey,
        next_master_share: IbeMasterKey,
        target_version: u32,
    },
}

impl MasterKeys {
    /// Load master keys from environment variables.
    /// For Committee mode, committee_version must be provided (fetched from blockchain by caller).
    /// If committee_version == target_version, loads only MASTER_SHARE_V{target_version} in Active mode.
    /// If committee_version == target_version - 1, loads both shares in Rotation mode.
    pub(crate) fn load(
        options: &KeyServerOptions,
        committee_version: Option<u32>,
    ) -> anyhow::Result<Self> {
        info!("Loading keys from env variables");
        match &options.server_mode {
            ServerMode::Open { .. } => {
                let master_key = match decode_master_key::<DefaultEncoding>(MASTER_KEY_ENV_VAR) {
                    Ok(master_key) => master_key,

                    // TODO: Fallback to Base64 encoding for backward compatibility.
                    Err(_) => decode_master_key::<Base64>(MASTER_KEY_ENV_VAR)?,
                };
                Ok(MasterKeys::Open { master_key })
            }
            ServerMode::Committee {
                committee_state, ..
            } => {
                let committee_version =
                    committee_version.expect("Onchain committee version must be loaded.");

                let key_state = match committee_state {
                    CommitteeState::Active => {
                        let master_share = load_master_share(committee_version)?;
                        CommitteeKeyState::Active { master_share }
                    }
                    CommitteeState::Rotation { target_version } => {
                        let target = *target_version;
                        if target == 0 {
                            anyhow::bail!("Invalid rotation config: target_version cannot be 0");
                        }

                        if committee_version == target {
                            // Rotation completed, just load MASTER_SHARE_V{target} and ignore others.
                            let master_share = load_master_share(target)?;
                            CommitteeKeyState::Active { master_share }
                        } else if committee_version == target - 1 {
                            // Rotation in progress, load both shares.
                            let master_share = load_master_share(committee_version)?;
                            let next_master_share = load_master_share(target)?;
                            CommitteeKeyState::Rotation {
                                master_share,
                                next_master_share,
                                target_version: target,
                            }
                        } else {
                            anyhow::bail!(
                                "Rotation mode mismatch: version {} doesn't match {} or {}",
                                committee_version,
                                target - 1,
                                target
                            );
                        }
                    }
                };

                Ok(MasterKeys::Committee {
                    key_state,
                    committee_version: Arc::new(AtomicU32::new(committee_version)),
                })
            }
            ServerMode::Permissioned { client_configs } => {
                let mut pkg_id_to_key = HashMap::new();
                let mut key_server_oid_to_key = HashMap::new();
                let seed = decode_byte_array::<DefaultEncoding, SEED_LENGTH>(MASTER_KEY_ENV_VAR)?;
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
            MasterKeys::Committee { .. } => self.get_committee_server_master_share(),
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
            MasterKeys::Committee { .. } => self.get_committee_server_master_share(),
            MasterKeys::Permissioned {
                key_server_oid_to_key,
                ..
            } => key_server_oid_to_key
                .get(key_server_object_id)
                .ok_or(InternalError::InvalidServiceId),
        }
    }
    /// Load committee version to determine which master share to use.
    pub(crate) fn get_committee_server_master_share(
        &self,
    ) -> anyhow::Result<&IbeMasterKey, InternalError> {
        match self {
            MasterKeys::Committee {
                key_state,
                committee_version,
            } => match key_state {
                CommitteeKeyState::Active { master_share } => Ok(master_share),
                CommitteeKeyState::Rotation {
                    master_share,
                    next_master_share,
                    target_version,
                } => {
                    if committee_version.load(Ordering::Relaxed) == *target_version {
                        Ok(next_master_share)
                    } else {
                        Ok(master_share)
                    }
                }
            },
            _ => panic!("get_committee_server_master_share called on non-Committee mode"),
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
        let result = MasterKeys::load(&options, None);
        assert!(result.is_err());
    });

    let sk = IbeMasterKey::generator();
    let sk_as_bytes = DefaultEncoding::encode(bcs::to_bytes(&sk).unwrap());
    with_vars([("MASTER_KEY", Some(sk_as_bytes))], || {
        let mk = MasterKeys::load(&options, None);
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
            ("MASTER_KEY", Some(sk_as_bytes.clone())),
            ("ALICE_KEY", Some(DefaultEncoding::encode(seed))),
        ],
        || {
            let mk = MasterKeys::load(&options, None).unwrap();
            let k1 = mk.get_key_for_key_server(&ObjectID::from_hex_literal("0x4").unwrap());
            let k2 = mk.get_key_for_key_server(&ObjectID::from_hex_literal("0x6").unwrap());
            assert!(k1.is_ok());
            assert_ne!(k1, k2);
        },
    );

    with_vars(
        [
            ("MASTER_KEY", None::<&str>),
            ("ALICE_KEY", Some(&DefaultEncoding::encode(seed))),
        ],
        || {
            assert!(MasterKeys::load(&options, None).is_err());
        },
    );

    with_vars(
        [
            ("MASTER_KEY", Some(&sk_as_bytes)),
            ("ALICE_KEY", None::<&String>),
        ],
        || {
            assert!(MasterKeys::load(&options, None).is_err());
        },
    );
}

#[test]
fn test_master_keys_committee_mode() {
    use crate::types::Network;
    use fastcrypto::encoding::Encoding;
    use std::sync::atomic::Ordering;
    use sui_sdk_types::Address;
    use temp_env::with_vars;

    use fastcrypto::groups::bls12381::Scalar;
    let master_share_v4 = Scalar::from(4u128);
    let master_share_v5 = Scalar::from(5u128);
    let master_share_v4_encoded = DefaultEncoding::encode(bcs::to_bytes(&master_share_v4).unwrap());
    let master_share_v5_encoded = DefaultEncoding::encode(bcs::to_bytes(&master_share_v5).unwrap());

    // Test Rotation mode.
    let mut options =
        KeyServerOptions::new_open_server_with_default_values(Network::Testnet, ObjectID::ZERO);
    options.server_mode = ServerMode::Committee {
        member_address: Address::ZERO,
        key_server_obj_id: Address::TWO,
        committee_state: CommitteeState::Rotation { target_version: 5 },
    };

    with_vars(
        [
            ("MASTER_SHARE_V4", Some(&master_share_v4_encoded)),
            ("MASTER_SHARE_V5", Some(&master_share_v5_encoded)),
        ],
        || {
            // Rotation mode: onchain is 4, target is 5, V4 is used.
            let mk = MasterKeys::load(&options, Some(4)).unwrap();
            assert_eq!(
                mk.get_committee_server_master_share().unwrap(),
                &master_share_v4
            );

            if let MasterKeys::Committee {
                committee_version, ..
            } = &mk
            {
                // After updating current version to target, V5 is used.
                committee_version.store(5, Ordering::Relaxed);
                assert_eq!(
                    mk.get_committee_server_master_share().unwrap(),
                    &master_share_v5
                );
            }
        },
    );

    // Test Active mode.
    options.server_mode = ServerMode::Committee {
        member_address: Address::ZERO,
        key_server_obj_id: Address::TWO,
        committee_state: CommitteeState::Active,
    };

    with_vars(
        [("MASTER_SHARE_V5", Some(&master_share_v5_encoded))],
        || {
            // Active mode: onchain version is 5, use V5.
            let mk = MasterKeys::load(&options, Some(5)).unwrap();
            assert_eq!(
                mk.get_committee_server_master_share().unwrap(),
                &master_share_v5
            );
        },
    );

    // Error for missing MASTER_SHARE_V{onchain} in Active mode.
    with_vars(
        [("MASTER_SHARE_V4", Some(&master_share_v4_encoded))],
        || {
            let result = MasterKeys::load(&options, Some(5));
            assert!(result.is_err());
        },
    );

    // Error for missing MASTER_SHARE_V{target-1} in Rotation mode.
    options.server_mode = ServerMode::Committee {
        member_address: Address::ZERO,
        key_server_obj_id: Address::TWO,
        committee_state: CommitteeState::Rotation { target_version: 5 },
    };
    with_vars(
        [("MASTER_SHARE_V5", Some(&master_share_v5_encoded))],
        || {
            let result = MasterKeys::load(&options, Some(4));
            assert!(result.is_err());
        },
    );
}
