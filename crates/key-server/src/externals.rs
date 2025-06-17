// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::cache::Cache;
use crate::errors::InternalError;
use crate::types::Network;
use crate::{mvr_forward_resolution, Timestamp};
use std::sync::Arc;
use std::time::Duration;
use sui_sdk::error::SuiRpcResult;
use sui_sdk::rpc_types::{CheckpointId, SuiData, SuiObjectDataOptions};
use sui_sdk::SuiClient;
use sui_types::base_types::ObjectID;
use tap::TapFallible;
use tracing::{debug, warn};

pub(crate) struct PackageManager {
    cache: Cache<ObjectID, ObjectID>,
    sui_client: Arc<SuiClient>,
}

impl PackageManager {
    pub fn new(sui_client: Arc<SuiClient>, cache_size: usize) -> Self {
        Self {
            cache: Cache::new(cache_size),
            sui_client,
        }
    }

    pub async fn fetch_first_pkg_id(&self, pkg_id: &ObjectID) -> Result<ObjectID, InternalError> {
        if let Some(first) = self.cache.get(pkg_id) {
            return Ok(first);
        }

        let object = self
            .sui_client
            .read_api()
            .get_object_with_options(*pkg_id, SuiObjectDataOptions::default().with_bcs())
            .await
            .map_err(|_| InternalError::Failure)? // internal error that fullnode fails to respond, check fullnode.
            .into_object()
            .map_err(|_| InternalError::InvalidPackage)?; // user error that object does not exist or deleted.

        let package = object
            .bcs
            .ok_or(InternalError::Failure)? // internal error that fullnode does not respond with bcs even though request includes the bcs option.
            .try_as_package()
            .ok_or(InternalError::InvalidPackage)?
            .to_move_package(u64::MAX)
            .map_err(|_| InternalError::InvalidPackage)?; // user error if the provided package throw MovePackageTooBig.

        let first = package.original_package_id();
        self.cache.insert(*pkg_id, first);
        Ok(first)
    }

    #[cfg(test)]
    pub(crate) fn add_package(&self, pkg_id: ObjectID) {
        self.cache.insert(pkg_id, pkg_id);
    }

    #[cfg(test)]
    pub(crate) fn add_upgraded_package(&self, pkg_id: ObjectID, new_pkg_id: ObjectID) {
        self.cache.insert(new_pkg_id, pkg_id);
    }
}

pub(crate) struct MvrManager {
    cache: Cache<String, ObjectID>,
    sui_client: Arc<SuiClient>,
    network: Network,
}

impl MvrManager {
    pub fn new(sui_client: Arc<SuiClient>, network: Network, cache_size: usize) -> Self {
        Self {
            cache: Cache::new(cache_size),
            sui_client,
            network,
        }
    }

    pub async fn check_mvr_package_id(
        &self,
        mvr_name: &Option<String>,
        first_pkg_id: ObjectID,
        req_id: Option<&str>,
    ) -> Result<(), InternalError> {
        let Some(mvr_name) = &mvr_name else {
            return Ok(());
        };

        // If an MVR name is provided, get it from cache or resolve it to the package
        // id. Then check that it points to the first package ID.
        let mvr_package_id = match self.cache_get(mvr_name) {
            None => {
                let mvr_package_id =
                    mvr_forward_resolution(&self.sui_client, mvr_name, &self.network).await?;
                debug!(
                    "Resolved MVR name {} to package ID {} and adding it to the cache (req_id: {:?})",
                    mvr_name, mvr_package_id, req_id
                );
                self.cache_insert(mvr_name.to_string(), mvr_package_id);
                mvr_package_id
            }
            Some(mvr_package_id) => {
                debug!(
                    "MVR name {} is already in cache (req_id: {:?})",
                    mvr_name, req_id
                );
                mvr_package_id
            }
        };
        if mvr_package_id != first_pkg_id {
            debug!(
                "MVR name {} points to package ID {:?} while the first package ID is {:?} (req_id: {:?})",
                mvr_name, mvr_package_id, first_pkg_id, req_id
            );
            return Err(InternalError::InvalidMVRName);
        }
        Ok(())
    }

    fn cache_insert(&self, mvr_name: String, package_id: ObjectID) {
        self.cache.insert(mvr_name, package_id);
    }

    fn cache_get(&self, mvr_name: &String) -> Option<ObjectID> {
        self.cache.get(mvr_name)
    }
}

/// Returns the timestamp for the latest checkpoint.
pub(crate) async fn get_latest_checkpoint_timestamp(
    client: Arc<SuiClient>,
) -> SuiRpcResult<Timestamp> {
    let latest_checkpoint_sequence_number = client
        .read_api()
        .get_latest_checkpoint_sequence_number()
        .await?;
    let checkpoint = client
        .read_api()
        .get_checkpoint(CheckpointId::SequenceNumber(
            latest_checkpoint_sequence_number,
        ))
        .await?;
    Ok(checkpoint.timestamp_ms)
}

pub(crate) async fn get_reference_gas_price(client: Arc<SuiClient>) -> SuiRpcResult<u64> {
    let rgp = client
        .read_api()
        .get_reference_gas_price()
        .await
        .tap_err(|e| {
            warn!("Failed retrieving RGP ({:?})", e);
        })?;
    Ok(rgp)
}

/// Compute the difference between the current time and the offset in milliseconds.
/// The offset and the difference between the current time and the offset are cast to i64,
/// so the caller should be aware of the potential overflow.
pub(crate) fn duration_since(offset: u64) -> i64 {
    let now = current_epoch_time() as i64;
    now - offset as i64
}

/// Returns the duration since the offset in milliseconds.
/// Returns `Duration::ZERO` if the offset is greater than the current time.
pub(crate) fn safe_duration_since(offset: u64) -> Duration {
    let duration = duration_since(offset);
    if duration < 0 {
        warn!("Offset is greater than current time, returning 0");
        return Duration::ZERO;
    }
    Duration::from_millis(duration as u64)
}

pub(crate) fn current_epoch_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("fixed start time")
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use fastcrypto::{
        ed25519::Ed25519KeyPair, secp256k1::Secp256k1KeyPair, secp256r1::Secp256r1KeyPair,
    };
    use shared_crypto::intent::{Intent, IntentMessage, PersonalMessage};
    use sui_sdk::{
        verify_personal_message_signature::verify_personal_message_signature, SuiClientBuilder,
    };
    use sui_types::{
        crypto::{get_key_pair, Signature},
        signature::GenericSignature,
    };

    use super::*;

    async fn package_manager() -> PackageManager {
        PackageManager::new(Arc::new(SuiClientBuilder::default()
            .build(&Network::Testnet.node_url())
            .await
            .expect("SuiClientBuilder should not failed unless provided with invalid network url")), 1000)
    }

    #[tokio::test]
    async fn test_fetch_first_pkg_id() {
        let address = ObjectID::from_str(
            "0xac7890f847ac6973ca615af9d7bbb642541f175e35e340e5d1241d0ffda9ed04",
        )
        .unwrap();
        match package_manager().await.fetch_first_pkg_id(&address).await {
            Ok(first) => {
                assert_eq!(
                    first.to_hex_literal(),
                    "0x717d42d8205adeb14b440d6b46c8524d7479952099435261defa1b57f151bf16"
                        .to_string()
                );
                println!("First address: {:?}", first);
            }
            Err(e) => panic!("Test failed with error: {:?}", e),
        }
    }
    #[tokio::test]
    async fn test_mvr_manager() {
        let mvr_manager = MvrManager::new(
            Arc::new(SuiClientBuilder::default().build_mainnet().await.expect(
                "SuiClientBuilder should not failed unless provided with invalid network url",
            )),
            Network::Mainnet,
            1000,
        );

        assert!(mvr_manager
            .check_mvr_package_id(
                &Some("@mysten/kiosk".to_string()),
                ObjectID::from_str(
                    "0xdfb4f1d4e43e0c3ad834dcd369f0d39005c872e118c9dc1c5da9765bb93ee5f3"
                )
                .unwrap(),
                None
            )
            .await
            .is_ok());

        // Verify the cache is added.
        assert_eq!(
            mvr_manager.cache_get(&"@mysten/kiosk".to_string()),
            Some(
                ObjectID::from_str(
                    "0xdfb4f1d4e43e0c3ad834dcd369f0d39005c872e118c9dc1c5da9765bb93ee5f3"
                )
                .unwrap()
            )
        );
    }

    #[tokio::test]
    async fn test_fetch_first_pkg_id_with_invalid_id() {
        let invalid_address = ObjectID::ZERO;
        let result = package_manager()
            .await
            .fetch_first_pkg_id(&invalid_address)
            .await;
        assert!(matches!(result, Err(InternalError::InvalidPackage)));
    }

    #[tokio::test]
    async fn test_simple_sigs() {
        let personal_msg = PersonalMessage {
            message: "hello".as_bytes().to_vec(),
        };
        let msg_with_intent = IntentMessage::new(Intent::personal_message(), personal_msg.clone());

        // simple sigs
        {
            let (addr, sk): (_, Ed25519KeyPair) = get_key_pair();
            let sig = GenericSignature::Signature(Signature::new_secure(&msg_with_intent, &sk));
            assert!(verify_personal_message_signature(
                sig.clone(),
                &personal_msg.message,
                addr,
                None
            )
            .await
            .is_ok());

            let (wrong_addr, _): (_, Ed25519KeyPair) = get_key_pair();
            assert!(verify_personal_message_signature(
                sig.clone(),
                &personal_msg.message,
                wrong_addr,
                None
            )
            .await
            .is_err());

            let wrong_msg = PersonalMessage {
                message: "wrong".as_bytes().to_vec(),
            };
            assert!(
                verify_personal_message_signature(sig.clone(), &wrong_msg.message, addr, None)
                    .await
                    .is_err()
            );
        }
        {
            let (addr, sk): (_, Secp256k1KeyPair) = get_key_pair();
            let sig = GenericSignature::Signature(Signature::new_secure(&msg_with_intent, &sk));
            assert!(verify_personal_message_signature(
                sig.clone(),
                &personal_msg.message,
                addr,
                None
            )
            .await
            .is_ok());
            let (wrong_addr, _): (_, Secp256k1KeyPair) = get_key_pair();
            assert!(verify_personal_message_signature(
                sig.clone(),
                &personal_msg.message,
                wrong_addr,
                None
            )
            .await
            .is_err());
            let wrong_msg = PersonalMessage {
                message: "wrong".as_bytes().to_vec(),
            };
            assert!(
                verify_personal_message_signature(sig.clone(), &wrong_msg.message, addr, None)
                    .await
                    .is_err()
            );
        }
        {
            let (addr, sk): (_, Secp256r1KeyPair) = get_key_pair();
            let sig = GenericSignature::Signature(Signature::new_secure(&msg_with_intent, &sk));
            assert!(verify_personal_message_signature(
                sig.clone(),
                &personal_msg.message,
                addr,
                None
            )
            .await
            .is_ok());

            let (wrong_addr, _): (_, Secp256r1KeyPair) = get_key_pair();
            assert!(verify_personal_message_signature(
                sig.clone(),
                &personal_msg.message,
                wrong_addr,
                None
            )
            .await
            .is_err());
            let wrong_msg = PersonalMessage {
                message: "wrong".as_bytes().to_vec(),
            };
            assert!(
                verify_personal_message_signature(sig.clone(), &wrong_msg.message, addr, None)
                    .await
                    .is_err()
            );
        }
    }
}
