// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::cache::{Cache, CACHE_SIZE, CACHE_TTL};
use crate::errors::InternalError;
use crate::errors::InternalError::InvalidMVRObject;
use crate::types::Network;
use crate::Timestamp;
use mvr_indexer::models::{mainnet, testnet};
use mvr_indexer::models::mainnet::mvr_metadata::package_info::PackageInfo as MainnetPkgInfo;
use mvr_indexer::models::mainnet::sui::vec_map::VecMap;
use mvr_indexer::models::testnet::mvr_metadata::package_info::PackageInfo as TestnetPkgInfo;
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use std::str::FromStr;
use sui_sdk::error::SuiRpcResult;
use sui_sdk::rpc_types::CheckpointId;
use sui_sdk::SuiClient;
use sui_types::base_types::{ObjectID, SUI_ADDRESS_LENGTH};
use tap::TapFallible;
use tracing::{debug, warn};

static CACHE: Lazy<Cache<ObjectID, (ObjectID, ObjectID)>> =
    Lazy::new(|| Cache::new(CACHE_TTL, CACHE_SIZE));

#[cfg(test)]
pub(crate) fn add_latest(pkg_id: ObjectID, latest: ObjectID) {
    match CACHE.get(&pkg_id) {
        Some((first, old_latest)) => {
            CACHE.insert(pkg_id, (first, latest));
            CACHE.insert(latest, (first, latest));
            CACHE.insert(old_latest, (first, latest));
        }
        None => panic!("Package is not in cache"),
    }
}

#[cfg(test)]
pub(crate) fn add_package(pkg_id: ObjectID) {
    CACHE.insert(pkg_id, (pkg_id, pkg_id));
}

pub(crate) async fn fetch_first_and_last_pkg_id(
    pkg_id: &ObjectID,
    network: &Network,
) -> Result<(ObjectID, ObjectID), InternalError> {
    match CACHE.get(pkg_id) {
        Some((first, latest)) => Ok((first, latest)),
        None => {
            let graphql_client = Client::new();
            let url = network.graphql_url();
            let query = serde_json::json!({
                "query": format!(
                    r#"
                    query {{
                        latestPackage(
                            address: "{}"
                        ) {{
                            address
                            packageAtVersion(version: 1) {{
                                address
                            }}
                        }}
                    }}
                    "#,
                    pkg_id
                )
            });
            let response = graphql_client.post(url).json(&query).send().await;
            debug!("Graphql response: {:?}", response);
            let response = response
                .map_err(|_| InternalError::Failure)?
                .json::<Value>()
                .await
                .map_err(|_| InternalError::Failure)?;

            let first = response["data"]["latestPackage"]["packageAtVersion"]["address"]
                .as_str()
                .ok_or(InternalError::InvalidPackage)?
                .to_string();
            let latest = response["data"]["latestPackage"]["address"]
                .as_str()
                .ok_or(InternalError::InvalidPackage)?
                .to_string();
            let (first, latest) = (
                ObjectID::from_str(&first).map_err(|_| InternalError::Failure)?,
                ObjectID::from_str(&latest).map_err(|_| InternalError::Failure)?,
            );
            CACHE.insert(*pkg_id, (first, latest));
            Ok((first, latest))
        }
    }
}

/// Returns the timestamp for the latest checkpoint.
pub(crate) async fn get_latest_checkpoint_timestamp(client: SuiClient) -> SuiRpcResult<Timestamp> {
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

pub(crate) async fn get_reference_gas_price(client: SuiClient) -> SuiRpcResult<u64> {
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

pub(crate) fn current_epoch_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("fixed start time")
        .as_millis() as u64
}

/// Given the ID of an MVR PackageInfo object, this function fetches and parses the object and
/// returns the MVR name and the id of the package.
pub(crate) async fn resolve_mvr_object(
    client: &SuiClient,
    network: &Network,
    package_info_object_id: ObjectID,
) -> Result<(String, ObjectID), InternalError> {
    let bcs = client
        .read_api()
        .get_move_object_bcs(package_info_object_id)
        .await
        .map_err(|_| InvalidMVRObject)?;

    match network {
        Network::Testnet => parse_testnet_package_info(&bcs),
        Network::Mainnet => parse_mainnet_package_info(&bcs),
        _ => {
            warn!("Network not supported for MVR object resolution");
            Err(InternalError::Failure)
        }
    }
}

fn parse_testnet_package_info(bytes: &[u8]) -> Result<(String, ObjectID), InternalError> {
    parse_package_info::<TestnetPkgInfo>(bytes, |info| {
        (info.metadata, info.package_address.into_inner())
    })
}

fn parse_mainnet_package_info(bytes: &[u8]) -> Result<(String, ObjectID), InternalError> {
    parse_package_info::<MainnetPkgInfo>(bytes, |info| {
        (info.metadata, info.package_address.into_inner())
    })
}

/// Given the BCS bytes of a PackageInfo struct (either from testnet of mainnet), get the metadata 
/// and the id.
fn parse_package_info<PkgInfo: for<'a> Deserialize<'a>>(
    bytes: &[u8],
    get_metadata_and_package_id: impl FnOnce(
        PkgInfo,
    ) -> (VecMap<String, String>, [u8; SUI_ADDRESS_LENGTH]),
) -> Result<(String, ObjectID), InternalError> {
    let package_info: PkgInfo = bcs::from_bytes(bytes).map_err(|_| InvalidMVRObject)?;
    let (metadata, package_id_bytes) = get_metadata_and_package_id(package_info);

    // Parse the MVR name from the metadata. See https://docs.suins.io/move-registry/managing-package-info.
    let name = metadata
        .contents
        .into_iter()
        .find(|entry| entry.key == "default")
        .ok_or(InvalidMVRObject)?
        .value;

    Ok((name, ObjectID::new(package_id_bytes)))
}

#[cfg(test)]
mod tests {
    use crate::externals::{fetch_first_and_last_pkg_id, resolve_mvr_object};
    use crate::types::Network;
    use crate::InternalError;
    use fastcrypto::ed25519::Ed25519KeyPair;
    use fastcrypto::secp256k1::Secp256k1KeyPair;
    use fastcrypto::secp256r1::Secp256r1KeyPair;
    use shared_crypto::intent::{Intent, IntentMessage, PersonalMessage};
    use std::str::FromStr;
    use sui_sdk::types::crypto::{get_key_pair, Signature};
    use sui_sdk::types::signature::GenericSignature;
    use sui_sdk::verify_personal_message_signature::verify_personal_message_signature;
    use sui_sdk::SuiClientBuilder;
    use sui_types::base_types::ObjectID;

    #[tokio::test]
    async fn test_fetch_mvr_package() {
        let sui_client = SuiClientBuilder::default().build_mainnet().await.unwrap();
        let (name, package_id) = resolve_mvr_object(
            &sui_client,
            &Network::Mainnet,
            ObjectID::from_str(
                "0xa364dd21f5eb43fdd4e502be52f450c09529dfc94dea12412a6d587f17ec7f24",
            )
            .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(name, "@mysten/kiosk".to_string());
        assert_eq!(
            package_id,
            ObjectID::from_str(
                "0xdfb4f1d4e43e0c3ad834dcd369f0d39005c872e118c9dc1c5da9765bb93ee5f3"
            )
            .unwrap()
        );
    }

    #[tokio::test]
    async fn test_fetch_first_and_last_pkg_id() {
        let address = ObjectID::from_str(
            "0xd92bc457b42d48924087ea3f22d35fd2fe9afdf5bdfe38cc51c0f14f3282f6d5",
        )
        .unwrap();

        match fetch_first_and_last_pkg_id(&address, &Network::Mainnet).await {
            Ok((first, latest)) => {
                assert!(!first.is_empty(), "First address should not be empty");
                assert!(!latest.is_empty(), "Latest address should not be empty");
                println!("First address: {:?}", first);
                println!("Latest address: {:?}", latest);
            }
            Err(e) => panic!("Test failed with error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_fetch_first_and_last_pkg_id_with_invalid_id() {
        let invalid_address = ObjectID::ZERO;
        let result = fetch_first_and_last_pkg_id(&invalid_address, &Network::Mainnet).await;
        assert!(matches!(result, Err(InternalError::InvalidPackage)));
    }

    #[tokio::test]
    async fn test_fetch_first_and_last_pkg_id_with_invalid_graphql_url() {
        let address = ObjectID::from_str(
            "0xd92bc457b42d48924087ea3f22d35fd2fe9afdf5bdfe38cc51c0f14f3282f6d5",
        )
        .unwrap();

        // Use a custom network with an invalid URL to emulate fetch failure
        let invalid_network = Network::Custom {
            graphql_url: "http://invalid-url".to_string(),
            node_url: "http://invalid-url".to_string(),
        };

        let result = fetch_first_and_last_pkg_id(&address, &invalid_network).await;
        assert!(matches!(result, Err(InternalError::Failure)));
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
