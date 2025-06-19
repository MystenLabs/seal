// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module provides functionality to interact with the Move Registry (MVR) on behalf of Seal.
//!
//! MVR (Move Registry) is a registry for Move packages and their metadata.
//!
//! A few facts about MVR that are important regarding its usage in Seal:
//! * Only the owner of a Move package can register an MVR name for it using its `UpgradeCap`. It may point to a Move package on mainnet, testnet or neither.
//! * There is a registry on mainnet that is used to store all MVR records (see [MVR_REGISTRY]). Using the MVR name, we can look up an `app_record` here.
//! * If there is an `app_info` field in the `app_record`, there is a package address in this that points to the package address on mainnet.
//! * The `app_record` has a `networks` field which contains a mapping of network IDs to metadata. If there is an entry with name [TESTNET_ID], it contains the package info for the testnet. The package address information here is <i>not</i> guaranteed to be accurate, so for testnet we should instead look up the package info object on testnet and get the package address from there.
//! * A valid name is of the form `subname@name/mvr-app` or, equivalently, `subname.name.sui/mvr-app`. The subname is optional, but there is always an `/` in the name, meaning that it is not possible to register an object ID like `0xe8417c530cde59eddf6dfb760e8a0e3e2c6f17c69ddaab5a73dd6a6e65fc463b` as an MVR name.
//! * The app record and package info objects point to the package address that was used when the name was registered, but there could be more recent versions of the package.

use crate::errors::InternalError;
use crate::errors::InternalError::{Failure, InvalidMVRName, InvalidPackage};
use crate::key_server_options::KeyServerOptions;
use crate::mvr::mainnet::mvr_core::app_record::AppRecord;
use crate::mvr::mainnet::mvr_core::name::Name;
use crate::mvr::mainnet::sui::dynamic_field::Field;
use crate::mvr::mainnet::sui::vec_map::VecMap;
use crate::mvr::testnet::mvr_metadata::package_info::PackageInfo;
use crate::sui_rpc_client::SuiRpcClient;
use crate::types::Network;
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::StructTag;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::hash::Hash;
use std::str::FromStr;
use sui_sdk::rpc_types::SuiObjectDataOptions;
use sui_sdk::SuiClientBuilder;
use sui_types::base_types::ObjectID;
use sui_types::dynamic_field::DynamicFieldName;
use sui_types::TypeTag;

const MVR_REGISTRY: &str = "0xe8417c530cde59eddf6dfb760e8a0e3e2c6f17c69ddaab5a73dd6a6e65fc463b";
const MVR_CORE: &str = "0x62c1f5b1cb9e3bfc3dd1f73c95066487b662048a6358eabdbf67f6cdeca6db4b";

/// Testnet records are stored on mainnet on the registry defined above, but under the 'networks' section using the following ID as key
const TESTNET_ID: &str = "4c78adac";

/// Bindings for Move structs used in the MVR registry, specifically AppRecord and PackageInfo.
#[allow(clippy::too_many_arguments)]
pub mod mainnet {
    use move_binding_derive::move_contract;
    move_contract! {alias = "sui", package = "0x2"}
    move_contract! {alias = "suins", package = "0xd22b24490e0bae52676651b4f56660a5ff8022a2576e0089f79b3c88d44e08f0", deps = [crate::mvr::mainnet::sui]}
    move_contract! {alias = "mvr_core", package = "@mvr/core", deps = [crate::mvr::mainnet::sui, crate::mvr::mainnet::suins, crate::mvr::mainnet::mvr_metadata]}
    move_contract! {alias = "mvr_metadata", package = "@mvr/metadata", deps = [crate::mvr::mainnet::sui]}
}
pub mod testnet {
    use move_binding_derive::move_contract;
    move_contract! {alias = "mvr_metadata", package = "@mvr/metadata", network = "testnet", deps = [crate::mvr::mainnet::sui]}
}

impl<K: Eq + Hash, V> From<VecMap<K, V>> for HashMap<K, V> {
    fn from(value: VecMap<K, V>) -> Self {
        value
            .contents
            .into_iter()
            .map(|entry| (entry.key, entry.value))
            .collect::<HashMap<K, V>>()
    }
}

/// Given an MVR name, look up the package it points to.
pub(crate) async fn mvr_forward_resolution(
    sui_rpc_client: &SuiRpcClient,
    mvr_name: &str,
    key_server_options: &KeyServerOptions,
) -> Result<ObjectID, InternalError> {
    let package_address = match key_server_options.network {
        Network::Mainnet => get_from_mvr_registry(mvr_name, sui_rpc_client)
            .await?
            .value
            .app_info
            .ok_or(InvalidMVRName)?
            .package_address
            .ok_or(Failure)?,
        Network::Testnet => {
            let networks: HashMap<_, _> = get_from_mvr_registry(
                mvr_name,
                &SuiRpcClient::new(
                    SuiClientBuilder::default()
                        .request_timeout(key_server_options.rpc_config.timeout)
                        .build_mainnet()
                        .await
                        .map_err(|_| Failure)?,
                    key_server_options.rpc_config.retry_config.clone(),
                    sui_rpc_client.get_metrics(),
                ),
            )
            .await?
            .value
            .networks
            .into();

            // For testnet, we need to look up the package info ID
            let package_info_id = networks
                .get(TESTNET_ID)
                .ok_or(InvalidMVRName)?
                .package_info_id
                .ok_or(Failure)
                .map(|id| ObjectID::new(id.into_inner()))?;
            let package_info: PackageInfo = get_object(package_info_id, sui_rpc_client).await?;

            // Check that the name in the package info matches the MVR name.
            let metadata: HashMap<_, _> = package_info.metadata.into();
            let name_in_package_info = metadata.get("default").ok_or(Failure)?;
            if name_in_package_info != mvr_name {
                return Err(InvalidMVRName);
            }

            package_info.package_address
        }
        _ => return Err(Failure),
    };
    Ok(ObjectID::new(package_address.into_inner()))
}

/// Given an MVR name, look up the record in the MVR registry on mainnet.
async fn get_from_mvr_registry(
    mvr_name: &str,
    mainnet_sui_rpc_client: &SuiRpcClient,
) -> Result<Field<Name, AppRecord>, InternalError> {
    let dynamic_field_name = dynamic_field_name(mvr_name)?;
    let record_id = mainnet_sui_rpc_client
        .get_dynamic_field_object(
            ObjectID::from_str(MVR_REGISTRY).unwrap(),
            dynamic_field_name.clone(),
        )
        .await
        .map_err(|_| Failure)?
        .object_id()
        .map_err(|_| InvalidMVRName)?;

    // TODO: Is there a way to get the BCS data in the above call instead of making a second call?
    get_object(record_id, mainnet_sui_rpc_client).await
}

/// Construct a `DynamicFieldName` from an MVR name for use in the MVR registry.
fn dynamic_field_name(mvr_name: &str) -> Result<DynamicFieldName, InternalError> {
    let parsed_name =
        mvr_types::name::VersionedName::from_str(mvr_name).map_err(|_| InvalidMVRName)?;
    if parsed_name.version.is_some() {
        return Err(InvalidMVRName);
    }

    Ok(DynamicFieldName {
        type_: TypeTag::Struct(Box::new(StructTag {
            address: AccountAddress::from_str(MVR_CORE).unwrap(),
            module: Identifier::from_str("name").unwrap(),
            name: Identifier::from_str("Name").unwrap(),
            type_params: vec![],
        })),
        value: json!(parsed_name.name),
    })
}

async fn get_object<T: for<'a> Deserialize<'a>>(
    object_id: ObjectID,
    sui_rpc_client: &SuiRpcClient,
) -> Result<T, InternalError> {
    bcs::from_bytes(
        sui_rpc_client
            .get_object_with_options(object_id, SuiObjectDataOptions::new().with_bcs())
            .await
            .map_err(|_| Failure)?
            .move_object_bcs()
            .ok_or(Failure)?,
    )
    .map_err(|_| InvalidPackage)
}

#[cfg(test)]
mod tests {
    use crate::errors::InternalError::InvalidMVRName;
    use crate::key_server_options::{KeyServerOptions, RetryConfig};
    use crate::mvr::mvr_forward_resolution;
    use crate::sui_rpc_client::SuiRpcClient;
    use crate::types::Network;
    use mvr_types::name::VersionedName;
    use std::str::FromStr;
    use sui_sdk::SuiClientBuilder;
    use sui_types::base_types::ObjectID;

    #[tokio::test]
    async fn test_forward_resolution() {
        assert!(crate::externals::check_mvr_package_id(
            &Some("@mysten/kiosk".to_string()),
            &SuiRpcClient::new(
                SuiClientBuilder::default().build_mainnet().await.unwrap(),
                RetryConfig::default(),
                None,
            ),
            &KeyServerOptions::new_for_testing(Network::Mainnet),
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
            crate::externals::get_mvr_cache("@mysten/kiosk"),
            Some(
                ObjectID::from_str(
                    "0xdfb4f1d4e43e0c3ad834dcd369f0d39005c872e118c9dc1c5da9765bb93ee5f3"
                )
                .unwrap()
            )
        );
        assert_eq!(
            mvr_forward_resolution(
                &SuiRpcClient::new(
                    SuiClientBuilder::default().build_testnet().await.unwrap(),
                    RetryConfig::default(),
                    None,
                ),
                "@mysten/kiosk",
                &KeyServerOptions::new_for_testing(Network::Testnet),
            )
            .await
            .unwrap(),
            ObjectID::from_str(
                "0xe308bb3ed5367cd11a9c7f7e7aa95b2f3c9a8f10fa1d2b3cff38240f7898555d"
            )
            .unwrap()
        );

        // This MVR name is not registered on mainnet.
        assert_eq!(
            mvr_forward_resolution(
                &SuiRpcClient::new(
                    SuiClientBuilder::default().build_mainnet().await.unwrap(),
                    RetryConfig::default(),
                    None,
                ),
                "@pkg/seal-demo-1234",
                &KeyServerOptions::new_for_testing(Network::Mainnet),
            )
            .await
            .err()
            .unwrap(),
            InvalidMVRName
        );

        // ..but it is on testnet.
        assert_eq!(
            mvr_forward_resolution(
                &SuiRpcClient::new(
                    SuiClientBuilder::default().build_testnet().await.unwrap(),
                    RetryConfig::default(),
                    None,
                ),
                "@pkg/seal-demo-1234",
                &KeyServerOptions::new_for_testing(Network::Testnet),
            )
            .await
            .unwrap(),
            ObjectID::from_str(
                "0xc5ce2742cac46421b62028557f1d7aea8a4c50f651379a79afdf12cd88628807"
            )
            .unwrap()
        );
    }

    #[tokio::test]
    async fn test_invalid_name() {
        assert_eq!(
            mvr_forward_resolution(
                &SuiRpcClient::new(
                    SuiClientBuilder::default().build_mainnet().await.unwrap(),
                    RetryConfig::default(),
                    None,
                ),
                "@saemundur/seal",
                &KeyServerOptions::new_for_testing(Network::Mainnet),
            )
            .await
            .err()
            .unwrap(),
            InvalidMVRName
        );

        assert_eq!(
            mvr_forward_resolution(
                &SuiRpcClient::new(
                    SuiClientBuilder::default().build_mainnet().await.unwrap(),
                    RetryConfig::default(),
                    None,
                ),
                "invalid_name",
                &KeyServerOptions::new_for_testing(Network::Mainnet),
            )
            .await
            .err()
            .unwrap(),
            InvalidMVRName
        );
    }

    #[test]
    fn test_mvr_names() {
        assert!(VersionedName::from_str("@saemundur/seal").is_ok());
        assert!(VersionedName::from_str("saemundur/seal").is_err());
        assert!(VersionedName::from_str("saemundur").is_err());
        assert!(VersionedName::from_str(
            "0xe8417c530cde59eddf6dfb760e8a0e3e2c6f17c69ddaab5a73dd6a6e65fc463b"
        )
        .is_err())
    }
}
