// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::errors::InternalError;
use crate::errors::InternalError::{Failure, InvalidMVRName, InvalidPackage};
use crate::mvr::mainnet::mvr_core::app_record::AppRecord;
use crate::mvr::mainnet::mvr_core::name::Name;
use crate::mvr::mainnet::sui::dynamic_field::Field;
use crate::mvr::mainnet::sui::vec_map::VecMap;
use crate::mvr::testnet::mvr_metadata::package_info::PackageInfo;
use crate::types::Network;
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::StructTag;
use serde_json::json;
use std::collections::HashMap;
use std::hash::Hash;
use std::str::FromStr;
use sui_sdk::rpc_types::SuiObjectDataOptions;
use sui_sdk::{SuiClient, SuiClientBuilder};
use sui_types::base_types::ObjectID;
use sui_types::dynamic_field::DynamicFieldName;
use sui_types::TypeTag;

const MVR_REGISTRY: &str = "0xe8417c530cde59eddf6dfb760e8a0e3e2c6f17c69ddaab5a73dd6a6e65fc463b";
const MVR_CORE: &str = "0x62c1f5b1cb9e3bfc3dd1f73c95066487b662048a6358eabdbf67f6cdeca6db4b";
const TESTNET_ID: &str = "4c78adac";

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
    client: &SuiClient,
    mvr_name: &str,
    network: &Network,
) -> Result<ObjectID, InternalError> {
    let package_address = match network {
        Network::Mainnet => get_from_mvr_registry(mvr_name, client)
            .await?
            .value
            .app_info
            .ok_or(InvalidMVRName)?
            .package_address
            .ok_or(Failure)?,
        Network::Testnet => {
            let networks: HashMap<_, _> = get_from_mvr_registry(
                mvr_name,
                &SuiClientBuilder::default()
                    .build_mainnet()
                    .await
                    .map_err(|_| Failure)?,
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
            let package_info: PackageInfo = bcs::from_bytes(
                client
                    .read_api()
                    .get_object_with_options(package_info_id, SuiObjectDataOptions::bcs_lossless())
                    .await
                    .map_err(|_| Failure)?
                    .move_object_bcs()
                    .ok_or(Failure)?,
            )
            .map_err(|_| InvalidPackage)?;
            package_info.package_address
        }
        _ => return Err(Failure),
    };
    Ok(ObjectID::new(package_address.into_inner()))
}

/// Given an MVR name, look up the record in the MVR registry.
async fn get_from_mvr_registry(
    mvr_name: &str,
    mainnet_client: &SuiClient,
) -> Result<Field<Name, AppRecord>, InternalError> {
    let record_id = mainnet_client
        .read_api()
        .get_dynamic_field_object(
            ObjectID::from_str(MVR_REGISTRY).unwrap(),
            dynamic_field_name(mvr_name)?,
        )
        .await
        .map_err(|_| Failure)?
        .object_id()
        .map_err(|_| InvalidMVRName)?;

    // TODO: Is there a way to get the BCS data in the above call instead of making a second call?
    bcs::from_bytes(
        mainnet_client
            .read_api()
            .get_object_with_options(record_id, SuiObjectDataOptions::bcs_lossless())
            .await
            .map_err(|_| Failure)?
            .move_object_bcs()
            .ok_or(Failure)?,
    )
    .map_err(|_| InvalidPackage)
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

#[cfg(test)]
mod tests {
    use crate::errors::InternalError::InvalidMVRName;
    use crate::mvr::mvr_forward_resolution;
    use crate::types::Network;
    use mvr_types::name::VersionedName;
    use std::str::FromStr;
    use sui_sdk::SuiClientBuilder;
    use sui_types::base_types::ObjectID;

    #[tokio::test]
    async fn test_forward_resolution() {
        assert_eq!(
            mvr_forward_resolution(
                &SuiClientBuilder::default().build_mainnet().await.unwrap(),
                "@mysten/kiosk",
                &Network::Mainnet
            )
            .await
            .unwrap(),
            ObjectID::from_str(
                "0xdfb4f1d4e43e0c3ad834dcd369f0d39005c872e118c9dc1c5da9765bb93ee5f3"
            )
            .unwrap()
        );
        assert_eq!(
            mvr_forward_resolution(
                &SuiClientBuilder::default().build_testnet().await.unwrap(),
                "@mysten/kiosk",
                &Network::Testnet
            )
            .await
            .unwrap(),
            ObjectID::from_str(
                "0xe308bb3ed5367cd11a9c7f7e7aa95b2f3c9a8f10fa1d2b3cff38240f7898555d"
            )
            .unwrap()
        );

        assert!(mvr_forward_resolution(
            &SuiClientBuilder::default().build_mainnet().await.unwrap(),
            "vesca@scallop/core",
            &Network::Mainnet
        )
        .await
        .is_ok());

        // This MVR name is not registered on testnet.
        // If it ever registered, please update the test.
        assert_eq!(
            mvr_forward_resolution(
                &SuiClientBuilder::default().build_testnet().await.unwrap(),
                "vesca@scallop/core",
                &Network::Testnet
            )
            .await
            .err()
            .unwrap(),
            InvalidMVRName
        );
    }

    #[tokio::test]
    async fn test_invalid_name() {
        assert_eq!(
            mvr_forward_resolution(
                &SuiClientBuilder::default().build_mainnet().await.unwrap(),
                "@saemundur/seal",
                &Network::Mainnet
            )
            .await
            .err()
            .unwrap(),
            InvalidMVRName
        );

        assert_eq!(
            mvr_forward_resolution(
                &SuiClientBuilder::default().build_mainnet().await.unwrap(),
                "invalid_name",
                &Network::Mainnet
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
