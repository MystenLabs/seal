// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::errors::InternalError;
use crate::errors::InternalError::{Failure, InvalidMVRName};
use crate::types::Network;
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::StructTag;
use serde_json::json;
use std::str::FromStr;
use sui_sdk::rpc_types::SuiParsedData;
use sui_sdk::SuiClient;
use sui_types::base_types::ObjectID;
use sui_types::dynamic_field::DynamicFieldName;
use sui_types::TypeTag;

const MVR_REGISTRY: &str = "0xe8417c530cde59eddf6dfb760e8a0e3e2c6f17c69ddaab5a73dd6a6e65fc463b";
const MVR_CORE: &str = "0x62c1f5b1cb9e3bfc3dd1f73c95066487b662048a6358eabdbf67f6cdeca6db4b";
const TESTNET_ID: &str = "4c78adac";

/// Given an MVR name, look up the package it points to.
pub(crate) async fn mvr_forward_resolution(
    client: &SuiClient,
    mvr_name: &str,
    network: &Network,
) -> Result<ObjectID, InternalError> {
    let dynamic_field = client
        .read_api()
        .get_dynamic_field_object(
            ObjectID::from_str(MVR_REGISTRY).unwrap(),
            dynamic_field_name(mvr_name)?,
        )
        .await
        .map_err(|_| InvalidMVRName)?
        .data
        .ok_or(Failure)?
        .content
        .ok_or(Failure)?;

    let package_address = match network {
        Network::Mainnet => match dynamic_field {
            SuiParsedData::MoveObject(obj) => obj.fields.to_json_value()["value"]["app_info"]
                ["package_address"]
                .as_str()
                .ok_or(Failure)?
                .to_string(),
            _ => return Err(Failure),
        },
        Network::Testnet => match dynamic_field {
            SuiParsedData::MoveObject(obj) => obj.fields.clone().to_json_value()["value"]
                ["networks"]["contents"]
                .as_array()
                .unwrap()
                .iter()
                .find(|x| x["key"].as_str().unwrap() == TESTNET_ID)
                .ok_or(Failure)?["value"]
                .as_object()
                .ok_or(Failure)?["package_address"]
                .as_str()
                .ok_or(Failure)?
                .to_string(),
            _ => return Err(Failure),
        },
        _ => panic!("Unsupported network for MVR resolution"),
    };
    ObjectID::from_str(&package_address).map_err(|_| Failure)
}

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
    use crate::mvr::mvr_forward_resolution;
    use crate::types::Network;
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
                &SuiClientBuilder::default().build_mainnet().await.unwrap(),
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
    }
}
