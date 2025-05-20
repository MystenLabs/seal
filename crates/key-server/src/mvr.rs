// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::errors::InternalError;
use crate::errors::InternalError::{Failure, InvalidMVRName};
use crate::types::Network;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::StructTag;
use serde_json::json;
use std::str::FromStr;
use sui_sdk::rpc_types::SuiParsedData;
use sui_sdk::SuiClient;
use sui_types::base_types::{ObjectID, SuiAddress};
use sui_types::dynamic_field::DynamicFieldName;
use sui_types::TypeTag;

const MVR_REGISTRY: &str = "0xe8417c530cde59eddf6dfb760e8a0e3e2c6f17c69ddaab5a73dd6a6e65fc463b";
const MVR_CORE: &str = "0x62c1f5b1cb9e3bfc3dd1f73c95066487b662048a6358eabdbf67f6cdeca6db4b";

/// Given an MVR name, look up the package it points to.
pub(crate) async fn mvr_forward_resolution(
    client: &SuiClient,
    _network: &Network,
    mvr_name: &str,
) -> Result<ObjectID, InternalError> {
    let registry = SuiAddress::from_str(MVR_REGISTRY).unwrap();
    let mvr_core = SuiAddress::from_str(MVR_CORE).unwrap();

    let parsed_name =
        mvr_types::name::VersionedName::from_str(mvr_name).map_err(|_| InvalidMVRName)?;
    if parsed_name.version.is_some() {
        return Err(InvalidMVRName);
    }

    let dynamic_field_name = DynamicFieldName {
        type_: TypeTag::Struct(Box::new(StructTag {
            address: mvr_core.into(),
            module: Identifier::from_str("name").unwrap(),
            name: Identifier::from_str("Name").unwrap(),
            type_params: vec![],
        })),
        value: json!(parsed_name.name),
    };

    let dynamic_field = client
        .read_api()
        .get_dynamic_field_object(registry.into(), dynamic_field_name)
        .await
        .map_err(|_| InvalidMVRName)?
        .data
        .ok_or(Failure)?
        .content
        .ok_or(Failure)?;

    let package_address_as_str = match dynamic_field {
        SuiParsedData::MoveObject(obj) => obj.fields.to_json_value()["value"]["app_info"]
            ["package_address"]
            .as_str()
            .ok_or(Failure)?
            .to_string(),
        _ => return Err(Failure),
    };
    let package_address = ObjectID::from_str(&package_address_as_str).unwrap();

    Ok(package_address)
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
        let sui_client = SuiClientBuilder::default().build_mainnet().await.unwrap();
        let package_id = mvr_forward_resolution(&sui_client, &Network::Mainnet, "@mysten/kiosk")
            .await
            .unwrap();
        assert_eq!(
            package_id,
            ObjectID::from_str(
                "0xdfb4f1d4e43e0c3ad834dcd369f0d39005c872e118c9dc1c5da9765bb93ee5f3"
            )
            .unwrap()
        )
    }
}
