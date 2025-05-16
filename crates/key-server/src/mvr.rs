// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::errors::InternalError;
use crate::errors::InternalError::InvalidMVRObject;
use crate::types::Network;
use mvr_indexer::models::mainnet::mvr_metadata::package_info::PackageInfo as MainnetPkgInfo;
use mvr_indexer::models::mainnet::sui::vec_map::VecMap;
use mvr_indexer::models::testnet::mvr_metadata::package_info::PackageInfo as TestnetPkgInfo;
use serde::Deserialize;
use sui_sdk::SuiClient;
use sui_types::base_types::{ObjectID, SUI_ADDRESS_LENGTH};
use tracing::warn;

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
    use crate::mvr::resolve_mvr_object;
    use crate::types::Network;
    use std::str::FromStr;
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
}
