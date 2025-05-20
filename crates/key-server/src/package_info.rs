use crate::errors::InternalError;
use crate::errors::InternalError::InvalidMVRName;
use crate::externals::{fetch_first_and_last_pkg_id, fetch_first_and_last_pkg_ids};
use crate::mvr::mvr_forward_resolution;
use crate::types::Network;
use sui_sdk::SuiClient;
use sui_types::base_types::ObjectID;

pub(crate) struct PackageInfo {
    pub(crate) first: ObjectID,
    pub(crate) latest: ObjectID,
    mvr_name: Option<String>,
}

impl PackageInfo {
    pub(crate) fn name(&self) -> String {
        match &self.mvr_name {
            Some(name) => name.clone(),
            None => self.first.to_hex_uncompressed(),
        }
    }
}

/// Get the first and last package IDs for a given package ID.
/// If an MVR name is provided, it will be checked that this points to the given package ID.
pub async fn fetch_package_info(
    pkg_id: ObjectID,
    sui_client: &SuiClient,
    network: &Network,
    mvr_name: Option<String>,
) -> Result<PackageInfo, InternalError> {
    match mvr_name {
        Some(mvr_name) => {
            let mvr_reference = mvr_forward_resolution(sui_client, &mvr_name).await?;
            let (first, latest, mvr_latest) =
                fetch_first_and_last_pkg_ids(&pkg_id, &mvr_reference, network).await?;

            // Check that the MVR name points to the given package
            if mvr_latest != latest {
                return Err(InvalidMVRName);
            }

            Ok(PackageInfo {
                first,
                latest,
                mvr_name: Some(mvr_name),
            })
        }
        None => {
            let (first, latest) = fetch_first_and_last_pkg_id(&pkg_id, network).await?;
            Ok(PackageInfo {
                first,
                latest,
                mvr_name: None,
            })
        }
    }
}
