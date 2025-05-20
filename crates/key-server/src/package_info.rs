use crate::errors::InternalError;
use crate::errors::InternalError::InvalidMVRName;
use crate::types::Network;
use crate::{externals, mvr};
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

pub async fn fetch_package_info(
    pkg_id: ObjectID,
    sui_client: &SuiClient,
    network: &Network,
    mvr_name: Option<&String>,
) -> Result<PackageInfo, InternalError> {
    match mvr_name {
        Some(mvr_name) => {
            let mvr_reference = mvr::mvr_forward_resolution(sui_client, network, mvr_name).await?;
            let (first, latest, mvr_latest) =
                externals::fetch_last_pkg_ids(&pkg_id, network, &mvr_reference).await?;
            if latest != mvr_latest {
                return Err(InvalidMVRName);
            }
            Ok(PackageInfo {
                first,
                latest,
                mvr_name: Some(mvr_name.clone()),
            })
        }
        None => {
            let (first, latest) = externals::fetch_first_and_last_pkg_id(&pkg_id, network).await?;
            Ok(PackageInfo {
                first,
                latest,
                mvr_name: None,
            })
        }
    }
}
