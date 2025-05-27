// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::errors::InternalError;
use crate::errors::InternalError::InvalidMVRName;
use crate::externals::fetch_first_and_last_pkg_id;
use crate::metrics::{call_with_duration, Metrics};
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
    /// Get the name used to identify this package in the signed message.
    pub(crate) fn name(&self) -> String {
        match &self.mvr_name {
            Some(name) => name.clone(),
            None => self.first.to_hex_uncompressed(),
        }
    }
}

/// Get the first and last package IDs for a given package ID.
/// If an MVR name is provided, it will be checked that this points to the first version of the given package.
pub async fn fetch_package_info(
    pkg_id: ObjectID,
    sui_client: &SuiClient,
    network: &Network,
    mvr_name: Option<String>,
    metrics: Option<&Metrics>,
) -> Result<PackageInfo, InternalError> {
    let (first, latest) =
        call_with_duration(metrics.map(|m| &m.fetch_pkg_ids_duration), || async {
            fetch_first_and_last_pkg_id(&pkg_id, network).await
        })
        .await?;

    if let Some(mvr_name) = mvr_name.as_ref() {
        // Check that the MVR name points to the first version of the given package
        let mvr_reference = mvr_forward_resolution(sui_client, mvr_name, network).await?;
        if mvr_reference != first {
            return Err(InvalidMVRName);
        }
    }

    Ok(PackageInfo {
        first,
        latest,
        mvr_name,
    })
}
