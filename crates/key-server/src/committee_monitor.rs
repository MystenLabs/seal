// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::sui_rpc_client::SuiRpcClient;
use serde::Deserialize;
use sui_sdk::error::SuiRpcResult;
use sui_sdk::rpc_types::SuiObjectDataOptions;
use sui_types::base_types::{ObjectID, SuiAddress};
use tracing::{error, info};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CommitteeState {
    Init,
    PreDKG,
    PostDKG,
    Finalized,
}

/// Check if a committee object exists onchain.
/// Returns Ok(true) if the object exists, Ok(false) if it doesn't exist (deleted),
/// or Err if there was an error fetching the object.
pub(crate) async fn check_committee_exists(
    sui_rpc_client: &SuiRpcClient,
    committee_id: ObjectID,
) -> SuiRpcResult<bool> {
    let result = sui_rpc_client
        .get_object_with_options(committee_id, SuiObjectDataOptions::default())
        .await?;

    // If the object data is None or the object has been deleted/wrapped, return false
    match result.data {
        Some(data) => Ok(data.object_id == committee_id),
        None => Ok(false),
    }
}

/// Check if the next committee has reached the Finalized state.
/// Returns Ok(true) if finalized, Ok(false) if not finalized, or Err if there was an error.
pub(crate) async fn check_committee_finalized(
    sui_rpc_client: &SuiRpcClient,
    next_committee_id: ObjectID,
) -> SuiRpcResult<bool> {
    let result = sui_rpc_client
        .get_object_with_options(
            next_committee_id,
            SuiObjectDataOptions::default().with_content(),
        )
        .await?;

    if let Some(data) = result.data {
        if let Some(content) = data.content {
            if let sui_sdk::rpc_types::SuiParsedData::MoveObject(move_object) = content {
                // Convert the fields to JSON and check for the state field
                if let Ok(fields_json) = serde_json::to_value(&move_object.fields) {
                    if let Some(state_field) =
                        fields_json.get("fields").and_then(|f| f.get("state"))
                    {
                        // Check if state is directly "Finalized" string
                        if let Some(state_str) = state_field.as_str() {
                            return Ok(state_str == "Finalized");
                        }

                        // Check if state is an object with "variant" or "fields" containing "Finalized"
                        if let Some(state_obj) = state_field.as_object() {
                            // Check for variant field
                            if let Some(variant) =
                                state_obj.get("variant").or_else(|| state_obj.get("type"))
                            {
                                if let Some(variant_str) = variant.as_str() {
                                    return Ok(variant_str.contains("Finalized"));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(false)
}

/// Fetch the PartialKeyServer object from the KeyServerV2 dynamic field.
/// This should be called when a committee reaches the Finalized state.
/// Returns the ObjectID of the PartialKeyServer for the given member address.
pub(crate) async fn fetch_partial_key_server(
    sui_rpc_client: &SuiRpcClient,
    key_server_object_id: ObjectID,
    member_address: SuiAddress,
) -> SuiRpcResult<Option<ObjectID>> {
    // Get the key server object with dynamic fields using the read_api
    let result = sui_rpc_client
        .sui_client()
        .read_api()
        .get_dynamic_fields(key_server_object_id, None, None)
        .await?;

    // Look for the KeyServerV2 dynamic field
    for df in result.data {
        let name = &df.name;
        // Check if this is the KeyServerV2 field
        if let Ok(name_json) = serde_json::to_value(&name) {
            if let Some(type_str) = name_json.get("type").and_then(|t| t.as_str()) {
                if type_str.contains("KeyServerV2") {
                    // Found KeyServerV2, now look for the PartialKeyServer with matching member address
                    let object_id = df.object_id;
                    // Get the KeyServerV2 object's dynamic fields
                    let v2_result = sui_rpc_client
                        .sui_client()
                        .read_api()
                        .get_dynamic_fields(object_id, None, None)
                        .await?;

                    // Look for the PartialKeyServer with matching member address
                    for partial_df in v2_result.data {
                        let partial_name = &partial_df.name;
                        if let Ok(partial_name_json) = serde_json::to_value(&partial_name) {
                            // Check if the value matches the member address
                            if let Some(value) = partial_name_json.get("value") {
                                if let Some(addr_str) = value.as_str() {
                                    if addr_str == member_address.to_string() {
                                        info!(
                                            "Found PartialKeyServer for member {}: {:?}",
                                            member_address, partial_df.object_id
                                        );
                                        return Ok(Some(partial_df.object_id));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    info!("No PartialKeyServer found for member {}", member_address);
    Ok(None)
}

/// Monitor the committee transition:
/// - Check if the next_committee has reached Finalized state
/// - If Finalized, check if the old committee object has been deleted
/// - If old committee is deleted, crash the server
/// Returns Ok(true) if monitoring should continue, Ok(false) if monitoring should stop (next committee is finalized)
pub(crate) async fn monitor_committee_transition(
    sui_rpc_client: SuiRpcClient,
    old_committee_id: ObjectID,
    next_committee_id: ObjectID,
) -> SuiRpcResult<bool> {
    // First check if next committee is finalized
    match check_committee_finalized(&sui_rpc_client, next_committee_id).await {
        Ok(true) => {
            info!(
                "Next committee {} has reached Finalized state. Checking if old committee {} is deleted.",
                next_committee_id, old_committee_id
            );

            // Check if old committee has been deleted
            match check_committee_exists(&sui_rpc_client, old_committee_id).await {
                Ok(true) => {
                    info!(
                        "Old committee object {} still exists after next committee finalized",
                        old_committee_id
                    );
                    Ok(true)
                }
                Ok(false) => {
                    error!(
                        "Old committee object {} has been deleted after next committee {} finalized. Server will now exit.",
                        old_committee_id, next_committee_id
                    );
                    std::process::exit(1);
                }
                Err(e) => {
                    error!(
                        "Failed to check old committee object {} existence: {:?}",
                        old_committee_id, e
                    );
                    Err(e)
                }
            }
        }
        Ok(false) => {
            info!(
                "Next committee {} is not yet finalized. Continuing to monitor.",
                next_committee_id
            );
            Ok(true)
        }
        Err(e) => {
            error!(
                "Failed to check next committee {} state: {:?}",
                next_committee_id, e
            );
            Err(e)
        }
    }
}
