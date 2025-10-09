// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::sui_rpc_client::{RpcResult, SuiRpcClient};
use serde::Deserialize;
use sui_types::base_types::{ObjectID, SuiAddress};
use tracing::{error, info};

// BCS-deserializable Committee state enum matching the Move definition
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub enum State {
    Init {
        candidate_data: serde_json::Value, // VecMap<address, CandidateData>
    },
    PostDKG {
        candidate_data: serde_json::Value, // VecMap<address, CandidateData>
        partial_pks: Vec<Vec<u8>>,
        pk: Vec<u8>,
        approvals: serde_json::Value, // VecSet<address>
    },
    Finalized {
        pk: Vec<u8>,
    },
}

// BCS-deserializable Committee struct matching the Move definition
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Committee {
    id: sui_types::base_types::ObjectID,
    threshold: u16,
    members: Vec<SuiAddress>,
    state: State,
    old_committee_id: Option<sui_types::base_types::ObjectID>,
}

/// Check if a committee object exists onchain.
/// Returns Ok(true) if the object exists, Ok(false) if it doesn't exist (deleted),
/// or Err if there was an error fetching the object.
pub(crate) async fn check_committee_exists(
    sui_rpc_client: &SuiRpcClient,
    committee_id: ObjectID,
) -> RpcResult<bool> {
    let result = sui_rpc_client
        .get_object_with_options(committee_id, false)
        .await?;

    // Check if the object exists by verifying the object_id matches
    match result.object_id() {
        Ok(oid) => Ok(oid == committee_id),
        Err(_) => Ok(false),
    }
}

/// Check if the next committee has reached the Finalized state.
/// Returns Ok(true) if finalized, Ok(false) if not finalized, or Err if there was an error.
pub(crate) async fn check_committee_finalized(
    sui_rpc_client: &SuiRpcClient,
    next_committee_id: ObjectID,
) -> RpcResult<bool> {
    // Get the committee object with BCS data
    let result = sui_rpc_client
        .get_object_with_options(next_committee_id, true)
        .await?;

    // Get the BCS bytes from the object
    let bcs_bytes = result.move_object_bcs()?;

    // Parse the BCS bytes to get the Committee struct
    match bcs::from_bytes::<Committee>(&bcs_bytes) {
        Ok(committee) => {
            // Check if the state is Finalized
            let is_finalized = matches!(committee.state, State::Finalized { .. });

            if is_finalized {
                info!("Committee {} is in Finalized state", next_committee_id);
            } else {
                info!(
                    "Committee {} is in state: {:?}",
                    next_committee_id,
                    match committee.state {
                        State::Init { .. } => "Init",
                        State::PostDKG { .. } => "PostDKG",
                        State::Finalized { .. } => "Finalized",
                    }
                );
            }

            Ok(is_finalized)
        }
        Err(e) => {
            error!(
                "Failed to deserialize Committee BCS for {}: {:?}",
                next_committee_id, e
            );
            Err(crate::sui_rpc_client::RpcError::new(format!(
                "Failed to deserialize committee: {}",
                e
            )))
        }
    }
}

/// Fetch the PartialKeyServer object from the KeyServerV2 dynamic field.
/// This should be called when a committee reaches the Finalized state.
/// Returns the ObjectID of the PartialKeyServer for the given member address.
pub(crate) async fn fetch_partial_key_server(
    sui_rpc_client: &SuiRpcClient,
    key_server_object_id: ObjectID,
    member_address: SuiAddress,
) -> RpcResult<Option<ObjectID>> {
    // Get the dynamic fields of the key server object
    let fields = sui_rpc_client
        .list_dynamic_fields(key_server_object_id)
        .await?;

    // Look for the KeyServerV2 dynamic field
    for df in fields {
        // Check if this is the KeyServerV2 field by checking the name_type
        if let Some(ref name_type) = df.name_type {
            if name_type.contains("KeyServerV2") {
                // Found KeyServerV2, get its field_id to fetch nested dynamic fields
                if let Some(field_id_str) = df.field_id {
                    if let Ok(v2_object_id) = ObjectID::from_hex_literal(&field_id_str) {
                        // Get the KeyServerV2 object's dynamic fields
                        let v2_fields = sui_rpc_client.list_dynamic_fields(v2_object_id).await?;

                        // Look for the PartialKeyServer with matching member address
                        for partial_df in v2_fields {
                            // The name_value contains the BCS-encoded address
                            if let Some(ref name_value) = partial_df.name_value {
                                // BCS encoding of SuiAddress is just the 32 bytes
                                if name_value.len() == 32 {
                                    if let Ok(addr) = SuiAddress::from_bytes(&name_value[..]) {
                                        if addr == member_address {
                                            if let Some(field_id_str) = partial_df.field_id {
                                                if let Ok(partial_key_server_id) =
                                                    ObjectID::from_hex_literal(&field_id_str)
                                                {
                                                    info!(
                                                        "Found PartialKeyServer for member {}: {}",
                                                        member_address, partial_key_server_id
                                                    );
                                                    return Ok(Some(partial_key_server_id));
                                                }
                                            }
                                        }
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

/// Validate committee at startup when no next_committee_id is provided:
/// Valid case: committee_id exists and is finalized, MASTER_KEY present, no NEXT_MASTER_KEY
/// Returns Ok(partial_key_server_id) if validation passes, or Err if validation fails
pub(crate) async fn validate_committee_at_startup(
    sui_rpc_client: &SuiRpcClient,
    committee_id: ObjectID,
    key_server_object_id: ObjectID,
    member_address: SuiAddress,
) -> RpcResult<ObjectID> {
    info!(
        "Validating committee {} for member {} with key server object {}",
        committee_id, member_address, key_server_object_id
    );

    // Check NEXT_MASTER_KEY should not be present when there's no next_committee_id
    if std::env::var("NEXT_MASTER_KEY").is_ok() {
        error!("NEXT_MASTER_KEY is set but next_committee_id is not configured");
        return Err(crate::sui_rpc_client::RpcError::new(
            "NEXT_MASTER_KEY is set but next_committee_id is not configured",
        ));
    }

    // Check if the committee exists
    if !check_committee_exists(sui_rpc_client, committee_id).await? {
        error!("Committee {} does not exist", committee_id);
        return Err(crate::sui_rpc_client::RpcError::new(format!(
            "Committee {} does not exist",
            committee_id
        )));
    }

    // Check if the committee is finalized
    if !check_committee_finalized(sui_rpc_client, committee_id).await? {
        error!("Committee {} is not finalized", committee_id);
        return Err(crate::sui_rpc_client::RpcError::new(format!(
            "Committee {} is not finalized",
            committee_id
        )));
    }

    info!("Committee {} is finalized and valid", committee_id);

    // Fetch the partial key server for this member
    match fetch_partial_key_server(sui_rpc_client, key_server_object_id, member_address).await? {
        Some(partial_key_server_id) => {
            info!(
                "Successfully validated committee {} and found PartialKeyServer {} for member {}",
                committee_id, partial_key_server_id, member_address
            );
            Ok(partial_key_server_id)
        }
        None => {
            error!(
                "No PartialKeyServer found for member {} in KeyServer {}",
                member_address, key_server_object_id
            );
            Err(crate::sui_rpc_client::RpcError::new(format!(
                "No PartialKeyServer found for member {} in KeyServer {}",
                member_address, key_server_object_id
            )))
        }
    }
}

/// Validate committee at startup when next_committee_id is provided.
///
/// Two valid cases:
/// 1. next_committee not finalized: committee_id exists and finalized, use MASTER_KEY, monitor for transition
/// 2. next_committee finalized AND committee_id deleted: use NEXT_MASTER_KEY (rotation complete)
///
/// Returns Ok(Some(partial_key_server_id)) if using NEXT_MASTER_KEY, Ok(None) if monitoring needed
pub(crate) async fn validate_committee_with_next_at_startup(
    sui_rpc_client: &SuiRpcClient,
    committee_id: ObjectID,
    next_committee_id: ObjectID,
    key_server_object_id: ObjectID,
    member_address: SuiAddress,
) -> RpcResult<Option<ObjectID>> {
    info!(
        "Validating committee transition: committee {} -> next {}",
        committee_id, next_committee_id
    );

    let committee_exists = check_committee_exists(sui_rpc_client, committee_id).await?;
    let next_committee_finalized =
        check_committee_finalized(sui_rpc_client, next_committee_id).await?;
    let next_master_key_present = std::env::var("NEXT_MASTER_KEY").is_ok();

    match (
        committee_exists,
        next_committee_finalized,
        next_master_key_present,
    ) {
        // Case 1: Next committee not finalized yet - use current committee and MASTER_KEY
        (true, false, _) => {
            info!(
                "Committee {} exists, next committee {} not finalized. Will monitor for transition.",
                committee_id, next_committee_id
            );

            // Validate current committee is finalized
            if !check_committee_finalized(sui_rpc_client, committee_id).await? {
                error!("Current committee {} is not finalized", committee_id);
                return Err(crate::sui_rpc_client::RpcError::new(format!(
                    "Current committee {} is not finalized",
                    committee_id
                )));
            }

            Ok(None) // Will use MASTER_KEY and monitor
        }

        // Case 2: Next committee finalized, old deleted, NEXT_MASTER_KEY present - rotation complete
        (false, true, true) => {
            info!(
                "Committee {} deleted, next committee {} finalized, NEXT_MASTER_KEY present. Rotation complete.",
                committee_id, next_committee_id
            );

            // Fetch PartialKeyServer for the next committee
            match fetch_partial_key_server(sui_rpc_client, key_server_object_id, member_address)
                .await?
            {
                Some(partial_key_server_id) => {
                    info!(
                        "Found PartialKeyServer {} for next committee {}",
                        partial_key_server_id, next_committee_id
                    );
                    Ok(Some(partial_key_server_id))
                }
                None => {
                    error!(
                        "No PartialKeyServer found for member {} after rotation",
                        member_address
                    );
                    Err(crate::sui_rpc_client::RpcError::new(format!(
                        "No PartialKeyServer found for member {} after rotation",
                        member_address
                    )))
                }
            }
        }

        // Case 3: Next committee finalized but old still exists - wait for deletion
        (true, true, _) => {
            info!(
                "Next committee {} is finalized but old committee {} still exists. Will monitor for deletion.",
                next_committee_id, committee_id
            );
            Ok(None) // Will use MASTER_KEY and monitor
        }

        // Invalid cases
        (false, true, false) => {
            error!(
                "Committee {} deleted and next committee {} finalized, but NEXT_MASTER_KEY not set",
                committee_id, next_committee_id
            );
            Err(crate::sui_rpc_client::RpcError::new(
                "Committee deleted and next committee finalized, but NEXT_MASTER_KEY not set",
            ))
        }
        (false, false, _) => {
            error!(
                "Committee {} does not exist and next committee {} not finalized",
                committee_id, next_committee_id
            );
            Err(crate::sui_rpc_client::RpcError::new(format!(
                "Committee {} does not exist and next committee {} not finalized",
                committee_id, next_committee_id
            )))
        }
    }
}

/// Monitor the committee transition:
/// - Check if the next_committee has reached Finalized state
/// - If Finalized, check if the old committee object has been deleted
/// - If old committee is deleted without NEXT_MASTER_KEY, crash with error
/// - If old committee is deleted with NEXT_MASTER_KEY, crash to restart with new key
///
/// Returns Ok(true) if monitoring should continue
pub(crate) async fn monitor_committee_transition(
    sui_rpc_client: SuiRpcClient,
    old_committee_id: ObjectID,
    next_committee_id: ObjectID,
) -> RpcResult<bool> {
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
                        "Old committee object {} still exists after next committee finalized. Continuing to monitor...",
                        old_committee_id
                    );
                    Ok(true)
                }
                Ok(false) => {
                    // Old committee deleted - check if NEXT_MASTER_KEY exists
                    if std::env::var("NEXT_MASTER_KEY").is_err() {
                        error!(
                            "Old committee object {} has been deleted but NEXT_MASTER_KEY environment variable is not set. Server will now exit.",
                            old_committee_id
                        );
                        std::process::exit(1);
                    }

                    error!(
                        "Old committee object {} has been deleted after next committee {} finalized. Server must restart to use NEXT_MASTER_KEY. Exiting now.",
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
