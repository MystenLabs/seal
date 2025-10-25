// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! gRPC utilities for interacting with Sui blockchain.

use anyhow::{anyhow, Result};
use serde::Deserialize;
use sui_rpc::client::v2::Client;
use sui_sdk_types::Address;

use crate::seal_move_types::SealCommittee;

/// Network enum for gRPC client creation
#[derive(Debug, Clone, Copy)]
pub enum Network {
    Mainnet,
    Testnet,
}

/// Create gRPC client for a given network.
pub fn create_grpc_client(network: Network) -> Result<Client> {
    let rpc_url = match network {
        Network::Mainnet => Client::MAINNET_FULLNODE,
        Network::Testnet => Client::TESTNET_FULLNODE,
    };
    Ok(Client::new(rpc_url)?)
}

/// Fetches complete committee data from Committee object onchain via gRPC.
pub async fn fetch_committee_data(
    committee_id: &Address,
    grpc_client: &mut Client,
) -> Result<SealCommittee> {
    // Fetch the Committee object with BCS data.
    let mut ledger_client = grpc_client.ledger_client();
    let mut request = sui_rpc::proto::sui::rpc::v2::GetObjectRequest::default();
    request.object_id = Some(committee_id.to_string());
    request.read_mask = Some(prost_types::FieldMask {
        paths: vec!["bcs".to_string()],
    });

    let response = ledger_client
        .get_object(request)
        .await
        .map(|r| r.into_inner())?;

    let bcs_bytes = response
        .object
        .and_then(|obj| obj.bcs)
        .and_then(|bcs| bcs.value)
        .map(|bytes| bytes.to_vec())
        .ok_or_else(|| anyhow!("No BCS data in Committee object"))?;

    // Deserialize as Object first, then extract Move object contents
    let obj: sui_types::object::Object = bcs::from_bytes(&bcs_bytes)?;
    let move_object = obj
        .data
        .try_as_move()
        .ok_or_else(|| anyhow!("Object is not a Move object"))?;

    bcs::from_bytes(move_object.contents())
        .map_err(|e| anyhow!("Failed to deserialize SealCommittee: {}", e))
}

/// Check if the committee has reached the Finalized state.
/// Returns Ok(true) if finalized, Ok(false) if not finalized, or Err if there was an error.
pub async fn check_committee_finalized(
    grpc_client: &mut Client,
    committee_id: &Address,
) -> Result<bool> {
    // Fetch the committee data
    let committee = fetch_committee_data(committee_id, grpc_client).await?;

    // Check if the state is Finalized
    let is_finalized = matches!(
        committee.state,
        crate::seal_move_types::CommitteeState::Finalized
    );
    Ok(is_finalized)
}

// BCS-deserializable KeyServer structs matching the Move definitions

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct KeyServer {
    pub id: Address,
    pub first_version: u64,
    pub last_version: u64,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct KeyServerV2 {
    pub name: String,
    pub key_type: u8,
    pub pk: Vec<u8>,
    pub server_type: ServerType,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub enum ServerType {
    Independent {
        url: String,
    },
    Committee {
        threshold: u16,
        partial_key_servers: sui_types::collection_types::VecMap<Address, PartialKeyServer>,
    },
}

#[derive(Debug, Deserialize, Clone)]
pub struct PartialKeyServer {
    pub partial_pk: Vec<u8>,
    pub url: String,
    pub party_id: u16,
}

/// Fetch the KeyServer object ID from the Committee's dynamic object field.
/// Returns the object ID of the KeyServer attached to this committee.
pub async fn fetch_key_server_id(
    grpc_client: &mut Client,
    committee_id: &Address,
) -> Result<Address> {
    let mut page_token: Option<Vec<u8>> = None;

    loop {
        let mut client = grpc_client.state_client();
        let mut request = sui_rpc::proto::sui::rpc::v2::ListDynamicFieldsRequest::default();
        request.parent = Some(committee_id.to_string());
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["field_id".to_string()],
        });
        request.page_size = Some(1000);
        request.page_token = page_token.clone().map(|t| t.into());

        let list_response = client
            .list_dynamic_fields(request)
            .await
            .map(|r| r.into_inner())?;

        // Search for KeyServer field
        for field in list_response.dynamic_fields {
            // For dynamic object fields, the field_id is a wrapper
            // We need to fetch the Field object to get the actual KeyServer object ID
            if let Some(field_id) = field.field_id {
                // Fetch the Field object to extract the actual KeyServer ID
                let mut ledger_client = grpc_client.ledger_client();
                let mut field_request = sui_rpc::proto::sui::rpc::v2::GetObjectRequest::default();
                field_request.object_id = Some(field_id.clone());
                field_request.read_mask = Some(prost_types::FieldMask {
                    paths: vec!["bcs".to_string()],
                });

                let field_response = ledger_client
                    .get_object(field_request)
                    .await
                    .map(|r| r.into_inner())?;

                let field_bcs_bytes = field_response
                    .object
                    .and_then(|obj| obj.bcs)
                    .and_then(|bcs| bcs.value)
                    .map(|bytes| bytes.to_vec())
                    .ok_or_else(|| anyhow!("No BCS data in Field object"))?;

                // Deserialize the Field object
                let field_obj: sui_types::object::Object = bcs::from_bytes(&field_bcs_bytes)?;

                // For dynamic object fields, the Field wraps an ObjectID
                // Extract it from the Move object data
                let move_object = field_obj
                    .data
                    .try_as_move()
                    .ok_or_else(|| anyhow!("Field is not a Move object"))?;

                // The Field<ID, KeyServer> struct has a `value` field containing the ObjectID
                // Parse the Move struct to extract the object ID
                #[derive(serde::Deserialize)]
                #[allow(dead_code)]
                struct Field<K, V> {
                    id: sui_types::id::UID,
                    name: K,
                    value: V,
                }

                let field: Field<sui_types::id::ID, sui_types::id::ID> =
                    bcs::from_bytes(move_object.contents())
                        .map_err(|e| anyhow!("Failed to deserialize Field: {}", e))?;

                // The value is the ObjectID of the actual KeyServer
                let key_server_id = sui_sdk_types::Address::from_bytes(field.value.bytes)?;
                return Ok(key_server_id);
            }
        }

        // Continue to next page if available
        match list_response.next_page_token {
            Some(token) if !token.is_empty() => page_token = Some(token.to_vec()),
            _ => break,
        }
    }

    Err(anyhow!(
        "No KeyServer dynamic object field found on committee {}",
        committee_id
    ))
}

/// Result containing PartialKeyServer data
pub struct PartialKeyServerInfo {
    pub party_id: u16,
    pub partial_pk: Vec<u8>,
    pub url: String,
}

/// Fetch the PartialKeyServer data for a specific member address from KeyServerV2.
/// This should be called when a committee reaches the Finalized state.
/// Returns the PartialKeyServer info including party_id, partial_pk, and url.
pub async fn fetch_partial_key_server_info(
    grpc_client: &mut Client,
    key_server_id: &Address,
    member_address: Address,
) -> Result<Option<PartialKeyServerInfo>> {
    // First, find the KeyServerV2 dynamic field on the KeyServer object
    let mut page_token: Option<Vec<u8>> = None;
    let mut v2_object_id: Option<String> = None;

    // Find KeyServerV2 field (key = 2)
    let key_2_bcs = bcs::to_bytes(&2u64)?;

    loop {
        let mut client = grpc_client.state_client();
        let mut request = sui_rpc::proto::sui::rpc::v2::ListDynamicFieldsRequest::default();
        request.parent = Some(key_server_id.to_string());
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["field_id".to_string(), "name".to_string()],
        });
        request.page_size = Some(1000);
        request.page_token = page_token.clone().map(|t| t.into());

        let list_response = client
            .list_dynamic_fields(request)
            .await
            .map(|r| r.into_inner())?;

        // Search for KeyServerV2 field (version 2) by matching the name = 2
        for field in list_response.dynamic_fields {
            if let Some(name) = field.name {
                if let Some(value) = name.value {
                    if value.as_ref() == key_2_bcs.as_slice() {
                        if let Some(field_id) = field.field_id {
                            v2_object_id = Some(field_id);
                            break;
                        }
                    }
                }
            }
        }

        if v2_object_id.is_some() {
            break;
        }

        // Continue to next page if available
        match list_response.next_page_token {
            Some(token) if !token.is_empty() => page_token = Some(token.to_vec()),
            _ => break,
        }
    }

    let v2_oid = v2_object_id
        .ok_or_else(|| anyhow!("No KeyServerV2 field found on KeyServer {}", key_server_id))?;

    // Fetch the KeyServerV2 object to extract the partial_key_servers VecMap
    let mut ledger_client = grpc_client.ledger_client();
    let mut v2_request = sui_rpc::proto::sui::rpc::v2::GetObjectRequest::default();
    v2_request.object_id = Some(v2_oid.clone());
    v2_request.read_mask = Some(prost_types::FieldMask {
        paths: vec!["bcs".to_string()],
    });

    let v2_response = ledger_client
        .get_object(v2_request)
        .await
        .map(|r| r.into_inner())?;

    let v2_bcs_bytes = v2_response
        .object
        .and_then(|obj| obj.bcs)
        .and_then(|bcs| bcs.value)
        .map(|bytes| bytes.to_vec())
        .ok_or_else(|| anyhow!("No BCS data in KeyServerV2 object"))?;

    // Deserialize as Object first
    let v2_obj: sui_types::object::Object = bcs::from_bytes(&v2_bcs_bytes)?;
    let move_object = v2_obj
        .data
        .try_as_move()
        .ok_or_else(|| anyhow!("KeyServerV2 is not a Move object"))?;

    // The object is actually a Field<u64, KeyServerV2> wrapper
    // We need to deserialize it and extract the value
    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct FieldWrapper<K, V> {
        id: sui_types::id::UID,
        name: K,
        value: V,
    }

    let field_wrapper: FieldWrapper<u64, KeyServerV2> = bcs::from_bytes(move_object.contents())
        .map_err(|e| anyhow!("Failed to deserialize Field wrapper: {}", e))?;

    let key_server_v2 = field_wrapper.value;

    // Extract the VecMap from the Committee variant
    match key_server_v2.server_type {
        ServerType::Committee {
            partial_key_servers,
            ..
        } => {
            // Look up the member address in the VecMap
            for entry in partial_key_servers.contents.iter() {
                if entry.key == member_address {
                    // PartialKeyServer is stored inline in VecMap, not as a separate object
                    return Ok(Some(PartialKeyServerInfo {
                        party_id: entry.value.party_id,
                        partial_pk: entry.value.partial_pk.clone(),
                        url: entry.value.url.clone(),
                    }));
                }
            }
            Ok(None)
        }
        ServerType::Independent { .. } => Err(anyhow!("KeyServerV2 is not a Committee server")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::encoding::{Encoding, Hex};
    use std::str::FromStr;

    #[tokio::test]
    async fn test_fetch_committee_members() {
        // Test Committee object ID from testnet
        let committee_id =
            Address::from_str("0x1d8e07b865da82d86c71bb0ac8adf174996fd780ccae8237dd5f6ea38d9fe903")
                .unwrap();

        // Create gRPC client
        let mut grpc_client = Client::new(Client::TESTNET_FULLNODE).unwrap();

        // Fetch committee data
        let committee = fetch_committee_data(&committee_id, &mut grpc_client)
            .await
            .unwrap();
        let members_info = committee.get_members_info().unwrap();

        let addresses = [
            Address::from_str("0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d")
                .unwrap(),
            Address::from_str("0xe6a37ff5cd968b6a666fb033d85eabc674449f44f9fc2b600e55e27354211ed6")
                .unwrap(),
            Address::from_str("0x223762117ab21a439f0f3f3b0577e838b8b26a37d9a1723a4be311243f4461b9")
                .unwrap(),
        ];
        for crate::seal_move_types::ParsedMemberInfo {
            party_id,
            address,
            enc_pk,
            signing_pk,
        } in members_info.iter()
        {
            assert!(addresses[*party_id as usize] == *address);
            assert!(*enc_pk == bcs::from_bytes(&Hex::decode("0xaf2ca44fd70f4e72d5ef6ad1bc8f5ab42850a36f75e1562f4f33ca2d25c5fee5fe780e164f17e0591a46a44d545e71f21447d316563899b77f34ee34d84ee70c70505f98dc4e7f5914b347cec49ef3a510efa9568416413cacd5361f42c8fa58").unwrap()).unwrap());
            assert!(*signing_pk == bcs::from_bytes(&Hex::decode("0x89dcee7b2f5b6256eafe4eabcac4a2fa348ce52d10b6a994da6f2969eb76d87e54f0298d446ab72f0094dae0f0fb5e2018e1d2957cb1514837d0bdb6edab1f549638bdbdca7542f81b62d426a898c9efff50cdaa1958b8ed06cbc72208570b46").unwrap()).unwrap());
        }
    }
}
