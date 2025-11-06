// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! gRPC utilities for interacting with Sui blockchain.

use std::collections::HashMap;

use crate::{
    move_types::{Field, KeyServerV2, PartialKeyServerInfo, SealCommittee, ServerType, Wrapper},
    Network,
};
use anyhow::{anyhow, Result};
use sui_rpc::client::v2::Client;
use sui_sdk_types::{Address, Object};

pub(crate) const EXPECTED_KEY_SERVER_VERSION: u64 = 2;
const PAGE_SIZE: u32 = 1000;

/// Create gRPC client for a given network.
pub fn create_grpc_client(network: &Network) -> Result<Client> {
    let rpc_url = match network {
        Network::Mainnet => Client::MAINNET_FULLNODE,
        Network::Testnet => Client::TESTNET_FULLNODE,
    };
    Ok(Client::new(rpc_url)?)
}

/// Fetch an object's BCS data and deserialize as type T.
async fn fetch_and_deserialize_move_object<T: serde::de::DeserializeOwned>(
    grpc_client: &mut Client,
    object_id: &str,
    error_context: &str,
) -> Result<T> {
    let mut ledger_client = grpc_client.ledger_client();
    let mut request = sui_rpc::proto::sui::rpc::v2::GetObjectRequest::default();
    request.object_id = Some(object_id.to_string());
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
        .ok_or_else(|| anyhow!("No BCS data in {}", error_context))?;

    let obj: Object = bcs::from_bytes(&bcs_bytes)?;
    let move_object = obj
        .as_struct()
        .ok_or_else(|| anyhow!("Object is not a Move struct in {}", error_context))?;
    bcs::from_bytes(move_object.contents())
        .map_err(|e| anyhow!("Failed to deserialize {}: {}", error_context, e))
}

/// Fetch seal Committee object onchain.
pub async fn fetch_committee_data(
    grpc_client: &mut Client,
    committee_id: &Address,
) -> Result<SealCommittee> {
    fetch_and_deserialize_move_object(grpc_client, &committee_id.to_string(), "Committee object")
        .await
}

/// Fetch partial key server info for all committee members.
/// Returns a HashMap mapping member addresses to their partial key server info.
pub async fn fetch_partial_key_server_info(
    grpc_client: &mut Client,
    committee_id: &Address,
) -> Result<HashMap<Address, PartialKeyServerInfo>> {
    // Find dynamic object field with name = committee.id to get KeyServer object ID.
    let field_name_bcs = bcs::to_bytes(&committee_id)?;
    let field_wrapper_id_str =
        find_dynamic_field(grpc_client, committee_id, &field_name_bcs).await?;
    let field_wrapper: Field<Wrapper<Address>, Address> = fetch_and_deserialize_move_object(
        grpc_client,
        &field_wrapper_id_str,
        "Field wrapper object",
    )
    .await?;
    let ks_obj_id = field_wrapper.value;

    // Find KeyServerV2 dynamic field on KeyServer object.
    let v2_field_name_bcs = bcs::to_bytes(&EXPECTED_KEY_SERVER_VERSION)?;
    let key_server_v2_field_id =
        find_dynamic_field(grpc_client, &ks_obj_id, &v2_field_name_bcs).await?;

    // Fetch and deserialize the Field<u64, KeyServerV2> object.
    let field: Field<u64, KeyServerV2> = fetch_and_deserialize_move_object(
        grpc_client,
        &key_server_v2_field_id,
        "KeyServerV2 Field object",
    )
    .await?;

    // Extract partial key servers from ServerType::Committee.
    match field.value.server_type {
        ServerType::Committee {
            partial_key_servers,
            ..
        } => partial_key_servers
            .0
            .contents
            .into_iter()
            .map(|entry| {
                let partial_pk = bcs::from_bytes(&entry.value.partial_pk)
                    .map_err(|e| anyhow!("Failed to deserialize partial PK: {}", e))?;
                Ok((
                    entry.key,
                    PartialKeyServerInfo {
                        ks_obj_id,
                        party_id: entry.value.party_id,
                        partial_pk,
                    },
                ))
            })
            .collect(),
        _ => Err(anyhow!("KeyServer is not of type Committee")),
    }
}

/// Find dynamic field by BCS-encoded name with pagination support.
async fn find_dynamic_field(
    grpc_client: &mut Client,
    parent_id: &Address,
    field_name_bcs: &[u8],
) -> Result<String> {
    let mut page_token: Option<Vec<u8>> = None;
    let mut client = grpc_client.state_client();

    loop {
        let mut request = sui_rpc::proto::sui::rpc::v2::ListDynamicFieldsRequest::default();
        request.parent = Some(parent_id.to_string());
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["field_id".to_string(), "name".to_string()],
        });
        request.page_size = Some(PAGE_SIZE);
        request.page_token = page_token.as_ref().map(|t| t.clone().into());

        let list_response = client
            .list_dynamic_fields(request)
            .await
            .map(|r| r.into_inner())?;

        // Search for matching field in this page.
        for field in list_response.dynamic_fields {
            if let Some(name) = field.name {
                if let Some(value) = name.value {
                    if value.as_ref() == field_name_bcs {
                        return field
                            .field_id
                            .ok_or_else(|| anyhow!("Field has no object ID"));
                    }
                }
            }
        }

        // Continue to next page if available.
        match list_response.next_page_token {
            Some(token) if !token.is_empty() => page_token = Some(token.to_vec()),
            _ => break,
        }
    }

    Err(anyhow!("Dynamic field not found for object {}", parent_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ParsedMemberInfo;
    use fastcrypto::encoding::{Encoding, Hex};
    use fastcrypto::groups::bls12381::G2Element;
    use fastcrypto_tbls::ecies_v1::PublicKey;
    use std::str::FromStr;

    /// Helper to deserialize from hex string.
    fn from_hex_bcs<T: serde::de::DeserializeOwned>(hex_str: &str) -> T {
        let bytes = Hex::decode(hex_str).unwrap();
        bcs::from_bytes(&bytes).unwrap()
    }

    #[tokio::test]
    async fn test_fetch_committee_members() {
        // Test committee object on testnet set up with 3 members.
        let committee_id =
            Address::from_str("0x1d8e07b865da82d86c71bb0ac8adf174996fd780ccae8237dd5f6ea38d9fe903")
                .unwrap();

        let mut grpc_client = create_grpc_client(&Network::Testnet).unwrap();
        let committee = fetch_committee_data(&mut grpc_client, &committee_id)
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

        let expected_enc_pk: PublicKey<G2Element> = from_hex_bcs("0xaf2ca44fd70f4e72d5ef6ad1bc8f5ab42850a36f75e1562f4f33ca2d25c5fee5fe780e164f17e0591a46a44d545e71f21447d316563899b77f34ee34d84ee70c70505f98dc4e7f5914b347cec49ef3a510efa9568416413cacd5361f42c8fa58");
        let expected_signing_pk: G2Element = from_hex_bcs("0x89dcee7b2f5b6256eafe4eabcac4a2fa348ce52d10b6a994da6f2969eb76d87e54f0298d446ab72f0094dae0f0fb5e2018e1d2957cb1514837d0bdb6edab1f549638bdbdca7542f81b62d426a898c9efff50cdaa1958b8ed06cbc72208570b46");

        for ParsedMemberInfo {
            party_id,
            address,
            enc_pk,
            signing_pk,
        } in members_info.values()
        {
            assert_eq!(addresses[*party_id as usize], *address);
            assert_eq!(enc_pk, &expected_enc_pk);
            assert_eq!(signing_pk, &expected_signing_pk);
        }

        assert!(committee.is_init().is_ok());
        assert!(committee.is_finalized().is_err());
    }

    #[tokio::test]
    async fn test_fetch_partial_key_servers() {
        // Test finalized committee from testnet.
        let committee_id =
            Address::from_str("0x210f1a2157d76e5c32a5e585ae3733b51105d553dc17f67457132af5e2dae7a5")
                .unwrap();

        // Create gRPC client.
        let mut grpc_client = Client::new(Client::TESTNET_FULLNODE).unwrap();

        // Fetch committee data to get member addresses.
        let committee = fetch_committee_data(&mut grpc_client, &committee_id)
            .await
            .unwrap();

        // Expected values.
        let expected_key_server =
            Address::from_str("0xd2b58f49921809aa797549b266974453d32babf286ca89fb1b33f6bbbfa303cc")
                .unwrap();
        let expected_partial_pks = [
            "0xb751ce15b11f71cc675f66cc490cea6151d0aa6ec2eb510969e4dfe125147a1dfe93c6b10ef6e19e7ec9a286ec5040330c08c223207379758bb742dc811885b2dcaed468650793d9486e647d2f9fb31c59b91945757f8eeb5fead34b6d353332",
            "0xb9b384f181c3b1fa00ac087ceb22f24e3468a320fc284ff87bd37a1c44b531679f18ad8cac1c4371736d4eadcb07a7281643f223f7cc7f9887f9cf0f5d69c2c30f2672511b4e80d00a66d34a18b0256eda999f91de53f9efd8c062025091bc30",
            "0x8cd739c5febbb942988e66525ff09ec3e29a746f44927069bb8e23f983cd6ee4a8f7a44b434178f7fd2951f89bae5ee70392911c0756b0339184be3f58b1de4966b8f6caa1e0a9c84429b043071fc8948935efca942f3c13fd3a115805fedd08",
        ];
        let partial_key_servers = fetch_partial_key_server_info(&mut grpc_client, &committee_id)
            .await
            .unwrap();

        for member in &committee.members {
            let partial_key_server_info = partial_key_servers.get(member).unwrap();

            assert_eq!(
                partial_key_server_info.ks_obj_id, expected_key_server,
                "Key server address should match for member {member}"
            );

            let expected_pk_bytes =
                Hex::decode(expected_partial_pks[partial_key_server_info.party_id as usize])
                    .unwrap();
            let expected_pk: fastcrypto::groups::bls12381::G2Element =
                bcs::from_bytes(&expected_pk_bytes).unwrap();
            assert_eq!(
                partial_key_server_info.partial_pk, expected_pk,
                "Partial PK for party {} (member {}) should match",
                partial_key_server_info.party_id, member
            );
        }
    }
}
