// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::groups::bls12381::G2Element;
use fastcrypto_tbls::ecies_v1::PublicKey;
use serde::Deserialize;
use std::collections::HashMap;
use sui_rpc::client::Client;
use sui_types::base_types::{ObjectID, SuiAddress};
use sui_types::collection_types::VecSet;
use sui_types::dynamic_field::Field;

/// Create gRPC client for a given network
pub fn create_grpc_client(network: &str) -> Result<Client> {
    let rpc_url = match network.to_lowercase().as_str() {
        "mainnet" => Ok(Client::MAINNET_FULLNODE),
        "testnet" => Ok(Client::TESTNET_FULLNODE),
        _ => Err(anyhow!(
            "Invalid network: {}. Use 'mainnet' or 'testnet'",
            network
        )),
    }?;
    Ok(Client::new(rpc_url)?)
}

// Move struct definitions for BCS deserialization (matching deployed contract on testnet)
#[derive(Deserialize, Clone, Debug)]
pub struct VecMap<K, V>(pub sui_types::collection_types::VecMap<K, V>);

#[derive(Deserialize, Clone, Debug)]
#[allow(dead_code)]
pub struct KeyServerV2 {
    name: String,
    key_type: u8,
    pk: Vec<u8>,
    server_type: ServerType,
}

#[derive(Deserialize, Clone, Debug)]
#[allow(dead_code)]
pub enum ServerType {
    Independent {
        url: String,
    },
    Committee {
        threshold: u16,
        partial_key_servers: VecMap<SuiAddress, PartialKeyServer>,
    },
}

#[derive(Deserialize, Clone, Debug)]
#[allow(dead_code)]
pub struct PartialKeyServer {
    partial_pk: Vec<u8>,
    url: String,
    party_id: u16,
    owner: SuiAddress,
}

// Committee-related structs for fetching init state (matching onchain structs)
#[derive(Deserialize, Clone, Debug)]
#[allow(dead_code)]
pub struct CandidateData {
    pub enc_pk: Vec<u8>,
    pub signing_pk: Vec<u8>,
    pub url: String,
}

#[derive(Deserialize, Clone, Debug)]
#[allow(dead_code)]
pub enum CommitteeState {
    Init {
        candidate_data: VecMap<SuiAddress, CandidateData>,
    },
    PostDKG {
        candidate_data: VecMap<SuiAddress, CandidateData>,
        partial_pks: Vec<Vec<u8>>,
        pk: Vec<u8>,
        approvals: VecSet<SuiAddress>,
    },
    Finalized {
        pk: Vec<u8>,
    },
}

#[derive(Deserialize, Clone, Debug)]
#[allow(dead_code)]
pub struct Committee {
    id: ObjectID,
    threshold: u16,
    pub members: Vec<SuiAddress>,
    pub state: CommitteeState,
    old_committee_id: Option<ObjectID>,
}

/// Complete committee data including threshold, old_committee_id, and members
/// Each member is represented as (party_id, address, enc_pk_hex)
#[derive(Debug, Clone)]
pub struct ParsedCommitteeData {
    pub threshold: u16,
    pub members: Vec<(u16, SuiAddress, PublicKey<G2Element>)>,
    pub old_committee_id: Option<ObjectID>,
}

impl ParsedCommitteeData {
    /// Find party ID by address
    pub fn find_party_id(&self, address: &SuiAddress) -> Option<u16> {
        self.members
            .iter()
            .find(|(_, addr, _)| addr == address)
            .map(|(party_id, _, _)| *party_id)
    }
}

/// Fetches complete committee data from Committee object onchain
pub async fn fetch_committee_data(
    committee_id: &ObjectID,
    grpc_client: &mut Client,
) -> Result<ParsedCommitteeData> {
    // Fetch the Committee object with BCS data
    let mut ledger_client = grpc_client.ledger_client();
    let mut request = sui_rpc::proto::sui::rpc::v2beta2::GetObjectRequest::default();
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

    // Deserialize Move object contents as Committee
    let committee: Committee = bcs::from_bytes(move_object.contents())?;

    // Extract candidate data from Init state
    let candidate_data = match &committee.state {
        CommitteeState::Init { candidate_data } => candidate_data,
        _ => {
            return Err(anyhow!("Invalid committee state: {:?}", committee.state));
        }
    };

    let mut members = Vec::new();

    // Use committee.members ordering. Party ID is the index in the members vector.
    for (party_id, member_addr) in committee.members.iter().enumerate() {
        // Find the candidate data for this member
        let entry = candidate_data
            .0
            .contents
            .iter()
            .find(|e| &e.key == member_addr)
            .ok_or_else(|| anyhow!("Member address {} not found in candidate data", member_addr))?;

        // The enc_pk is stored as ASCII bytes of a Move byte literal (x0x...)
        // Convert bytes directly to UTF-8 string
        let enc_pk_str = String::from_utf8(entry.value.enc_pk.clone())
            .map_err(|e| anyhow!("Failed to convert enc_pk to UTF-8 string: {}", e))?;

        // Strip Move byte literal format: x0x... -> 0x...
        let enc_pk_hex = enc_pk_str.trim_start_matches('x').to_string();
        let node_pk: PublicKey<G2Element> =
            bcs::from_bytes(&Hex::decode(&enc_pk_hex)?).map_err(|e| {
                anyhow!(
                    "Failed to deserialize ECIES PK for party {}: {}",
                    party_id,
                    e
                )
            })?;
        members.push((party_id as u16, *member_addr, node_pk));
    }

    Ok(ParsedCommitteeData {
        threshold: committee.threshold,
        members,
        old_committee_id: committee.old_committee_id,
    })
}

/// Fetches old partial public keys from KeyServer object onchain
pub async fn fetch_old_partial_pks_from_keyserver(
    key_server_id: &ObjectID,
    grpc_client: &mut Client,
) -> Result<HashMap<u16, G2Element>> {
    // BCS-serialize the dynamic field name (u64 value 2 for KeyServerV2)
    let field_name_bcs = bcs::to_bytes(&2u64)?;

    // Find the dynamic field with name value = 2
    let field_object_id = find_dynamic_field(grpc_client, key_server_id, &field_name_bcs).await?;

    // Fetch the Field<u64, KeyServerV2> object with BCS data
    let mut ledger_client = grpc_client.ledger_client();
    let mut request = sui_rpc::proto::sui::rpc::v2beta2::GetObjectRequest::default();
    request.object_id = Some(field_object_id);
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
        .ok_or_else(|| anyhow!("No BCS data in object"))?;

    // Deserialize as Object first, then extract Move object contents
    let obj: sui_types::object::Object = bcs::from_bytes(&bcs_bytes)?;
    let move_object = obj
        .data
        .try_as_move()
        .ok_or_else(|| anyhow!("Object is not a Move object"))?;

    // Deserialize Move object contents as Field<u64, KeyServerV2>
    let field: Field<u64, KeyServerV2> = bcs::from_bytes(move_object.contents())?;

    // Extract partial key servers from the ServerType
    let partial_key_servers = match field.value.server_type {
        ServerType::Committee {
            partial_key_servers,
            ..
        } => partial_key_servers,
        _ => return Err(anyhow!("KeyServer is not of type Committee")),
    };

    // Convert VecMap to HashMap and extract G2Elements
    let mut result = HashMap::new();

    for entry in partial_key_servers.0.contents.iter() {
        let party_id = entry.value.party_id;

        // The partial_pk is stored as a Move byte literal: x"0xabc..."
        // Convert to string and strip the Move byte literal format
        let hex_str = String::from_utf8(entry.value.partial_pk.clone()).map_err(|e| {
            anyhow!(
                "Failed to convert partial_pk to UTF-8 string for party {}: {}",
                party_id,
                e
            )
        })?;

        // Strip Move byte literal format: x"0x..." -> 0x...
        let hex_str = hex_str.trim_start_matches("x\"").trim_end_matches('"');

        // Decode hex to bytes
        let pk_bytes = Hex::decode(hex_str)
            .map_err(|e| anyhow!("Failed to decode hex string for party {}: {}", party_id, e))?;

        // Deserialize as G2Element from BCS
        let pk: G2Element = bcs::from_bytes(&pk_bytes).map_err(|e| {
            anyhow!(
                "Failed to deserialize G2Element for party {}: {}",
                party_id,
                e
            )
        })?;
        result.insert(party_id, pk);
    }

    if result.is_empty() {
        return Err(anyhow!("No partial public keys found in KeyServer object"));
    }

    Ok(result)
}

/// Find a dynamic field by its BCS-encoded name
async fn find_dynamic_field(
    grpc_client: &mut Client,
    parent_id: &ObjectID,
    field_name_bcs: &[u8],
) -> Result<String> {
    let mut page_token: Option<Vec<u8>> = None;

    loop {
        let mut client = grpc_client.live_data_client();
        let mut request = sui_rpc::proto::sui::rpc::v2beta2::ListDynamicFieldsRequest::default();
        request.parent = Some(parent_id.to_hex_literal());
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["field_id".to_string(), "name_value".to_string()],
        });
        request.page_size = Some(1000);
        request.page_token = page_token.clone().map(|t| t.into());

        let list_response = client
            .list_dynamic_fields(request)
            .await
            .map(|r| r.into_inner())?;

        // Search for matching field in this page
        for field in list_response.dynamic_fields {
            if let Some(name_value) = field.name_value {
                if name_value.as_ref() == field_name_bcs {
                    return field
                        .field_id
                        .ok_or_else(|| anyhow!("Field has no object ID"));
                }
            }
        }

        // Continue to next page if available
        match list_response.next_page_token {
            Some(token) if !token.is_empty() => page_token = Some(token.to_vec()),
            _ => break,
        }
    }

    Err(anyhow!(
        "Dynamic field with version 2 not found for object {}",
        parent_id
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_fetch_old_partial_pks_from_keyserver() {
        // Test KeyServer object ID from testnet
        let key_server_id = ObjectID::from_hex_literal(
            "0xe2974ab332c5625bf1ce501bd33f518c39a3b1c788b88e996aaa3f90b8fe27e7",
        )
        .unwrap();

        // Create gRPC client
        let mut grpc_client = Client::new(Client::TESTNET_FULLNODE).unwrap();

        // Fetch partial PKs
        let partial_pks = fetch_old_partial_pks_from_keyserver(&key_server_id, &mut grpc_client)
            .await
            .unwrap();

        // Verify partial PKs match expected values from onchain KeyServer
        let expected_pks = [
            "0xa902797f71d15e5410686b29019cdfd09fa641f8069815f0f122a5a564b60ddf6f8c408c30c95b30967e13f10c96f8271423ddb64efe3527e171d5057501b78c70bc2f37d538f851b2f01fd67d018d233ec90fbe12762e2ba3e353dfcf935880",
            "0xa3359770d9c57203a06f94cb87b4556498f7a8d192d5996283b3b0bfb90412fadfe957ef248952c637b8fd29fe556bd20d1d9778fb1b956efb4d0749be4fd49e15881648ec9d558a88e4a2f3949c2147db53c611c2ef5e0fc6f897a7b8a692eb",
            "0x94dc2adcf38b2c41e84094696181536b957f039cd491cc9816e278658c07d745a4b235185198e4e2448af43ba2403447154f7d55769c94dd0a456bf30ca34718a567cbed94998dd4d459957a5425393face7a02e78e58deca9a8df2cd3b132e7",
            "0x88bd931e9308b4f2e5dce359b1180da67e81ee40f0b607929d78c4403f0a3c1c5fbc78117d4cd5b17d38d78a3b49bf94101090bba00327f6962f6e977e07d90f8098de133f9e6344b34e2c5f291a482cb92abc5eeb5f00247a782d523a3b97ba",
        ];

        for (party_id, expected_pk_hex) in expected_pks.iter().enumerate() {
            let expected_pk = bcs::from_bytes(&Hex::decode(expected_pk_hex).unwrap()).unwrap();

            let actual_pk = partial_pks
                .get(&(party_id as u16))
                .unwrap_or_else(|| panic!("Missing party {}", party_id));

            assert_eq!(actual_pk, &expected_pk, "Party {} PK mismatch", party_id);
        }
    }

    #[tokio::test]
    async fn test_fetch_committee_data() {
        // Test Committee object ID from testnet
        let committee_id = ObjectID::from_hex_literal(
            "0x7323635e5fda4e43895b8a954f1f620bebe8bfabf2714fa6fb54d1a4a97c9586",
        )
        .unwrap();

        // Create gRPC client
        let mut grpc_client = Client::new(Client::TESTNET_FULLNODE).unwrap();

        // Fetch committee data
        let committee_data = fetch_committee_data(&committee_id, &mut grpc_client)
            .await
            .unwrap();

        // Expected members with party_id from actual onchain data
        let expected_members = vec![
            (0u16, SuiAddress::from_str("0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d").unwrap(),
             bcs::from_bytes(&Hex::decode("0x886d98eddd9f4e66e69f620dff66b6ed3c21f3cf5bde3b42d1e18159ad2e7b59ed5eb994b2bdcc491d29a1c5d4d492fc0c549c8d20838c6adaa82945a60908f3a481c78273eadbc51d94906238d6fe2f16494559556b074e7bb6f36807f8462c").unwrap()).unwrap()),
            (1u16, SuiAddress::from_str("0xe6a37ff5cd968b6a666fb033d85eabc674449f44f9fc2b600e55e27354211ed6").unwrap(),
              bcs::from_bytes(&Hex::decode("0xab5603f3cfaef06c0994f289bf8f1519222edd6ed48b49d9ebb975312dfbcd513dca31c83f6d1d1f45188f373aff95ae06f81dfd2cfafd69f679ce22d311ad4d34725277b369ece21f98e8f3ac257a589c0075d7533487862170760c69aedf4e").unwrap()).unwrap()),
            (2u16, SuiAddress::from_str("0x223762117ab21a439f0f3f3b0577e838b8b26a37d9a1723a4be311243f4461b9").unwrap(),
            bcs::from_bytes(&Hex::decode("0xa92323cf59aa3250ce8dc9e9c9062e675be937fe342ec276927c7dc99788957a0e589b7eff49a5de061b72976312d1e80281c37d050d1a68959c7b92c815ecd8283df96578c91a6da9e1b5b1cba73b7d39b77af88d784ce9f51f487d64295560").unwrap()).unwrap()),
        ];

        assert_eq!(committee_data.members, expected_members);
    }
}
