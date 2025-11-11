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
use sui_sdk_types::{Address, Object, StructTag, TypeTag};

pub(crate) const EXPECTED_KEY_SERVER_VERSION: u64 = 2;

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
    object_id: &Address,
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
    fetch_and_deserialize_move_object(grpc_client, committee_id, "Committee object").await
}

/// Fetch the KeyServer object and KeyServerV2 data for a given committee.
/// Returns the KeyServer object ID and the KeyServerV2 data.
pub async fn fetch_key_server(
    grpc_client: &mut Client,
    committee_id: &Address,
) -> Result<(Address, KeyServerV2)> {
    // Derive dynamic object field wrapper id.
    let wrapper_key = Wrapper {
        name: *committee_id,
    };
    let wrapper_key_bcs = bcs::to_bytes(&wrapper_key)?;

    let wrapper_type_tag = TypeTag::Struct(Box::new(StructTag {
        address: Address::TWO,
        module: "dynamic_object_field".parse().unwrap(),
        name: "Wrapper".parse().unwrap(),
        type_params: vec![TypeTag::Struct(Box::new(StructTag {
            address: Address::TWO,
            module: "object".parse().unwrap(),
            name: "ID".parse().unwrap(),
            type_params: vec![],
        }))],
    }));

    let field_wrapper_id =
        committee_id.derive_dynamic_child_id(&wrapper_type_tag, &wrapper_key_bcs);

    let field_wrapper: Field<Wrapper<Address>, Address> =
        fetch_and_deserialize_move_object(grpc_client, &field_wrapper_id, "Field wrapper object")
            .await?;
    let ks_obj_id = field_wrapper.value;

    // Derive KeyServerV2 dynamic field ID on KeyServer object.
    // This is a regular dynamic_field, not dynamic_object_field.
    // Key type: u64, Key value: EXPECTED_KEY_SERVER_VERSION
    let v2_field_name_bcs = bcs::to_bytes(&EXPECTED_KEY_SERVER_VERSION)?;
    let key_server_v2_field_id =
        ks_obj_id.derive_dynamic_child_id(&sui_sdk_types::TypeTag::U64, &v2_field_name_bcs);

    // Fetch and deserialize the Field<u64, KeyServerV2> object.
    let field: Field<u64, KeyServerV2> = fetch_and_deserialize_move_object(
        grpc_client,
        &key_server_v2_field_id,
        "KeyServerV2 Field object",
    )
    .await?;

    Ok((ks_obj_id, field.value))
}

/// Fetch partial key server info for all committee members.
/// Returns a HashMap mapping member addresses to their partial key server info.
pub async fn fetch_partial_key_server_info(
    grpc_client: &mut Client,
    committee_id: &Address,
) -> Result<HashMap<Address, PartialKeyServerInfo>> {
    let (ks_obj_id, key_server_v2) = fetch_key_server(grpc_client, committee_id).await?;

    // Extract partial key servers from ServerType::Committee.
    match key_server_v2.server_type {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ParsedMemberInfo;
    use fastcrypto::bls12381::min_sig::BLS12381PublicKey;
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
        let expected_signing_pk: BLS12381PublicKey = from_hex_bcs("0x89dcee7b2f5b6256eafe4eabcac4a2fa348ce52d10b6a994da6f2969eb76d87e54f0298d446ab72f0094dae0f0fb5e2018e1d2957cb1514837d0bdb6edab1f549638bdbdca7542f81b62d426a898c9efff50cdaa1958b8ed06cbc72208570b46");

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
        // Test rotated finalized committee from testnet.
        let committee_id =
            Address::from_str("0x82283c1056bb18832428034d20e0af5ed098bc58f8815363c33eb3a9b3fba867")
                .unwrap();

        // Old committee ID (before rotation).
        let old_committee_id =
            Address::from_str("0xaf2962d702d718f7b968eddc262da28418a33c296786cd356a43728a858faf80")
                .unwrap();

        // Create gRPC client.
        let mut grpc_client = Client::new(Client::TESTNET_FULLNODE).unwrap();

        // Assert that the old committee has no key server object (should fail).
        let old_result = fetch_partial_key_server_info(&mut grpc_client, &old_committee_id).await;
        assert!(
            old_result.is_err(),
            "Old committee should not have a key server object after rotation"
        );

        // Fetch committee data to get member addresses.
        let committee = fetch_committee_data(&mut grpc_client, &committee_id)
            .await
            .unwrap();

        // Expected values for rotated committee (4 parties).
        let expected_key_server =
            Address::from_str("0x5b4b868b22f4e1e87d3938f29aefc71a1e1ddf7352e214088c9eaf37e31efd31")
                .unwrap();
        let expected_partial_pks = [
            "0xaa56bd6b3af3eb4c92b75c1cbe7c4fff64563966b81f812008b4edcf1dac9cf42df1695be94f850f01dcfa813add29630810a51dc5bb558f67da1f3182e5e1ff064555e3c3cf83e295899677873c10c284ace2526dd7f5f7b898a7d323622e57",
            "0x8f1902dbf32c7c2dd7a6eefa97b1e6833bccd859c35c4ec6124dde5f267d260fcd16240cf0c5ecadfa5202563f97035e05ba0cd246ceaca8abb930505cf2752b00e14565af0ffe02a437de0b5c799c1e84314297b7fdc7e9fdd322a9c77c6bc3",
            "0x8d942a02eb6a3bf78d27ec8ee27b9a8721b07fe22866bb4f6614f78978e394c9ddc8b87712ddbc3fa2f0386bc3b68ccc18dd0f05f2ca5345bf19433933a5d77bf56cd2563a2e872f82b16495529b47086212466f903f84949b15153d7eab6848",
            "0x94eba091a424bed60ad920855706ee476d23c2d9d4763ab5a4f832b3e57c38eb7d81013ea8f5b4790b4db6cd1ad2fd051633e6c8e9a25f302b5b4382724c5e83c40e487dba39910df2829c09f7d38ee2d37e0a8a1bdc2a71486c5fb6e508c069",
        ];
        let partial_key_servers = fetch_partial_key_server_info(&mut grpc_client, &committee_id)
            .await
            .unwrap();

        // Fetch KeyServerV2 to check the version field.
        let (_ks_obj_id, key_server_v2) = fetch_key_server(&mut grpc_client, &committee_id)
            .await
            .unwrap();

        // Assert that the version field is 1.
        match key_server_v2.server_type {
            ServerType::Committee { version, .. } => {
                assert_eq!(version, 1, "Key server version should be 1 after rotation");
            }
            _ => panic!("KeyServer should be of type Committee"),
        }

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
