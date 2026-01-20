// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! gRPC utilities for interacting with Sui blockchain.

use std::collections::HashMap;

use crate::{
    move_types::{Field, KeyServerV2, PartialKeyServerInfo, SealCommittee, ServerType, Wrapper},
    Network,
};
use anyhow::{anyhow, Result};
use sui_rpc::client::Client;
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

/// Fetch KeyServerV2 data directly from a KeyServer object ID.
/// Returns the KeyServerV2 data.
pub async fn fetch_key_server_by_id(
    grpc_client: &mut Client,
    ks_obj_id: &Address,
) -> Result<KeyServerV2> {
    // Derive KeyServerV2 dynamic field ID on KeyServer object.
    // This is a regular dynamic_field, not dynamic_object_field.
    // Key type: u64, Key value: EXPECTED_KEY_SERVER_VERSION
    let v2_field_name_bcs =
        bcs::to_bytes(&EXPECTED_KEY_SERVER_VERSION).expect("BCS serialization failed");
    let key_server_v2_field_id =
        ks_obj_id.derive_dynamic_child_id(&sui_sdk_types::TypeTag::U64, &v2_field_name_bcs);

    // Fetch and deserialize the Field<u64, KeyServerV2> object.
    let field: Field<u64, KeyServerV2> = fetch_and_deserialize_move_object(
        grpc_client,
        &key_server_v2_field_id,
        "KeyServerV2 Field object",
    )
    .await?;

    Ok(field.value)
}

pub async fn fetch_committee_server_version(
    grpc_client: &mut Client,
    ks_obj_id: &Address,
) -> Result<u32> {
    let key_server_v2 = fetch_key_server_by_id(grpc_client, ks_obj_id).await?;
    match key_server_v2.server_type {
        ServerType::Committee { version, .. } => Ok(version),
        _ => Err(anyhow!("KeyServer is not of type Committee")),
    }
}

/// Fetch the KeyServer object and KeyServerV2 data for a given committee.
/// Returns the KeyServer object ID and the KeyServerV2 data.
pub async fn fetch_key_server_by_committee(
    grpc_client: &mut Client,
    committee_id: &Address,
) -> Result<(Address, KeyServerV2)> {
    // Derive dynamic object field wrapper id.
    let wrapper_key = Wrapper {
        name: *committee_id,
    };
    let wrapper_key_bcs = bcs::to_bytes(&wrapper_key)?;

    let wrapper_type_tag = TypeTag::Struct(Box::new(StructTag::new(
        Address::TWO,
        "dynamic_object_field".parse().unwrap(),
        "Wrapper".parse().unwrap(),
        vec![TypeTag::Struct(Box::new(StructTag::new(
            Address::TWO,
            "object".parse().unwrap(),
            "ID".parse().unwrap(),
            vec![],
        )))],
    )));

    let field_wrapper_id =
        committee_id.derive_dynamic_child_id(&wrapper_type_tag, &wrapper_key_bcs);

    let field_wrapper: Field<Wrapper<Address>, Address> =
        fetch_and_deserialize_move_object(grpc_client, &field_wrapper_id, "Field wrapper object")
            .await?;
    let ks_obj_id = field_wrapper.value;

    let key_server_v2 = fetch_key_server_by_id(grpc_client, &ks_obj_id).await?;

    Ok((ks_obj_id, key_server_v2))
}

/// Fetch partial key server information for a specific committee member from onchain KeyServer object.
/// Returns the PartialKeyServerInfo for the specified member address.
pub async fn get_partial_key_server_for_member(
    grpc_client: &mut Client,
    key_server_obj_id: &Address,
    member_address: &Address,
) -> Result<PartialKeyServerInfo> {
    let ks = fetch_key_server_by_id(grpc_client, key_server_obj_id).await?;
    let partial_key_servers = to_partial_key_servers(&ks).await?;

    partial_key_servers
        .get(member_address)
        .cloned()
        .ok_or_else(|| {
            anyhow!(
                "PartialKeyServerInfo not found for member {}",
                member_address
            )
        })
}

pub async fn to_partial_key_servers(
    key_server_v2: &KeyServerV2,
) -> Result<HashMap<Address, PartialKeyServerInfo>> {
    match &key_server_v2.server_type {
        ServerType::Committee {
            partial_key_servers,
            ..
        } => partial_key_servers
            .0
            .contents
            .iter()
            .map(|entry| {
                Ok((
                    entry.key,
                    PartialKeyServerInfo {
                        party_id: entry.value.party_id,
                        partial_pk: entry.value.partial_pk,
                        name: entry.value.name.clone(),
                        url: entry.value.url.clone(),
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
            Address::from_str("0xcadfbdfff2b6df35000ec7bd7a9532eb2b5f834a27bdf33f67d1440f99f6b476")
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

        let expected_enc_pks = [
            from_hex_bcs::<PublicKey<G2Element>>("0xac92aa451bb120df26205693cf8724cbeb6781ee48ab62d84a165fea30aa78167f5bcfc5eadd801f67c2c88547584dec14e7e5c29107bbb5bbfec7aac302774c7861504158f4ec174f5d55b1b71d9ca022965729e6785bb7553ed99fb01bb96a"),
            from_hex_bcs::<PublicKey<G2Element>>("0x8e67011155f8795e7d19d21b5b5c4bdc07499946cd80f151f2d7473830380215b7b768b1b3f179ed3764f47855db409217a2675f9f0cfd1c19c553ebc11a0e7289a91336165208bc5d3f58aaf09679427ab9b561abcef16e5da23791aefa6d58"),
            from_hex_bcs::<PublicKey<G2Element>>("0x999ff841e7b2f8d565ad69b96b6e03f9478bdb52b037245f41d5ad1535271fb514b5c3c96f66ef5bd2122ef55cdaac48042c969d95ce66c629381a64cdefa3781ec521704818ccfd8bb070249a08072fc07d80ae572a1e5d5dbc2edc12bda8d1"),
        ];
        let expected_signing_pks = [
            from_hex_bcs::<BLS12381PublicKey>("0xa265e1b0eff30db329c9abafe14005a31d3a7e5f8b4fad0d007a994aac9f21b4eae3f4e9ebc8ff268d11c93b2d8ba8df08b57a54bbf4900011df0be631dc087846a9cf233902a7d1d819d46df80db55c35e5310bc5557481bb618c765347958b"),
            from_hex_bcs::<BLS12381PublicKey>("0xa83e3f4d171d1655d98830af433be591c6a97dcc2f9f054b8cf5c07ecd405daa2f33cdf5e19fea68b843e2946df49550138350f39ebd529b370d46b46254a093b349290564cca85676d9ecf5a90539f57563a55ea92b65a8a932314c19ab24ed"),
            from_hex_bcs::<BLS12381PublicKey>("0x8604819b0729b376015bfbc30e4de554cba2eb28767407091328b154c83c53978221cbf1974b85b8e73287d0104a5462062558d6e7e6ef04457a50d5dd333f0c33315bbfadf399587b58a483f119168bd78bc8b2bffb5fd87e1518ffc93d4529"),
        ];

        for ParsedMemberInfo {
            name,
            party_id,
            address,
            enc_pk,
            signing_pk,
        } in members_info.values()
        {
            assert_eq!(name, &format!("server{}", party_id + 1));
            assert_eq!(addresses[*party_id as usize], *address);
            assert_eq!(enc_pk, &expected_enc_pks[*party_id as usize]);
            assert_eq!(signing_pk, &expected_signing_pks[*party_id as usize]);
        }

        assert!(committee.is_init().is_ok());
        assert!(committee.is_finalized().is_err());
    }

    #[tokio::test]
    async fn test_fetch_partial_key_servers() {
        // Test rotated finalized committee from testnet (V1 with 4 parties).
        let committee_id =
            Address::from_str("0x27f97ecae74a58add30df73bc2d5b4a15dd55deb03bdb4e460ee5dc02b813892")
                .unwrap();

        // Create gRPC client.
        let mut grpc_client = Client::new(Client::TESTNET_FULLNODE).unwrap();

        // Fetch committee data to get member addresses.
        let committee = fetch_committee_data(&mut grpc_client, &committee_id)
            .await
            .unwrap();

        // Expected values for rotated committee (4 parties, version 1).
        let expected_key_server =
            Address::from_str("0xdf791818e65275ea9e3dca53e639cd5a764d7ee8d5b1107cf362004df42a8295")
                .unwrap();
        let expected_partial_pks = [
            "0xb875772befcf3838c67fb39dd094d9eacf1beed625c6eabec1f66aa1c79fb65d98d1972bf8f45b2092fa8dd089cc12eb0c9d23db44842a7db16caf54ebc64202de1aea1767b70e6f462e354e62bcd0e5b151ab8d8c9dbcc54b01dc482e90cd61",
            "0xa733bc8ffa0c914a23892a7eba24290fff392b1b5f4f06c7dccaef67f4fcb315e44606abba3e92141c2fd88b06b138f6167d026700db3d46d09d406381dd1c0b1b78c0a35fda6d2489fa602cd5334ca179243ec766acbfc75bffa7e704772d31",
            "0x98a060d7711d3edbcb819155326f2bdf1c2ee4d9621df4bd7adf4d6ae49b625bb7bd293299a0cb550cf76a22f93618f412e76dcf4a8ef0251e3423cb72d0760ec7f2d34dae9cd8745fbfa8ab8ec00813806e4e8ac35064f5e885658732ba5f19"
        ];

        let (ks_obj_id, key_server_v2) =
            fetch_key_server_by_committee(&mut grpc_client, &committee_id)
                .await
                .unwrap();
        let partial_key_servers = to_partial_key_servers(&key_server_v2).await.unwrap();

        // Assert that the version field is 1.
        match key_server_v2.server_type {
            ServerType::Committee { version, .. } => {
                assert_eq!(version, 0);
            }
            _ => panic!("KeyServer should be of type Committee"),
        }

        // Verify the key server object ID matches expected.
        assert_eq!(ks_obj_id, expected_key_server,);

        for member in &committee.members {
            let partial_key_server_info = partial_key_servers.get(member).unwrap();

            let expected_pk_bytes =
                Hex::decode(expected_partial_pks[partial_key_server_info.party_id as usize])
                    .unwrap();
            let expected_pk: G2Element = bcs::from_bytes(&expected_pk_bytes).unwrap();
            assert_eq!(
                partial_key_server_info.partial_pk, expected_pk,
                "Partial PK for party {} (member {}) should match",
                partial_key_server_info.party_id, member
            );
        }
    }
}
