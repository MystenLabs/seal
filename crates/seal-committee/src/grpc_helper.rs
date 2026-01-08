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
            Address::from_str("0x39bddd8ac7a160c87267de8142e0c3f87322745ac48697807be83899ee716b0b")
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
            from_hex_bcs::<PublicKey<G2Element>>("0x8ebd9dd80ca1652b6b6b8d80a14afde4bae196f369182ec2e302c235f739853e322ee742adb7911628050bed24353a530da67dffe02f5390eeff949c12fbdf4d3567d1c3f8602c335eb93e88da7b14b8cfde3d94ee835b15d70e7a883ed28eda"),
            from_hex_bcs::<PublicKey<G2Element>>("0x8aa3a0b722271e9f6f14e621e1db76e4652c5944bbd57b7469c45eb4894c1584017cafe3eff0517cfcd710fcf1812554082b04334b018d6472ea3f34cc53ac6aecda3baed51dd92031803ab87a7cd8ccc75d2d968b1eed569b0d9304d1f41c19"),
            from_hex_bcs::<PublicKey<G2Element>>("0xb9a30a4515570699dbb8f2b57c81c27415b7f3788545c9defa196fcec5f360880e8ab66cd8479ee8e7486e061aeb834107b12c31ae87db68ccb8a219e3517d44b5a0254d456ee7506af70c6e72692b95392adba312d3958e2c57c9c61ef63a06"),
        ];
        let expected_signing_pks = [
            from_hex_bcs::<BLS12381PublicKey>("0x90eef60cb0ecb8ca153d99233add7832a2fe7221667a3272961d0cb7af9b662eba7a41941af1c05e0149f87cc789d74d0fb47d16b819158f92531b551d7043d371be825598436d5a54ee74a1dd48d848445e77c8b86e42651666cd2f2550b53b"),
            from_hex_bcs::<BLS12381PublicKey>("0xb1a9cb54074e036c39e0c7f097fe6b3b53b96c2569a3a0c14c1751501d758c42697a47ae0c035749fde44445e0fb12c2081dfeabc33ea65b4ce7529c16da8cc9ca2b4fe8615a241543e1d5db33052cc75bfb806c1e50a950c1db25ccee8da649"),
            from_hex_bcs::<BLS12381PublicKey>("0x8ea9af5ed693681f0c776068c440938efd8e25f8ab287549a5bb7dbfc2b620092e3e95469820b94f408b1352e802c089131abc0865336019575b5d6f6455652a02cecff5d4459181d62cb8aa710999784579ccd5199a0dab8b171289d7aa6551"),
        ];

        for ParsedMemberInfo {
            party_id,
            address,
            enc_pk,
            signing_pk,
        } in members_info.values()
        {
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
            Address::from_str("0x9b137931e62e28b57da78aa4c3ffd050f9a3f8a51dc5f28cf18be9907c70c0ea")
                .unwrap();

        // Create gRPC client.
        let mut grpc_client = Client::new(Client::TESTNET_FULLNODE).unwrap();

        // Fetch committee data to get member addresses.
        let committee = fetch_committee_data(&mut grpc_client, &committee_id)
            .await
            .unwrap();

        // Expected values for rotated committee (4 parties, version 1).
        let expected_key_server =
            Address::from_str("0x0c9b2a1185f42bebdc16baf0a393ec5bd93bab8b0cb902b694198077b27c15da")
                .unwrap();
        let expected_partial_pks = [
            "0xa99ccc28dec85022a6c812878b17d0ddf1d6b7e166e9f5776737baa1297dc548f2168a1616c9da66f2d108f246f40172136cef6fd68408be515ee2544619eef07a9eb1965207f019cf0f9e1bd5e6c74b09d9c0a2311f6b1c1b1db071f14190f3",
            "0x96896800af1d60489b01c784c6935c260e0e855879bd7bd1836608dafa969f6fe84f412e646dffc826529227bd0388a31713f382aec66924d1eada8a7eb33702300a5fd85d15e7ebed113a79a1cc4c61ee188d332bd3dc713b06b8044944d2af",
            "0x8ed8ac534f4991509b2fca4a6d99bc9239b8c6688bc80a4009f6db3a5c2d79129726ddae6f99c85109b8bfd91a9f9179184067a8b1b8652abd87c51a6681b32d562880db2a2db69b031c420e44f2f4dd01d7622227470cb324f0286c0a115cd3",
            "0x8538902206ff0227b235c9f3e2526f0692100e38a0bef4cc0e472f9e5e39095a529de5f181aecf9e59e1029b99bc1aab184e9239c7d3d0258dc3f51b3c9b577260f913a4ce5bb298877cdba2d89d81581ecfe80134b296a6bd6442a319621345",
        ];

        let (ks_obj_id, key_server_v2) =
            fetch_key_server_by_committee(&mut grpc_client, &committee_id)
                .await
                .unwrap();
        let partial_key_servers = to_partial_key_servers(&key_server_v2).await.unwrap();

        // Assert that the version field is 1.
        match key_server_v2.server_type {
            ServerType::Committee { version, .. } => {
                assert_eq!(version, 1, "Key server version should be 1 after rotation");
            }
            _ => panic!("KeyServer should be of type Committee"),
        }

        // Verify the key server object ID matches expected.
        assert_eq!(
            ks_obj_id, expected_key_server,
            "Key server address should match"
        );

        for member in &committee.members {
            let partial_key_server_info = partial_key_servers.get(member).unwrap();

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
