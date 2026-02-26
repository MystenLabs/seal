// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! gRPC utilities for interacting with Sui blockchain.

use crate::{
    move_types::{
        Field, KeyServerV2, PartialKeyServerInfo, SealCommittee, ServerType, UpgradeManager,
        UpgradeProposal, Wrapper,
    },
    Network,
};
use anyhow::{anyhow, bail, Result};
use sui_rpc::client::Client;
use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
use sui_sdk_types::{Address, Object, StructTag, TypeTag};

pub(crate) const EXPECTED_KEY_SERVER_VERSION: u64 = 2;

/// Key struct for accessing UpgradeManager in dynamic object fields.
/// Must match the Move struct definition in seal_committee.
#[derive(serde::Serialize, serde::Deserialize)]
struct UpgradeManagerKey {
    dummy_field: bool,
}

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
    let mut request = GetObjectRequest::default();
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

/// Fetch a field wrapper object and deserialize it.
async fn fetch_field_wrapper<T: serde::de::DeserializeOwned>(
    grpc_client: &mut Client,
    field_wrapper_id: &Address,
) -> Result<T> {
    let mut ledger_client = grpc_client.ledger_client();
    let mut fw_request = GetObjectRequest::default();
    fw_request.object_id = Some(field_wrapper_id.to_string());
    fw_request.read_mask = Some(prost_types::FieldMask {
        paths: vec!["bcs".to_string()],
    });

    let fw_response = ledger_client
        .get_object(fw_request)
        .await
        .map(|r| r.into_inner());

    let fw_bcs = match fw_response {
        Ok(response) => response
            .object
            .and_then(|obj| obj.bcs)
            .and_then(|bcs| bcs.value)
            .ok_or_else(|| anyhow!("Field wrapper object not found"))?,
        Err(e) => return Err(anyhow!("Failed to fetch field wrapper: {}", e)),
    };

    let fw_object: Object = bcs::from_bytes(&fw_bcs)?;
    let fw_struct = fw_object
        .as_struct()
        .ok_or_else(|| anyhow!("Field wrapper is not a Move struct"))?;

    let field_wrapper: T = bcs::from_bytes(fw_struct.contents())?;
    Ok(field_wrapper)
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
        fetch_field_wrapper(grpc_client, &field_wrapper_id).await?;
    let ks_obj_id = field_wrapper.value;

    let key_server_v2 = fetch_key_server_by_id(grpc_client, &ks_obj_id).await?;

    Ok((ks_obj_id, key_server_v2))
}

/// Fetch partial key server information for a specific committee member from onchain KeyServer object.
/// Returns the PartialKeyServerInfo for the specified member address.
pub async fn get_partial_key_server_for_member(
    grpc_client: &mut Client,
    key_server_obj_id: &Address,
    committee_id: &Address,
    member_address: &Address,
) -> Result<PartialKeyServerInfo> {
    let ks = fetch_key_server_by_id(grpc_client, key_server_obj_id).await?;
    let committee = fetch_committee_data(grpc_client, committee_id).await?;
    let partial_key_servers = ks.to_partial_key_servers(&committee.members)?;

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

/// Fetch committee ID and package ID from a key server object ID.
/// Returns (committee_id, package_id).
pub async fn fetch_committee_from_key_server(
    grpc_client: &mut Client,
    key_server_obj_id: &Address,
) -> Result<(Address, sui_types::base_types::ObjectID)> {
    use std::str::FromStr;
    use sui_types::base_types::ObjectID;

    // Fetch key server object to get owner (field wrapper).
    let field_wrapper_id = {
        let mut ledger_client = grpc_client.ledger_client();
        let mut ks_request = GetObjectRequest::default();
        ks_request.object_id = Some(key_server_obj_id.to_string());
        ks_request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["owner".to_string()],
        });

        let ks_response = ledger_client
            .get_object(ks_request)
            .await
            .map(|r| r.into_inner())?;

        let ks_object = ks_response
            .object
            .ok_or_else(|| anyhow!("Key server object not found"))?;

        // Parse owner to get field wrapper ID.
        let owner_data = ks_object
            .owner
            .ok_or_else(|| anyhow!("Key server object has no owner"))?;

        let owner_address = owner_data
            .address
            .ok_or_else(|| anyhow!("Owner has no address"))?;

        Address::from_str(&owner_address)?
    };

    // Fetch field wrapper to extract committee ID.
    let field: Field<Wrapper<Address>, Address> =
        fetch_field_wrapper(grpc_client, &field_wrapper_id).await?;
    let committee_id = field.name.name;

    // Fetch committee object to get the correct package ID.
    let mut ledger_client = grpc_client.ledger_client();
    let mut committee_request = GetObjectRequest::default();
    committee_request.object_id = Some(committee_id.to_string());
    committee_request.read_mask = Some(prost_types::FieldMask {
        paths: vec!["object_type".to_string()],
    });

    let committee_response = ledger_client
        .get_object(committee_request)
        .await
        .map(|r| r.into_inner())?;

    let committee_object = committee_response
        .object
        .ok_or_else(|| anyhow!("Committee object not found"))?;

    let committee_type = committee_object
        .object_type
        .ok_or_else(|| anyhow!("Committee has no type"))?;

    let committee_struct_tag = StructTag::from_str(&committee_type)?;
    let package_id = ObjectID::new(committee_struct_tag.address().into_inner());

    Ok((committee_id, package_id))
}

/// Fetch upgrade proposal from the committee's UpgradeManager DOF.
/// Returns None if there is no active proposal.
pub async fn fetch_upgrade_proposal(
    grpc_client: &mut Client,
    committee_id: &Address,
) -> Result<Option<UpgradeProposal>> {
    let upgrade_manager = fetch_upgrade_manager(grpc_client, committee_id).await?;
    Ok(upgrade_manager.upgrade_proposal)
}

/// Fetch the full UpgradeManager from the committee's UpgradeManager DOF.
pub async fn fetch_upgrade_manager(
    grpc_client: &mut Client,
    committee_id: &Address,
) -> Result<UpgradeManager> {
    use std::str::FromStr;

    // First, we need to get the committee package address to construct the correct type tag.
    let mut ledger_client = grpc_client.ledger_client();
    let mut committee_request = GetObjectRequest::default();
    committee_request.object_id = Some(committee_id.to_string());
    committee_request.read_mask = Some(prost_types::FieldMask {
        paths: vec!["object_type".to_string()],
    });

    let committee_response = ledger_client
        .get_object(committee_request)
        .await
        .map(|r| r.into_inner())?;

    let object_type = committee_response
        .object
        .and_then(|obj| obj.object_type)
        .ok_or_else(|| anyhow!("Committee object has no type"))?;

    let struct_tag = StructTag::from_str(&object_type)?;
    let committee_pkg_addr = struct_tag.address();

    let wrapper_key = Wrapper {
        name: UpgradeManagerKey { dummy_field: false },
    };
    let wrapper_key_bcs = bcs::to_bytes(&wrapper_key)?;

    // The type tag for Wrapper<UpgradeManagerKey>.
    let wrapper_type_tag = TypeTag::Struct(Box::new(StructTag::new(
        Address::TWO,
        "dynamic_object_field".parse().unwrap(),
        "Wrapper".parse().unwrap(),
        vec![TypeTag::Struct(Box::new(StructTag::new(
            *committee_pkg_addr,
            "seal_committee".parse().unwrap(),
            "UpgradeManagerKey".parse().unwrap(),
            vec![],
        )))],
    )));

    // Derive the field wrapper ID for UpgradeManager.
    let field_wrapper_id =
        committee_id.derive_dynamic_child_id(&wrapper_type_tag, &wrapper_key_bcs);

    // Fetch field wrapper.
    let field_wrapper: crate::move_types::FieldWrapper<UpgradeManagerKey, Address> =
        fetch_field_wrapper(grpc_client, &field_wrapper_id).await?;
    let upgrade_manager_id = field_wrapper.value;

    // Fetch the UpgradeManager object.
    let upgrade_manager: UpgradeManager =
        fetch_and_deserialize_move_object(grpc_client, &upgrade_manager_id, "UpgradeManager")
            .await?;

    Ok(upgrade_manager)
}

/// Get next committee version and key server pk if exists. For fresh DKG, the next version is 0,
/// old pk is None. For rotation, the next version is the old committee's KeyServer version + 1.
/// Old pk is returned as Some from the key server object.
pub async fn get_committee_rotation_info(
    grpc_client: &mut Client,
    committee_id: &Address,
) -> Result<(u32, Option<Vec<u8>>)> {
    let committee = fetch_committee_data(grpc_client, committee_id).await?;

    if let Some(old_committee_id) = committee.old_committee_id {
        // Rotation: fetch the old committee's KeyServer version then increment by 1.
        match fetch_key_server_by_committee(grpc_client, &old_committee_id).await {
            Ok((_, key_server_v2)) => {
                let pk = key_server_v2.pk;
                match key_server_v2.server_type {
                    ServerType::Committee { version, .. } => {
                        println!(
                            "Old committee version: {}, new version will be: {}",
                            version,
                            version + 1
                        );
                        Ok((version + 1, Some(pk)))
                    }
                    _ => bail!("Old KeyServer is not of type Committee"),
                }
            }
            Err(e) => {
                bail!(
                    "Failed to fetch old committee's KeyServer for rotation: {}",
                    e
                );
            }
        }
    } else {
        Ok((0, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ParsedMemberInfo;
    use fastcrypto::bls12381::min_sig::BLS12381PublicKey;
    use fastcrypto::encoding::{Encoding, Hex};
    use fastcrypto::groups::bls12381::{G1Element, G2Element};
    use fastcrypto_tbls::ecies_v1::PublicKey;
    use std::str::FromStr;

    /// Helper to deserialize from hex string.
    fn from_hex_bcs<T: serde::de::DeserializeOwned>(hex_str: &str) -> T {
        let bytes = Hex::decode(hex_str).unwrap();
        bcs::from_bytes(&bytes).unwrap()
    }

    #[tokio::test]
    async fn test_fetch_committee_members() {
        // Test committee object on testnet in Init state with G1Element encryption keys (48 bytes each).
        let committee_id =
            Address::from_str("0x3c9e055bb08775441a3d1a3c834b2b01f1029e4a0c0ba0158dd5d7b5d562cf1d")
                .unwrap();

        let mut grpc_client = create_grpc_client(&Network::Testnet).unwrap();
        let committee = fetch_committee_data(&mut grpc_client, &committee_id)
            .await
            .unwrap();
        let members_info = committee.get_members_info().unwrap();

        let addresses = [
            Address::from_str("0x0ceffe3ba385abe7a11f535e3428ae2ff4508eb4b6d370b829318b0d901c1152")
                .unwrap(),
            Address::from_str("0x15ef03731c612580a2c604696da996641d0426c80a202b92f97beb7e55ceccae")
                .unwrap(),
            Address::from_str("0xef91ea73b4423e3a6176b0a1c9c6e4619de45c9c4e7c0b4aae358e292707d8c2")
                .unwrap(),
        ];

        // G1Element encryption public keys (48 bytes each)
        let expected_enc_pks = [
            from_hex_bcs::<PublicKey<G1Element>>("0x8730386961c9a2cb20e85a4c25f334481eb96a2e85df4c3ea0052aceeffa5d5c4ea5293bfd9b653f358e662c38e4e141"),
            from_hex_bcs::<PublicKey<G1Element>>("0xa67011cc8940b3fb55f95a5ece7755d27e83340f71f5cc54c11e63853fa4c1bc90096993b0b9c2e98f21d49fcb700066"),
            from_hex_bcs::<PublicKey<G1Element>>("0x8978be47813d6f4d243c024636d2d432655703b57511f36a3fa3eaa310a9f51ac7e3ec10b2748c8527a8a75da4582ff3"),
        ];
        // G2Element signing public keys (96 bytes each)
        let expected_signing_pks = [
            from_hex_bcs::<BLS12381PublicKey>("0x8e24bb14e03a5089a58883beae33c4290f7946d1f49ecaa71d201c03ba735797310489dadaac0a2f5ff81962e6c8a5ac06f57b48e4645859bea3b3b7675bfbae002d8f8d588e0ea7a36a1b4e55e0721f3fe7e41a01b2807b6c9b7471d0f2c024"),
            from_hex_bcs::<BLS12381PublicKey>("0x9253b1638d92f3c58193d35fa8a4f61e22d419f50b10abbc60448862c2c5100c720183f64ca67a01cca89fbaec3948540c6d99dd4e34cb3e710d1df7eaaa2183f1cc0974d451d6feaf1ae71dbb7280dc1626e72f0163e7d7a4f43fa2a2ad713a"),
            from_hex_bcs::<BLS12381PublicKey>("0x8f4b8feb60373e4f220512af981da323f85d2851339aec1f3f372bb5a2d31f5f971261b0db62f5fa70a09110ec66aefd06f1ee42536b577ff883a4eba3e70b6183fad1ddd16189ebdb3dafa607684ef75bfc09b10eddf73ca7b854277512b596"),
        ];

        for ParsedMemberInfo {
            name,
            party_id,
            address,
            enc_pk,
            signing_pk,
        } in members_info.values()
        {
            assert_eq!(name, &format!("server-ci-{}", party_id));
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
            Address::from_str("0x400b8e7f1ae460a2b2fd40426db7e1ba66ac76d0c8b0c8344a44d7134e189039")
                .unwrap();

        // Create gRPC client.
        let mut grpc_client = Client::new(Client::TESTNET_FULLNODE).unwrap();

        // Fetch committee data to get member addresses.
        let committee = fetch_committee_data(&mut grpc_client, &committee_id)
            .await
            .unwrap();

        // Expected values for rotated committee (4 parties, version 1).
        let expected_key_server =
            Address::from_str("0xa8bfdab21c38ed39fb0b0c839878186044cd5d64662d8cd9722ef288e1a64b73")
                .unwrap();
        let expected_partial_pks = [
            "0xaa67c0a82c48fe46203c73e88337113178e2e6728925bd605cd7a9daaf5a94ad2a6031edbb532898f7aec8a1d05c464a0e5fc4dc178eb4d6ffb8f3654b92d23d46845271d55ca9b161de071c0b9ffda2c8cea2588f11b8a38790591231b0125b",
            "0xb2d22b59d3d1b88d4c41980cbbbf3e744d2154db6c9a67d5ac9d12545953f17dcf30f1760c0c9bf901ba4a9e0585b468112215cac50fc276ccd11554588142bc51db7b1514a2b246c2a21f50c28808c4ae102ac90372098bb980247f3c9d529b",
            "0xaa22fdfac657098037691488eb6331221f4be7a0c39cca4c3e06aee876978beecdf9f83fee4cc98dc089f6bb5ab71c680df7dc8aaa7d8b5ec04328790972c077725789081073e2cc35dcf68cbca5189f191554fba8e94b5dba6cca3c64542871"
        ];

        let (ks_obj_id, key_server_v2) =
            fetch_key_server_by_committee(&mut grpc_client, &committee_id)
                .await
                .unwrap();
        let partial_key_servers = key_server_v2
            .to_partial_key_servers(&committee.members)
            .unwrap();

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
