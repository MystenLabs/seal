// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! gRPC utilities for interacting with Sui blockchain.

use anyhow::{anyhow, Result};
use sui_rpc::client::v2::Client;
use sui_sdk_types::Address;

use crate::seal_move_types::SealCommittee;

/// Create gRPC client for a given network.
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
    Ok(bcs::from_bytes(move_object.contents())?)
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
            Address::from_str("0xaa2e3cc1637ec725f3e4633f253d24e6f000f2c4a4c110f6c0bc38df1355b034")
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
            assert!(*enc_pk == bcs::from_bytes(&Hex::decode("0xa528d09bb6d99f29d954e2683235a52b03dd0a6f4440454074b12b169a08f4d0b72bcfb65ab3f082784ddb9bc778c9ec17e72c2c738e8f1d971987ba6db21de210d9a31a5cc8871e6229b4be18aa86876b382ab0f61f288bff8d0b6b4a51ba70").unwrap()).unwrap());
            assert!(*signing_pk == bcs::from_bytes(&Hex::decode("0xb4899c7fd9ac4d17938e61bf645168ceb005e2b1d1a77847a27ae1a4a8132a91e2e59ff705b5eb74eaa1181c30872ac011e18349766f46dcc6ecf00967eb7307d883331876362b323084d8a5b4f2f8a4abeb507e867bd3044a9e402c33a58226").unwrap()).unwrap());
        }
    }
}
