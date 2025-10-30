// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! gRPC utilities for interacting with Sui blockchain.

use anyhow::{anyhow, Result};
use sui_rpc::client::v2::Client;
use sui_sdk_types::Address;

use crate::seal_move_types::SealCommittee;
use crate::types::Network;

/// Create gRPC client for a given network.
pub fn create_grpc_client(network: &Network) -> Result<Client> {
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
