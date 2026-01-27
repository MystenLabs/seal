// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::aggregator::KEY_SERVER_REQUEST_TIMEOUT_SECS;
use crate::common::{HEADER_KEYSERVER_GIT_VERSION, HEADER_KEYSERVER_VERSION};
use crate::errors::{ErrorResponse, InternalError};
use axum::http::HeaderValue;
use crypto::{elgamal, ibe::verify_encrypted_signature, DST_POP};
use fastcrypto::{
    encoding::{Base64, Encoding, Hex},
    error::FastCryptoError::InvalidInput,
    error::FastCryptoResult,
    groups::{
        bls12381::{G1Element, G2Element},
        GroupElement, HashToGroupElement, Pairing,
    },
};
use mysten_service::package_version;
use seal_committee::move_types::PartialKeyServer;
use seal_sdk::{
    types::{DecryptionKey, ElgamalVerificationKey},
    FetchKeyResponse,
};
use semver::{Version, VersionReq};
use serde::Deserialize;
use std::collections::HashMap;
use sui_sdk_types::Address;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Given a list of fetch key responses of servers: (party id, list of (key_id, encrypted_key)),
/// aggregate encrypted keys of all parties for each key id and return a list of aggregated
/// encrypted keys.
pub fn aggregate_verified_encrypted_responses(
    threshold: u16,
    responses: Vec<(u16, FetchKeyResponse)>, // (party_id, response)
) -> FastCryptoResult<FetchKeyResponse> {
    // Build map: key_id -> Vec<(party_id, encrypted_key)>.
    let mut shares_by_key_id: HashMap<Vec<u8>, Vec<(u16, elgamal::Encryption<_>)>> = HashMap::new();

    for (party_id, response) in responses {
        for dk in response.decryption_keys {
            shares_by_key_id
                .entry(dk.id)
                .or_default()
                .push((party_id, dk.encrypted_key));
        }
    }

    let mut decryption_keys = Vec::with_capacity(shares_by_key_id.len());
    for (key_id, encrypted_shares) in shares_by_key_id {
        let aggregated_encrypted = elgamal::aggregate_encrypted(threshold, &encrypted_shares)?;
        decryption_keys.push(DecryptionKey {
            id: key_id,
            encrypted_key: aggregated_encrypted,
        });
    }

    Ok(FetchKeyResponse { decryption_keys })
}

/// Verify decryption keys for one party. Returns error if any key fails verification.
pub fn verify_decryption_keys(
    decryption_keys: &[DecryptionKey],
    partial_pk: &G2Element,
    ephemeral_vk: &ElgamalVerificationKey,
    party_id: u16,
) -> Result<Vec<DecryptionKey>, String> {
    let mut verified_keys = Vec::with_capacity(decryption_keys.len());

    for dk in decryption_keys {
        verify_encrypted_signature(&dk.encrypted_key, ephemeral_vk, partial_pk, &dk.id).map_err(
            |e| {
                format!(
                    "Verification failed for party {} key_id={}: {}",
                    party_id,
                    Hex::encode(&dk.id),
                    e
                )
            },
        )?;
        verified_keys.push(dk.clone());
    }

    info!(
        "Verified all {} decryption keys from party {}",
        decryption_keys.len(),
        party_id
    );

    Ok(verified_keys)
}

/// Validate key server version from response header against the configured version requirement.
pub fn validate_key_server_version(
    version: Option<&HeaderValue>,
    ks_version_req: &VersionReq,
) -> Result<(), InternalError> {
    let version = version
        .ok_or(InternalError::MissingRequiredHeader(
            HEADER_KEYSERVER_VERSION.to_string(),
        ))
        .and_then(|v| {
            v.to_str().map_err(|_| {
                let msg = "Invalid key server version header".to_string();
                warn!("{}", msg);
                InternalError::Failure(msg)
            })
        })
        .and_then(|v| {
            Version::parse(v).map_err(|_| {
                let msg = format!("Failed to parse key server version: {}", v);
                warn!("{}", msg);
                InternalError::Failure(msg)
            })
        })?;

    if !ks_version_req.matches(&version) {
        let msg = format!(
            "Key server version {} does not meet requirement {}",
            version, ks_version_req
        );
        warn!("{}", msg);
        Err(InternalError::Failure(msg))
    } else {
        Ok(())
    }
}

/// Response from the /v1/service endpoint.
#[derive(Deserialize, Debug)]
struct ServiceResponse {
    service_id: String,
    pop: String, // Base64 encoded G1Element
}

/// Verify that a proof-of-possession is valid for a given public key, key server object ID, and party ID.
fn verify_pop(
    pop: &G1Element,
    key_server_obj_id: &Address,
    party_id: u16,
    public_key: &G2Element,
) -> FastCryptoResult<()> {
    // Construct the PoP message: key_server_obj_id || party_id
    let mut pop_message = Vec::new();
    pop_message.extend_from_slice(key_server_obj_id.as_ref());
    pop_message.extend_from_slice(&party_id.to_le_bytes());

    // Reconstruct the full message that was signed
    let mut full_msg = DST_POP.to_vec();
    full_msg.extend(bcs::to_bytes(public_key).map_err(|_| InvalidInput)?);
    full_msg.extend(pop_message);

    // Verify pairing.
    if pop.pairing(&G2Element::generator())
        == G1Element::hash_to_group_element(&full_msg).pairing(public_key)
    {
        Ok(())
    } else {
        Err(InvalidInput)
    }
}

/// Verify a partial key server by calling its /service endpoint and verifying the PoP signature.
/// Requires API credentials - caller should check for their existence before calling.
pub async fn verify_partial_key_server(
    server: &PartialKeyServer,
    key_server_object_id: &Address,
    key_server_version_requirement: &VersionReq,
    api_key_name: &str,
    api_key: &str,
) -> Result<(), String> {
    let url = format!(
        "{}/v1/service?service_id={}",
        server.url, key_server_object_id
    );
    debug!(
        "Verifying partial key server '{}' at url={}",
        server.name, url
    );

    let client = reqwest::Client::new();
    let request_id = Uuid::new_v4().to_string();
    let request = client
        .get(&url)
        .header("Content-Type", "application/json")
        .header("Request-Id", request_id)
        .header("Client-Sdk-Type", "aggregator")
        .header("Client-Sdk-Version", package_version!())
        .header(api_key_name, api_key)
        .timeout(std::time::Duration::from_secs(
            KEY_SERVER_REQUEST_TIMEOUT_SECS,
        ));

    // Send request
    let response = request
        .send()
        .await
        .map_err(|e| format!("Failed to fetch service info from '{}': {}", server.name, e))?;

    // Check HTTP status
    if !response.status().is_success() {
        return Err(format!(
            "Service endpoint returned HTTP {} for '{}'",
            response.status(),
            server.name
        ));
    }

    // Validate key server version from response headers
    let version_header = response.headers().get(HEADER_KEYSERVER_VERSION);
    let git_version_header = response.headers().get(HEADER_KEYSERVER_GIT_VERSION);

    debug!(
        "Get service response from server '{}' version={:?}, git_version={:?}",
        server.name, version_header, git_version_header
    );

    validate_key_server_version(version_header, key_server_version_requirement).map_err(|e| {
        let error_response = ErrorResponse::from(e);
        format!(
            "Version validation failed for '{}': {}",
            server.name, error_response.message
        )
    })?;

    // Parse response body
    let service_response: ServiceResponse = response.json().await.map_err(|e| {
        format!(
            "Failed to parse service response from '{}': {}",
            server.name, e
        )
    })?;

    // Verify service_id matches
    let expected_service_id = format!("0x{}", hex::encode(key_server_object_id.as_ref() as &[u8]));
    if service_response.service_id != expected_service_id {
        return Err(format!(
            "Service ID mismatch for '{}': expected {}, got {}",
            server.name, expected_service_id, service_response.service_id
        ));
    }

    // Decode PoP from base64
    let pop_bytes = Base64::decode(&service_response.pop)
        .map_err(|e| format!("Failed to decode PoP for '{}': {}", server.name, e))?;

    let pop: G1Element = bcs::from_bytes(&pop_bytes)
        .map_err(|e| format!("Failed to parse PoP for '{}': {}", server.name, e))?;

    // Verify PoP signature
    verify_pop(
        &pop,
        key_server_object_id,
        server.party_id,
        &server.partial_pk,
    )
    .map_err(|e| {
        format!(
            "PoP verification failed for '{}' (party_id={}): {}",
            server.name, server.party_id, e
        )
    })?;

    info!(
        "Successfully verified partial key server '{}' (url={})",
        server.name, server.url
    );
    Ok(())
}
