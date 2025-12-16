// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Aggregator server for Seal committee mode. It fetches encrypted partial keys from committee
//! servers, verifies and aggregates them into a single response and propagates the majority error
//! if threshold is not achieved.

mod errors;

use aggregator_server::{aggregate_verified_encrypted_responses, verify_decryption_keys};
use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use errors::InternalError;
use futures::stream::{FuturesUnordered, StreamExt};
use mysten_service::{get_mysten_service, package_name, package_version};
use seal_committee::{
    fetch_key_server_by_id,
    grpc_helper::create_grpc_client,
    move_types::{PartialKeyServer, VecMap},
    ErrorResponse, Network,
};
use seal_sdk::{FetchKeyRequest, FetchKeyResponse};
use semver::Version;
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use sui_rpc::client::Client as SuiGrpcClient;
use sui_sdk_types::Address;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};

/// Default port for aggregator server.
const DEFAULT_PORT: u16 = 2024;

/// Interval (in seconds) to refresh committee version from onchain.
const REFRESH_INTERVAL_SECS: u64 = 30;

/// Configuration for aggregator server.
#[derive(Deserialize)]
struct Config {
    network: Network,
    key_server_object_id: Address,
}

/// Application state.
#[derive(Clone)]
struct AppState {
    key_server_object_id: Address,
    grpc_client: SuiGrpcClient,
    threshold: u16,
    committee_members: Arc<RwLock<VecMap<Address, PartialKeyServer>>>,
    // TODO: API storage and rotation.
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Load configuration from file.
    let config_path =
        env::var("CONFIG_PATH").context("CONFIG_PATH environment variable not set")?;
    info!("Loading config file: {}", config_path);

    let config: Config = serde_yaml::from_reader(
        std::fs::File::open(&config_path)
            .context(format!("Cannot open configuration file {config_path}"))?,
    )
    .context("Failed to parse configuration file")?;

    info!(
        "Starting aggregator for KeyServer {} on {:?}",
        config.key_server_object_id, config.network
    );

    let state = load_committee_state(&config.key_server_object_id, config.network).await?;

    // Spawn background task to monitor committee member updates.
    {
        let state_clone = state.clone();
        tokio::spawn(async move {
            monitor_members_update(state_clone).await;
        });
    }

    info!(
        "Loaded committee with {} members, threshold {}",
        state.committee_members.read().await.0.contents.len(),
        state.threshold
    );

    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| DEFAULT_PORT.to_string())
        .parse()
        .context("Invalid PORT")?;

    let app = get_mysten_service::<AppState>(package_name!(), package_version!())
        .merge(
            Router::new()
                .route("/v1/fetch_key", post(handle_fetch_key))
                .route("/v1/service", get(handle_get_service)),
        )
        .with_state(state)
        .layer(CorsLayer::new().allow_origin(Any));

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Aggregator server listening on http://localhost:{}", port);

    axum::serve(listener, app).await?;
    Ok(())
}

/// get_service not supported for aggregator server.
async fn handle_get_service() -> Response {
    (StatusCode::FORBIDDEN, "Unsupported").into_response()
}

/// Handle fetch_key request by fanning out to committee members and returns the aggregated
/// responses if threshold is achieved. Otherwise, propagates the majority error from key servers.
async fn handle_fetch_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<FetchKeyRequest>,
) -> Result<(HeaderMap, Json<FetchKeyResponse>), ErrorResponse> {
    // Extract client SDK headers to forward to committee members.
    let client_sdk_type = headers
        .get("Client-Sdk-Type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let client_sdk_version = headers
        .get("Client-Sdk-Version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    // Call to committee members' servers in parallel.
    let mut fetch_tasks: FuturesUnordered<_> = state
        .committee_members
        .read()
        .await
        .0
        .contents
        .iter()
        .map(|member| {
            let request = request.clone();
            let partial_key_server = member.clone().value;
            let client_sdk_type = client_sdk_type.to_string();
            let client_sdk_version = client_sdk_version.to_string();
            async move {
                match fetch_from_member(
                    &partial_key_server,
                    &request,
                    &client_sdk_type,
                    &client_sdk_version,
                )
                .await
                {
                    Ok((response, server_version)) => {
                        Ok((partial_key_server.party_id, response, server_version))
                    }
                    Err(e) => {
                        warn!(
                            "Failed to fetch from party_id={}, url={}: {:?}",
                            partial_key_server.party_id, partial_key_server.url, e
                        );
                        Err(e)
                    }
                }
            }
        })
        .collect();

    // Collect responses until we have threshold, then abort remaining.
    let mut responses = Vec::new();
    let mut server_versions = Vec::new();
    let mut errors = Vec::new();
    while let Some(result) = fetch_tasks.next().await {
        match result {
            Ok((party_id, response, server_version)) => {
                responses.push((party_id, response));
                server_versions.push(server_version);
                if responses.len() >= state.threshold as usize {
                    break;
                }
            }
            Err(e) => {
                errors.push(e);
            }
        }
    }

    info!("Collected {} responses", responses.len());

    // If not enough responses, return majority error from key servers.
    if responses.len() < state.threshold as usize {
        error!(
            "Insufficient responses: got {}, need {}. Errors: {:?}",
            responses.len(),
            state.threshold,
            errors
        );

        // Find majority error by error type.
        if !errors.is_empty() {
            let mut error_counts = HashMap::new();
            for err in errors {
                error_counts
                    .entry(err.error.clone())
                    .and_modify(|(count, _)| *count += 1)
                    .or_insert((1, err));
            }

            if let Some((_, (_, majority_error))) =
                error_counts.iter().max_by_key(|(_, (count, _))| count)
            {
                return Err(majority_error.clone());
            }
        }

        // If errors is empty but still insufficient responses, return generic error.
        return Err(ErrorResponse::from(InternalError::InsufficientResponses(
            responses.len(),
            state.threshold as usize,
        )));
    }

    // Get the oldest version for all committee servers' responses and use it for the aggregator
    // response header.
    let min_version = server_versions
        .iter()
        .filter_map(|v| Version::parse(v).ok())
        .min()
        .map(|v| v.to_string())
        .unwrap_or_default();
    info!("Oldest key server version: {}", min_version);

    let mut headers = HeaderMap::new();
    headers.insert("X-KeyServer-Version", min_version.parse().unwrap());

    // Aggregate encrypted responses and return.
    match aggregate_verified_encrypted_responses(state.threshold, responses) {
        Ok(aggregated_response) => Ok((headers, Json(aggregated_response))),
        Err(e) => {
            error!("Aggregating responses failed: {e}");
            Err(ErrorResponse::from(InternalError::AggregationFailed(
                e.to_string(),
            )))
        }
    }
}

/// Fetch encrypted partial key from a single committee member.
async fn fetch_from_member(
    member: &PartialKeyServer,
    request: &FetchKeyRequest,
    client_sdk_type: &str,
    client_sdk_version: &str,
) -> Result<(FetchKeyResponse, String), ErrorResponse> {
    info!("Fetching from party {} at {}", member.party_id, member.url);

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/v1/fetch_key", member.url))
        .header("Client-Sdk-Type", client_sdk_type)
        .header("Client-Sdk-Version", client_sdk_version)
        .header("Content-Type", "application/json")
        .body(request.to_json_string().expect("should not fail"))
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| ErrorResponse::from(InternalError::RequestFailed(e.to_string())))?;

    // Extract version header.
    let version_str = response
        .headers()
        .get("X-KeyServer-Version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();

    // If response is not successful, try to parse error response from key server
    let status = response.status();
    if !status.is_success() {
        if let Ok(error_response) = response.json::<ErrorResponse>().await {
            return Err(error_response);
        } else {
            return Err(ErrorResponse::from(InternalError::HttpError(status)));
        }
    }

    let mut body = response
        .json::<FetchKeyResponse>()
        .await
        .map_err(|e| ErrorResponse::from(InternalError::ParseFailed(e.to_string())))?;

    // Verify each decryption key.
    body.decryption_keys = verify_decryption_keys(
        &body.decryption_keys,
        &member.partial_pk,
        &request.enc_verification_key,
        member.party_id,
    )
    .map_err(|e| ErrorResponse::from(InternalError::VerificationFailed(e)))?;

    Ok((body, version_str))
}

/// Load committee state from onchain KeyServerV2 object.
async fn load_committee_state(key_server_obj_id: &Address, network: Network) -> Result<AppState> {
    let mut grpc_client = create_grpc_client(&network)?;
    let key_server_v2 = fetch_key_server_by_id(&mut grpc_client, key_server_obj_id).await?;
    let (threshold, members) = key_server_v2.extract_committee_info()?;

    Ok(AppState {
        key_server_object_id: *key_server_obj_id,
        grpc_client,
        committee_members: Arc::new(RwLock::new(members)),
        threshold,
    })
}

/// Background task that periodically refreshes committee members from onchain.
/// Polls every 30 seconds and updates the committee members.
async fn monitor_members_update(mut state: AppState) {
    let mut ticker = interval(Duration::from_secs(REFRESH_INTERVAL_SECS));

    loop {
        ticker.tick().await;

        // Fetch the current state from onchain.
        let (_, members) =
            match fetch_key_server_by_id(&mut state.grpc_client, &state.key_server_object_id)
                .await
                .and_then(|ks| ks.extract_committee_info())
            {
                Ok(info) => info,
                Err(e) => {
                    warn!("Failed to fetch/parse KeyServer: {}", e);
                    continue;
                }
            };

        // Always update committee members.
        *state.committee_members.write().await = members;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::elgamal::genkey;
    use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519Signature};
    use fastcrypto::groups::bls12381::G1Element;
    use fastcrypto::groups::{bls12381::G2Element, GroupElement};
    use fastcrypto::traits::{KeyPair, Signer, ToFromBytes};
    use rand::thread_rng;
    use seal_sdk::types::Certificate;
    use serde_json::json;
    use sui_sdk_types::UserSignature;
    use sui_types::collection_types::{Entry, VecMap as SuiVecMap};
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn test_majority_error_with_3_invalid_ptb_2_noaccess() {
        // Create 5 mock key servers.
        let mut mock_servers = vec![];

        // 3 servers return InvalidPTB.
        for _ in 0..3 {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/fetch_key"))
                .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                    "error": "InvalidPTB",
                    "message": "Invalid PTB: test error"
                })))
                .mount(&server)
                .await;
            mock_servers.push(server);
        }

        // 2 servers return NoAccess.
        for _ in 0..2 {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/fetch_key"))
                .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                    "error": "NoAccess",
                    "message": "Access denied"
                })))
                .mount(&server)
                .await;
            mock_servers.push(server);
        }

        // Create committee members for testing.
        let mut committee_contents = vec![];
        for (i, server) in mock_servers.iter().enumerate() {
            let address = Address::from([i as u8; 32]);
            let member = PartialKeyServer {
                party_id: i as u16,
                url: server.uri(),
                partial_pk: G2Element::zero(),
            };
            committee_contents.push(Entry {
                key: address,
                value: member,
            });
        }

        // Create AppState for testing.
        let grpc_client = create_grpc_client(&Network::Testnet).unwrap();
        let state = AppState {
            key_server_object_id: Address::from([0u8; 32]),
            grpc_client,
            threshold: 3,
            committee_members: Arc::new(RwLock::new(VecMap(SuiVecMap {
                contents: committee_contents,
            }))),
        };

        // Create a FetchKeyRequest for testing.
        let mut rng = thread_rng();
        let (_, enc_key, enc_verification_key) = genkey::<G1Element, G2Element, _>(&mut rng);
        let kp = Ed25519KeyPair::generate(&mut rng);
        let pk = kp.public().clone();
        let sig: Ed25519Signature = kp.sign(b"test");
        let mut user_sig_bytes = vec![0u8];
        user_sig_bytes.extend_from_slice(sig.as_bytes());
        user_sig_bytes.extend_from_slice(pk.as_bytes());

        let request = FetchKeyRequest {
            ptb: "{}".to_string(),
            enc_key,
            enc_verification_key,
            request_signature: sig,
            certificate: Certificate {
                user: Address::from([0u8; 32]),
                session_vk: pk,
                creation_time: 0,
                ttl_min: 60,
                mvr_name: None,
                signature: UserSignature::from_bytes(&user_sig_bytes).unwrap(),
            },
        };

        // Call handle_fetch_key and check majority error.
        let headers = HeaderMap::new();
        let result = handle_fetch_key(State(state), headers, Json(request)).await;
        match result {
            Err(error) => {
                assert_eq!(error.error, "InvalidPTB");
            }
            Ok(_) => panic!("Expected error but got success"),
        }
    }
}
