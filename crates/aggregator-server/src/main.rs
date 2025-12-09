// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Aggregator server for Seal committee mode. It fetches encrypted partial keys from committee
//! servers, verifies and aggregates them into a single response.

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use futures::stream::{FuturesUnordered, StreamExt};
use mysten_service::{get_mysten_service, package_name, package_version};
use seal_committee::grpc_helper::{create_grpc_client, fetch_key_server_by_id};
use seal_committee::move_types::{PartialKeyServer, ServerType};
use seal_committee::Network;
use seal_sdk::{
    aggregate_encrypted_responses, verify_decryption_keys, FetchKeyRequest, FetchKeyResponse,
};
use semver::{Version, VersionReq};
use serde::Deserialize;
use std::env;
use std::sync::Arc;
use sui_sdk_types::Address;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};

/// Minimum required version for committee members, from ts-sdks.
const MIN_SERVER_VERSION: &str = ">=0.4.1";
const DEFAULT_PORT: u16 = 2024;

#[derive(Deserialize, Debug)]
struct Config {
    network: Network,
    key_server_object_id: Address,
}

/// Application state.
#[derive(Clone)]
struct AppState {
    committee_members: Arc<Vec<PartialKeyServer>>,
    threshold: u16,
    // TODO: Handle API key storage and rotation.
}

/// Custom error type for aggregator responses.
struct AggregatorError {
    status: StatusCode,
    message: String,
    headers: HeaderMap,
}

impl IntoResponse for AggregatorError {
    fn into_response(self) -> Response {
        let mut response = (self.status, self.message).into_response();
        *response.headers_mut() = self.headers;
        response
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config_path =
        env::var("CONFIG_PATH").context("CONFIG_PATH environment variable not set")?;

    let config: Config = serde_yaml::from_reader(
        std::fs::File::open(&config_path)
            .context(format!("Cannot open configuration file {config_path}"))?,
    )?;

    info!("Starting aggregator with config: {:?}", config);

    let state = load_members(&config.key_server_object_id, config.network).await?;

    // TODO: Add periodic refresh of committee members from onchain by watching version.
    info!(
        "Loaded committee with {} members, threshold {}",
        state.committee_members.len(),
        state.threshold
    );

    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| DEFAULT_PORT.to_string())
        .parse()
        .context("Invalid PORT")?;

    let app = get_mysten_service::<AppState>(package_name!(), package_version!())
        .merge(Router::new().route("/v1/fetch_key", post(handle_fetch_key)))
        .with_state(state)
        .layer(CorsLayer::new().allow_origin(Any));

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Aggregator server listening on http://localhost:{}", port);

    axum::serve(listener, app).await?;
    Ok(())
}

/// Hanldle fetch_key request by fanning out to committee members' servers and aggregating responses.
async fn handle_fetch_key(
    State(state): State<AppState>,
    Json(request): Json<FetchKeyRequest>,
) -> Result<(HeaderMap, Json<FetchKeyResponse>), AggregatorError> {
    let num_members = state.committee_members.len();
    info!(
        "Fanning out to all {} members (need {} responses)",
        num_members, state.threshold
    );

    // Call to committee members' servers in parallel.
    let mut fetch_tasks: FuturesUnordered<_> = state
        .committee_members
        .iter()
        .map(|member| {
            let request = request.clone();
            let member = member.clone();
            async move {
                match fetch_from_member(&member, &request).await {
                    Ok((response, version)) => Ok((member.party_id, response, version)),
                    Err(e) => {
                        warn!("Failed to fetch from party {}: {}", member.party_id, e);
                        Err(e)
                    }
                }
            }
        })
        .collect();

    // Collect responses until we have threshold, then abort remaining.
    let mut responses: Vec<(u16, FetchKeyResponse)> = Vec::new();
    let mut versions: Vec<String> = Vec::new();
    while let Some(result) = fetch_tasks.next().await {
        if let Ok((party_id, response, version)) = result {
            responses.push((party_id, response));
            versions.push(version);
            if responses.len() >= state.threshold as usize {
                info!(
                    "Reached threshold ({} responses), aborting remaining requests",
                    responses.len()
                );
                break;
            }
        }
    }

    info!("Collected {} responses", responses.len());

    // Get the olest version for all committee servers' responses and use it for the aggregator
    // response header.
    let min_version = versions
        .iter()
        .filter_map(|v| semver::Version::parse(v).ok())
        .min()
        .map(|v| v.to_string())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    info!("Minimum committee version: {}", min_version);

    let mut headers = HeaderMap::new();
    headers.insert("X-KeyServer-Version", min_version.parse().unwrap());

    // Check if we have enough responses to meet threshold.
    if responses.len() < state.threshold as usize {
        let msg = format!(
            "Insufficient responses: got {}, need {}",
            responses.len(),
            state.threshold
        );
        error!("{}", msg);
        return Err(AggregatorError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: msg,
            headers,
        });
    }

    // Aggregate encrypted responses and return.
    match aggregate_encrypted_responses(state.threshold, responses) {
        Ok(aggregated_response) => {
            info!("Successfully aggregated keys");
            Ok((headers, Json(aggregated_response)))
        }
        Err(e) => {
            let msg = format!("Aggregation failed: {e}");
            error!("{msg}");
            Err(AggregatorError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: msg,
                headers,
            })
        }
    }
}

/// Fetch encrypted partial key from a single committee member.
async fn fetch_from_member(
    member: &PartialKeyServer,
    request: &FetchKeyRequest,
) -> Result<(FetchKeyResponse, String), String> {
    info!("Fetching from party {} at {}", member.party_id, member.url);

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/v1/fetch_key", member.url))
        .header("Client-Sdk-Type", "rust")
        .header("Client-Sdk-Version", env!("CARGO_PKG_VERSION"))
        .header("Content-Type", "application/json")
        .body(request.to_json_string().expect("should not fail"))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }

    // Extract version header and check minimum requirement.
    let version_str = response
        .headers()
        .get("X-KeyServer-Version")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| "Missing X-KeyServer-Version header".to_string())?;

    let version = Version::parse(version_str)
        .map_err(|e| format!("Invalid version format '{version_str}': {e}"))?;

    let version_req = VersionReq::parse(MIN_SERVER_VERSION)
        .expect("MIN_SERVER_VERSION must be valid semver requirement");

    if !version_req.matches(&version) {
        return Err(format!(
            "Committee member version {version} does not meet requirement {MIN_SERVER_VERSION}"
        ));
    }

    info!("Committee member version: {}", version);

    let mut body = response
        .json::<FetchKeyResponse>()
        .await
        .map_err(|e| format!("Parse failed: {e}"))?;

    // Verify encrypted signatures for each decryption key.
    body.decryption_keys = verify_decryption_keys(
        &body.decryption_keys,
        &member.partial_pk,
        &request.enc_verification_key,
        member.party_id,
    )?;

    Ok((body, version.to_string()))
}

/// Load member servers onchain for the give key server object.
async fn load_members(key_server_obj_id: &Address, network: Network) -> Result<AppState> {
    let mut grpc_client = create_grpc_client(&network)?;
    let key_server_v2 = fetch_key_server_by_id(&mut grpc_client, key_server_obj_id).await?;

    let (threshold, partial_key_servers) = match key_server_v2.server_type {
        ServerType::Committee {
            threshold,
            partial_key_servers,
            ..
        } => (threshold, partial_key_servers),
        ServerType::Independent { .. } => {
            anyhow::bail!("Invalid independent key server type.");
        }
    };
    let members: Vec<PartialKeyServer> = partial_key_servers
        .0
        .contents
        .into_iter()
        .map(|entry| entry.value)
        .collect();

    Ok(AppState {
        committee_members: Arc::new(members),
        threshold,
    })
}
