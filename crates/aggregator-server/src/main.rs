// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Lightweight aggregator server for Seal committee mode.
//!
//! Coordinates between clients and MPC committee members by aggregating
//! encrypted partial keys into a single response.

use anyhow::{Context, Result};
use axum::{extract::State, routing::post, Json, Router};
use futures::stream::{FuturesUnordered, StreamExt};
use mysten_service::{get_mysten_service, package_name, package_version, serve};
use seal_committee::grpc_helper::{create_grpc_client, fetch_key_server_by_id};
use seal_committee::move_types::{PartialKeyServer, ServerType};
use seal_committee::Network;
use seal_sdk::{aggregate_encrypted_responses, FetchKeyRequest, FetchKeyResponse};
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use sui_sdk_types::Address;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};

/// Application state
#[derive(Clone)]
struct AppState {
    committee_members: Arc<Vec<PartialKeyServer>>,
    threshold: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let key_server_obj_id = Address::from_str(
        &env::var("KEY_SERVER_OBJ_ID").context("KEY_SERVER_OBJ_ID environment variable not set")?,
    )?;

    let network = Network::from_str(
        env::var("NETWORK")
            .context("NETWORK environment variable not set")?
            .as_str(),
    )
    .expect("Invalid network");

    info!(
        "Starting aggregator for KeyServer {} on {}",
        key_server_obj_id, network
    );

    let state = load_members(&key_server_obj_id, network).await?;

    // TODO: Add periodic refresh of committee members from onchain by watching version.
    info!(
        "Loaded committee with {} members, threshold {}",
        state.committee_members.len(),
        state.threshold
    );

    let app = get_mysten_service::<AppState>(package_name!(), package_version!())
        .merge(Router::new().route("/v1/fetch_key", post(handle_fetch_key)))
        .with_state(state)
        .layer(CorsLayer::new().allow_origin(Any));
    info!("Starting aggregator server");

    serve(app).await?;
    Ok(())
}

/// Hanldle fetch_key request by fanning out to committee members' servers and aggregating responses.
async fn handle_fetch_key(
    State(state): State<AppState>,
    Json(request): Json<FetchKeyRequest>,
) -> Json<FetchKeyResponse> {
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
                    Ok(response) => Ok((member.party_id, response)),
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
    while let Some(result) = fetch_tasks.next().await {
        if let Ok(response) = result {
            responses.push(response);
            if responses.len() >= state.threshold as usize {
                info!(
                    "Reached threshold ({} responses), aborting remaining requests",
                    responses.len()
                );
                break;
            }
        }
    }

    // Check if we have enough responses.
    if responses.len() < state.threshold as usize {
        error!(
            "Insufficient responses: got {}, need {}",
            responses.len(),
            state.threshold
        );
        // Return empty response on error.
        return Json(FetchKeyResponse {
            decryption_keys: vec![],
        });
    }

    info!("Collected {} responses", responses.len());

    // Aggregate encrypted responses and return.
    match aggregate_encrypted_responses(state.threshold, responses) {
        Ok(aggregated_response) => {
            info!("Successfully aggregated keys");
            Json(aggregated_response)
        }
        Err(e) => {
            error!("Aggregation failed: {}", e);
            Json(FetchKeyResponse {
                decryption_keys: vec![],
            })
        }
    }
}

/// Fetch encrypted partial key from a single committee member.
async fn fetch_from_member(
    member: &PartialKeyServer,
    request: &FetchKeyRequest,
) -> Result<FetchKeyResponse, String> {
    info!("Fetching from party {} at {}", member.party_id, member.url);

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/v1/fetch_key", member.url))
        .json(request)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }

    response
        .json::<FetchKeyResponse>()
        .await
        .map_err(|e| format!("Parse failed: {e}"))
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
