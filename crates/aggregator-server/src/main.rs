// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Aggregator server for Seal committee mode. It fetches encrypted partial keys from committee
//! servers, verifies and aggregates them into a single response.

#![allow(dead_code)]
#![allow(unused_variables)]

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use mysten_service::{get_mysten_service, package_name, package_version};
use seal_committee::{grpc_helper::create_grpc_client, move_types::PartialKeyServer, Network};
use seal_sdk::{FetchKeyRequest, FetchKeyResponse};
use serde::Deserialize;
use std::env;
use std::sync::Arc;
use sui_rpc::client::Client as SuiGrpcClient;
use sui_sdk_types::Address;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

/// Minimum required version for committee members' responses (matches typescript).
const MIN_SERVER_VERSION: &str = ">=0.4.1";

/// Default port for aggregator server.
const DEFAULT_PORT: u16 = 2024;

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
    network: Network,
    grpc_client: SuiGrpcClient,
    threshold: u16,
    committee_members: Arc<Vec<PartialKeyServer>>,
    // TODO: API storage and rotation.
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

    // Load configuration from file.
    let config_path =
        env::var("CONFIG_PATH").context("CONFIG_PATH environment variable not set")?;
    info!("Loading config file: {}", config_path);

    let config: Config = serde_yaml::from_reader(
        std::fs::File::open(&config_path)
            .context(format!("Cannot open configuration file {config_path}"))?,
    )
    .context("Failed to parse configuration file")?;
    let grpc_client = create_grpc_client(&config.network)?;

    info!(
        "Starting aggregator for KeyServer {} on {:?}",
        config.key_server_object_id, config.network
    );

    let state = AppState {
        key_server_object_id: config.key_server_object_id,
        network: config.network,
        grpc_client,
        threshold: 0,                        // TODO: Load from onchain
        committee_members: Arc::new(vec![]), // TODO: Load from onchain
    };

    // TODO: Spawn background task to watch onchain for committee version updates:
    // 1. Every 30s, fetch KeyServerV2.version from onchain
    // 2. If version changes, refresh committee_members in AppState
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

/// Handle fetch_key request by fanning out to committee members and aggregating responses.
async fn handle_fetch_key(
    State(state): State<AppState>,
    Json(request): Json<FetchKeyRequest>,
) -> Result<(HeaderMap, Json<FetchKeyResponse>), AggregatorError> {
    // TODO:
    // 1. Call fetch_from_member for all committee members in parallel.
    // 2. Collect responses until we have t successful responses and abort others.
    // 3. Track versions from each response header (X-KeyServer-Version). Use the oldest version as
    // the aggregator's response version (?)
    // 4. Upon sufficient responses, Aaggregate encrypted responses using crypto::elgamal::aggregate_encrypted
    // 5. Return with appropriate headers

    unimplemented!("depends on crypto code")
}

/// Fetch encrypted partial key from a single committee member.
async fn fetch_from_member(
    member: &PartialKeyServer,
    request: &FetchKeyRequest,
) -> Result<(FetchKeyResponse, String), String> {
    // TODO:
    // 1. Implement HTTP client call to each member URL.
    // 2. Extract each and validate X-KeyServer-Version header with MIN_SERVER_VERSION
    // 3. Parse response body as FetchKeyResponse
    // 4. Verify encrypted signatures using crypto::ibe::verify_encrypted_signature.
    // 5. Return (response, version_string)

    unimplemented!("not implemented yet")
}

/// Load committee state from onchain KeyServerV2 object.
async fn load_committee_state(key_server_obj_id: &Address, network: Network) -> Result<AppState> {
    // TODO:
    // 1. Fetch KeyServerV2 object from chain.
    // 2. Parse committee members and threshold.
    // 3. Return AppState with loaded data.

    unimplemented!("not implemented yet")
}
