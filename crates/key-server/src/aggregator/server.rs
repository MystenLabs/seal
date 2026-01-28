// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Aggregator server for Seal committee mode. It fetches encrypted partial keys from committee
//! servers, verifies and aggregates them into a single response if threshold is achieved, or
//! propagates the majority error otherwise.

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::{self, map_response},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures::future::pending;
use futures::stream::{FuturesUnordered, StreamExt};
use key_server::aggregator::utils::{
    aggregate_verified_encrypted_responses, verify_decryption_keys,
};
use key_server::common::{
    add_response_headers, ClientSdkType, Network, NetworkConfig, HEADER_CLIENT_SDK_TYPE,
    HEADER_CLIENT_SDK_VERSION, HEADER_KEYSERVER_GIT_VERSION, HEADER_KEYSERVER_VERSION,
    SDK_TYPE_AGGREGATOR,
};
use key_server::errors::InternalError::{
    DeprecatedSDKVersion, InvalidSDKType, InvalidSDKVersion, MissingRequiredHeader,
};
use key_server::errors::{ErrorResponse, InternalError};
use key_server::metrics::{aggregator_metrics_middleware, uptime_metric, AggregatorMetrics};
use key_server::metrics_push::{create_push_client, push_metrics, MetricsPushConfig};
use mysten_service::{get_mysten_service, package_name, package_version};
use prometheus::Registry;
use seal_committee::{
    fetch_key_server_by_id,
    move_types::{PartialKeyServer, VecMap},
};
use seal_sdk::{FetchKeyRequest, FetchKeyResponse};
use semver::{Version, VersionReq};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::env;
use std::sync::Arc;
use sui_rpc::client::Client as SuiGrpcClient;
use sui_sdk_types::Address;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration};
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, info, warn};
/// Default port for aggregator server.
const DEFAULT_PORT: u16 = 2024;

/// Git version of the aggregator server.
const GIT_VERSION: &str = key_server::git_version!();

/// Interval seconds to refresh committee members.
const REFRESH_INTERVAL_SECS: u64 = 30;

/// Default SDK version requirement.
fn default_ts_sdk_version_requirement() -> VersionReq {
    // TODO: Update on first aggregator compatible SDK release.
    VersionReq::parse(">=1000.0.0").expect("Failed to parse default SDK version requirement")
}

/// Default key server version requirement.
fn default_key_server_version_requirement() -> VersionReq {
    VersionReq::parse(">=0.5.14").expect("Failed to parse default key server version requirement")
}

/// API credentials for a key server.
#[derive(Clone, Deserialize, Debug)]
struct ApiCredentials {
    api_key_name: String,
    api_key: String,
}

/// Configuration file format for aggregator server.
#[derive(Debug, Clone, Deserialize)]
struct AggregatorOptions {
    /// The network this aggregator is running on.
    network: Network,

    /// A custom node URL. If not set, the default for the given network is used.
    node_url: Option<String>,

    key_server_object_id: Address,

    /// The minimum version of the SDK that is required to use this aggregator.
    #[serde(default = "default_ts_sdk_version_requirement")]
    ts_sdk_version_requirement: VersionReq,

    /// The minimum version of the key server that is required by this aggregator.
    #[serde(default = "default_key_server_version_requirement")]
    key_server_version_requirement: VersionReq,

    /// API credentials mapped by key server name.
    /// Each key server's registered PartialKeyServer.name maps to its API credentials.
    #[serde(default)]
    api_credentials: HashMap<String, ApiCredentials>,

    /// Optional metrics push configuration to send metrics to seal-proxy.
    #[serde(default)]
    metrics_push_config: Option<MetricsPushConfig>,
}

impl NetworkConfig for AggregatorOptions {
    fn network(&self) -> &Network {
        &self.network
    }

    fn node_url_option(&self) -> &Option<String> {
        &self.node_url
    }
}

/// Application state.
#[derive(Clone)]
struct AppState {
    aggregator_metrics: Arc<AggregatorMetrics>,
    grpc_client: SuiGrpcClient,
    threshold: Arc<RwLock<u16>>,
    committee_members: Arc<RwLock<VecMap<Address, PartialKeyServer>>>,
    options: AggregatorOptions,
}

impl AppState {
    /// Validate SDK version against requirement based on SDK type.
    fn validate_sdk_version(
        &self,
        version: &str,
        sdk_type: Option<&HeaderValue>,
    ) -> Result<(), InternalError> {
        let version = Version::parse(version).map_err(|_| InvalidSDKVersion)?;
        let sdk_type = ClientSdkType::from_header(sdk_type.and_then(|v| v.to_str().ok()));

        match sdk_type {
            ClientSdkType::TypeScript => {
                if !self.options.ts_sdk_version_requirement.matches(&version) {
                    return Err(DeprecatedSDKVersion);
                }
            }
            _ => {
                // TODO: Add support for other SDK types.
                return Err(InvalidSDKType);
            }
        }

        Ok(())
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    let _guard = mysten_service::logging::init();

    // Load configuration from file.
    let config_path =
        env::var("CONFIG_PATH").context("CONFIG_PATH environment variable not set")?;
    info!("Loading config file: {}", config_path);

    let options: AggregatorOptions = serde_yaml::from_reader(
        std::fs::File::open(&config_path)
            .context(format!("Cannot open configuration file {config_path}"))?,
    )
    .context("Failed to parse configuration file")?;

    info!(
        "Starting aggregator for KeyServer {} on network {:?}, configured API credentials for: {:?}",
        options.key_server_object_id, options.network, options.api_credentials.keys().collect::<Vec<_>>()
    );

    let registry = Registry::new();

    // Track the uptime of the aggregator server.
    let registry_clone = registry.clone();
    tokio::task::spawn(async move {
        registry_clone
            .register(uptime_metric(
                "aggregator server",
                format!("{}-{}", package_version!(), GIT_VERSION).as_str(),
            ))
            .expect("metrics defined at compile time must be valid");
    });

    let metrics = Arc::new(AggregatorMetrics::new(&registry));

    let state = load_committee_state(options.clone(), metrics.clone()).await?;

    // Spawn background task to push metrics to seal-proxy if configured.
    let _metrics_push_handle =
        spawn_metrics_push_job(options.metrics_push_config.clone(), registry.clone());

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
        *state.threshold.read().await
    );

    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| DEFAULT_PORT.to_string())
        .parse()
        .context("Invalid PORT")?;

    let app = get_mysten_service::<AppState>(package_name!(), package_version!())
        .merge(
            Router::new()
                .route("/v1/fetch_key", post(handle_fetch_key))
                .route("/v1/service", get(handle_get_service))
                .layer(map_response(|response| {
                    add_response_headers(response, package_version!(), GIT_VERSION)
                })),
        )
        .with_state(state)
        .layer(middleware::from_fn_with_state(
            metrics.clone(),
            aggregator_metrics_middleware,
        ))
        .layer(CorsLayer::new().allow_origin(Any));

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Aggregator server started (version: {}, git version: {}), listening on http://localhost:{}", package_version!(), GIT_VERSION, port);

    axum::serve(listener, app).await?;
    Ok(())
}

/// get_service not supported for aggregator server.
async fn handle_get_service() -> Response {
    (StatusCode::BAD_REQUEST, "Unsupported").into_response()
}

/// Handle fetch_key request by fanning out to committee members and returns the aggregated
/// responses if threshold is achieved. Otherwise, propagates the majority error from key servers.
async fn handle_fetch_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<FetchKeyRequest>,
) -> Result<Json<FetchKeyResponse>, ErrorResponse> {
    // Track total requests.
    state.aggregator_metrics.requests.inc();

    // Extract request ID early for logging.
    let req_id = headers
        .get("Request-Id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    // Extract headers and validate version.
    let version = headers.get(HEADER_CLIENT_SDK_VERSION);
    let sdk_type = headers.get(HEADER_CLIENT_SDK_TYPE);

    let version_str = version
        .ok_or_else(|| {
            let err = MissingRequiredHeader(HEADER_CLIENT_SDK_VERSION.to_string());
            debug!("Missing SDK version header (req_id: {})", req_id);
            state.aggregator_metrics.observe_error(err.as_str());
            ErrorResponse::from(err)
        })
        .and_then(|v| {
            v.to_str().map_err(|_| {
                debug!(
                    "Invalid SDK version header format (req_id: {}), header: {:?}",
                    req_id, v
                );
                state
                    .aggregator_metrics
                    .observe_error(InvalidSDKVersion.as_str());
                ErrorResponse::from(InvalidSDKVersion)
            })
        })?;

    // Validate and track SDK version.
    state
        .validate_sdk_version(version_str, sdk_type)
        .map_err(|e| {
            debug!(
                "Invalid SDK version: {:?}, sdk_version: {:?}, sdk_type: {:?} (req_id: {})",
                e, version, sdk_type, req_id
            );
            state.aggregator_metrics.observe_error(e.as_str());
            ErrorResponse::from(e)
        })?;

    // Track client SDK version by type
    let sdk_type_enum = ClientSdkType::from_header(sdk_type.and_then(|v| v.to_str().ok()));
    let sdk_type_str = sdk_type_enum.to_string();
    state
        .aggregator_metrics
        .client_sdk_version
        .with_label_values(&[&sdk_type_str, version_str])
        .inc();

    // Log incoming request with structured data
    info!(
        "Aggregator request - req_id: {}, SDK version: {}, SDK type: {:?}, user: {:?}",
        req_id, version_str, sdk_type_enum, request.certificate.user
    );

    // Call to committee members' servers in parallel.
    let ks_version_req = &state.options.key_server_version_requirement;
    let api_credentials = &state.options.api_credentials;
    let metrics = state.aggregator_metrics.clone();
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
            let ks_version_req = ks_version_req.clone();
            let api_creds = api_credentials.get(&partial_key_server.name).cloned();
            let metrics = metrics.clone();
            async move {
                // Check if API credentials exist for this server.
                let creds = match api_creds {
                    Some(c) => c,
                    None => {
                        let msg = format!(
                            "Missing API credentials config for server '{}' ({})",
                            partial_key_server.name, partial_key_server.url
                        );
                        warn!("{}", msg);
                        return Err(ErrorResponse::from(InternalError::Failure(msg)));
                    }
                };

                match fetch_from_member(
                    &partial_key_server,
                    &request.clone(),
                    req_id,
                    &ks_version_req,
                    creds,
                )
                .await
                {
                    Ok(response) => Ok((partial_key_server.party_id, response)),
                    Err(e) => {
                        metrics.observe_upstream_error(&partial_key_server.name, &e.error);
                        debug!(
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
    let threshold = *state.threshold.read().await;
    let mut responses = Vec::new();
    let mut errors = Vec::new();
    while let Some(result) = fetch_tasks.next().await {
        match result {
            Ok((party_id, response)) => {
                responses.push((party_id, response));
                if responses.len() >= threshold as usize {
                    break;
                }
            }
            Err(e) => {
                errors.push(e);
            }
        }
    }

    info!(
        "Collected {} responses, {} errors",
        responses.len(),
        errors.len()
    );

    // If not enough responses, return majority error from key servers.
    if responses.len() < threshold as usize {
        let err = handle_insufficient_responses(responses.len(), threshold as usize, errors);
        state.aggregator_metrics.observe_error(&err.error);
        return Err(err);
    }

    // Aggregate encrypted responses and return.
    let aggregated_response = aggregate_verified_encrypted_responses(threshold, responses)
        .map_err(|e| {
            let msg = format!("Aggregating responses failed: {e}");
            warn!("{}", msg);
            let internal_err = InternalError::Failure(msg);
            state
                .aggregator_metrics
                .observe_error(internal_err.as_str());
            internal_err
        })?;

    // Log successful aggregation
    let committee_size = state.committee_members.read().await.0.contents.len();
    info!(
        "Aggregation successful - req_id: {}, threshold: {}/{}, user: {:?}",
        req_id, threshold, committee_size, request.certificate.user
    );

    Ok(Json(aggregated_response))
}

/// Fetch encrypted partial key from a single committee member's URL, use aggregator type and its version.
async fn fetch_from_member(
    member: &PartialKeyServer,
    request: &FetchKeyRequest,
    req_id: &str,
    ks_version_req: &VersionReq,
    api_credentials: ApiCredentials,
) -> Result<FetchKeyResponse, ErrorResponse> {
    info!(
        "Fetching from party {} at {} (req_id: {})",
        member.party_id, member.url, req_id
    );

    let client = reqwest::Client::new();
    let request_builder = client
        .post(format!("{}/v1/fetch_key", member.url))
        .header(HEADER_CLIENT_SDK_TYPE, SDK_TYPE_AGGREGATOR)
        .header(HEADER_CLIENT_SDK_VERSION, package_version!())
        .header("Request-Id", req_id)
        .header("Content-Type", "application/json")
        .header(&api_credentials.api_key_name, &api_credentials.api_key);

    let response = request_builder
        .body(request.to_json_string().expect("should not fail"))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| {
            let msg = format!("Request failed (req_id: {}): {}", req_id, e);
            if e.is_timeout() {
                debug!("{}", msg);
            } else {
                warn!("{}", msg);
            }
            InternalError::Failure(msg)
        })?;

    // If response is not success, relay error response from key server.
    let status = response.status();
    if !status.is_success() {
        if let Ok(error_response) = response.json::<ErrorResponse>().await {
            return Err(error_response);
        } else {
            let msg = format!("HTTP {status} (req_id: {})", req_id);
            warn!("{}", msg);
            return Err(InternalError::Failure(msg).into());
        }
    }

    // Validate key server version in response.
    let version = response.headers().get(HEADER_KEYSERVER_VERSION);
    let git_version = response.headers().get(HEADER_KEYSERVER_GIT_VERSION);

    let version_str = version.and_then(|v| v.to_str().ok()).unwrap_or("unknown");
    let git_version_str = git_version
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    info!(
        "Received response from party {} ({}) - version={}, git_version={} (req_id: {})",
        member.party_id, member.url, version_str, git_version_str, req_id
    );

    validate_key_server_version(version, ks_version_req)?;

    let mut body = response.json::<FetchKeyResponse>().await.map_err(|e| {
        let msg = format!("Parse failed: {e} (req_id: {})", req_id);
        warn!("{}", msg);
        InternalError::Failure(msg)
    })?;

    // Verify each decryption key. Errors early if any key fails.
    let verified_keys = verify_decryption_keys(
        &body.decryption_keys,
        &member.partial_pk,
        &request.enc_verification_key,
        member.party_id,
    )
    .map_err(|e| {
        let msg = format!("Verification failed: {e} (req_id: {})", req_id);
        warn!("{}", msg);
        InternalError::Failure(msg)
    })?;

    body.decryption_keys = verified_keys;
    Ok(body)
}

/// Validate key server version from response header against the configured version requirement.
fn validate_key_server_version(
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
/// Handle insufficient responses by finding and returning the majority error, or a generic error.
fn handle_insufficient_responses(
    got: usize,
    threshold: usize,
    errors: Vec<ErrorResponse>,
) -> ErrorResponse {
    let msg = format!(
        "Insufficient responses: got {}, need {}. Errors: {:?}",
        got, threshold, errors
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
            return majority_error.clone();
        }
    }

    // If errors is empty but still insufficient responses, return generic error.
    warn!("{}", msg);
    InternalError::Failure(msg).into()
}

/// Spawn a metrics push background job that pushes metrics to seal-proxy
fn spawn_metrics_push_job(
    push_config: Option<MetricsPushConfig>,
    registry: Registry,
) -> JoinHandle<()> {
    if let Some(push_config) = push_config {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(push_config.push_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut client = create_push_client();
            tracing::info!("starting metrics push to '{}'", &push_config.push_url);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(error) = push_metrics(
                            push_config.clone(),
                            &client,
                            &registry,
                        ).await {
                            tracing::warn!(?error, "unable to push metrics");
                            client = create_push_client();
                        }
                    }
                }
            }
        })
    } else {
        tokio::spawn(async move {
            warn!("No metrics push config is found");
            pending().await
        })
    }
}

/// Check and warn about missing API credentials for committee members.
fn check_missing_api_credentials(
    members: &VecMap<Address, PartialKeyServer>,
    api_credentials: &HashMap<String, ApiCredentials>,
) {
    for member in &members.0.contents {
        if !api_credentials.contains_key(&member.value.name) {
            warn!(
                "Missing API credentials for committee member '{}' (party_id: {}, url: {})",
                member.value.name, member.value.party_id, member.value.url
            );
        }
    }
}

/// Load committee state from onchain KeyServerV2 object.
async fn load_committee_state(
    options: AggregatorOptions,
    metrics: Arc<AggregatorMetrics>,
) -> Result<AppState> {
    let mut grpc_client =
        SuiGrpcClient::new(options.node_url()).context("Failed to create SuiGrpcClient")?;
    let key_server_v2 =
        fetch_key_server_by_id(&mut grpc_client, &options.key_server_object_id).await?;
    let (threshold, members) = key_server_v2.extract_committee_info()?;

    // Check and warn about missing API credentials for current committee.
    check_missing_api_credentials(&members, &options.api_credentials);

    Ok(AppState {
        aggregator_metrics: metrics,
        grpc_client,
        committee_members: Arc::new(RwLock::new(members)),
        threshold: Arc::new(RwLock::new(threshold)),
        options,
    })
}

/// Background task that periodically refreshes committee members from onchain.
/// Polls every 30 seconds and updates the committee members.
async fn monitor_members_update(mut state: AppState) {
    let mut ticker = interval(Duration::from_secs(REFRESH_INTERVAL_SECS));

    info!(
        "Committee monitor started - refresh interval: {}s",
        REFRESH_INTERVAL_SECS
    );

    loop {
        ticker.tick().await;

        // Fetch the current state from onchain.
        let (threshold, members) = match fetch_key_server_by_id(
            &mut state.grpc_client,
            &state.options.key_server_object_id,
        )
        .await
        .and_then(|ks| ks.extract_committee_info())
        {
            Ok(info) => info,
            Err(e) => {
                warn!(
                    "Committee refresh failed: {} - will retry in {}s",
                    e, REFRESH_INTERVAL_SECS
                );
                continue;
            }
        };

        // Check for new members' API credentials by comparing with current state.
        let member_count = members.0.contents.len();
        let current_members = state.committee_members.read().await;
        let current_names: HashSet<_> = current_members
            .0
            .contents
            .iter()
            .map(|m| &m.value.name)
            .collect();

        for member in &members.0.contents {
            if !current_names.contains(&member.value.name)
                && !state
                    .options
                    .api_credentials
                    .contains_key(&member.value.name)
            {
                warn!(
                    "Missing API credentials for new committee member '{}' (party_id: {}, url: {})",
                    member.value.name, member.value.party_id, member.value.url
                );
            }
        }

        // Update members and threshold in state.
        *state.committee_members.write().await = members;
        *state.threshold.write().await = threshold;

        info!(
            "Committee refreshed: {} members, threshold {}",
            member_count, threshold
        );
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

    /// Helper to create a FetchKeyRequest for testing.
    fn create_test_fetch_key_request(
        rng: &mut impl fastcrypto::traits::AllowedRng,
    ) -> (
        FetchKeyRequest,
        crypto::elgamal::PublicKey<G1Element>,
        crypto::elgamal::VerificationKey<G2Element>,
    ) {
        let (_, enc_key, enc_verification_key) = genkey::<G1Element, G2Element, _>(rng);
        let kp = Ed25519KeyPair::generate(rng);
        let pk = kp.public().clone();
        let sig: Ed25519Signature = kp.sign(b"test");
        let mut user_sig_bytes = vec![0u8];
        user_sig_bytes.extend_from_slice(sig.as_bytes());
        user_sig_bytes.extend_from_slice(pk.as_bytes());

        let request = FetchKeyRequest {
            ptb: "{}".to_string(),
            enc_key: enc_key.clone(),
            enc_verification_key: enc_verification_key.clone(),
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

        (request, enc_key, enc_verification_key)
    }

    /// Helper to create AppState for testing.
    fn create_test_app_state(
        mock_servers: &[MockServer],
        threshold: u16,
        partial_pks: Vec<G2Element>,
    ) -> AppState {
        let mut committee_contents = vec![];
        for (i, server) in mock_servers.iter().enumerate() {
            let address = Address::from([i as u8; 32]);
            let member = PartialKeyServer {
                name: "server".to_string(),
                party_id: i as u16,
                url: server.uri(),
                partial_pk: partial_pks.get(i).cloned().unwrap_or(G2Element::zero()),
            };
            committee_contents.push(Entry {
                key: address,
                value: member,
            });
        }

        let mut api_credentials = HashMap::new();
        api_credentials.insert(
            "server".to_string(),
            ApiCredentials {
                api_key_name: "X-API-Key".to_string(),
                api_key: "test-key".to_string(),
            },
        );

        let options = AggregatorOptions {
            network: Network::Testnet,
            node_url: None,
            key_server_object_id: Address::from([0u8; 32]),
            ts_sdk_version_requirement: VersionReq::parse(">=0.9.0").unwrap(),
            key_server_version_requirement: VersionReq::parse(">=0.5.14").unwrap(),
            api_credentials,
            metrics_push_config: None,
        };
        let registry = Registry::new();
        let metrics = Arc::new(AggregatorMetrics::new(&registry));
        let grpc_client = SuiGrpcClient::new(options.node_url()).unwrap();

        AppState {
            aggregator_metrics: metrics,
            grpc_client,
            threshold: Arc::new(RwLock::new(threshold)),
            committee_members: Arc::new(RwLock::new(VecMap(SuiVecMap {
                contents: committee_contents,
            }))),
            options,
        }
    }

    #[tokio::test]
    async fn test_version_validations() {
        use mysten_service::package_version;

        // Test 1: Aggregator rejects client SDK if version is too old
        {
            let server1 = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/fetch_key"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header(HEADER_KEYSERVER_VERSION, package_version!())
                        .insert_header(HEADER_KEYSERVER_GIT_VERSION, "git-abc123")
                        .set_body_json(json!({
                            "decryption_keys": []
                        })),
                )
                .mount(&server1)
                .await;

            let state = create_test_app_state(&[server1], 1, vec![G2Element::zero()]);
            let (request, _, _) = create_test_fetch_key_request(&mut thread_rng());

            let mut headers = HeaderMap::new();
            headers.insert(HEADER_CLIENT_SDK_VERSION, "0.3.0".parse().unwrap()); // Too old
            let result = handle_fetch_key(State(state), headers, Json(request)).await;

            match result {
                Err(error) => {
                    assert_eq!(error.error, "DeprecatedSDKVersion");
                }
                Ok(_) => panic!("Expected error for deprecated SDK version"),
            }
        }

        // Test 2: Aggregator rejects key server response if version is too old
        {
            let server2 = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/fetch_key"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header(HEADER_KEYSERVER_VERSION, "0.5.13") // Too old
                        .insert_header(HEADER_KEYSERVER_GIT_VERSION, "git-old")
                        .set_body_json(json!({
                            "decryption_keys": []
                        })),
                )
                .mount(&server2)
                .await;

            let state = create_test_app_state(&[server2], 1, vec![G2Element::zero()]);
            let (request, _, _) = create_test_fetch_key_request(&mut thread_rng());

            let mut headers = HeaderMap::new();
            headers.insert(HEADER_CLIENT_SDK_VERSION, "0.9.6".parse().unwrap());
            let result = handle_fetch_key(State(state), headers, Json(request)).await;

            match result {
                Err(error) => {
                    assert_eq!(error.error, "Failure");
                }
                Ok(_) => panic!("Expected error for deprecated key server version"),
            }
        }

        // Test 3: If key server responses are good, return aggregator's own version to client
        {
            let server3 = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/fetch_key"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header(HEADER_KEYSERVER_VERSION, package_version!())
                        .insert_header(HEADER_KEYSERVER_GIT_VERSION, "git-abc123")
                        .set_body_json(json!({
                            "decryption_keys": []
                        })),
                )
                .mount(&server3)
                .await;

            let state = create_test_app_state(&[server3], 1, vec![G2Element::zero()]);
            let (request, _, _) = create_test_fetch_key_request(&mut thread_rng());

            let mut headers = HeaderMap::new();
            headers.insert(HEADER_CLIENT_SDK_VERSION, "0.9.6".parse().unwrap());
            let result = handle_fetch_key(State(state), headers, Json(request)).await;
            let response = result.unwrap().into_response();
            let response = add_response_headers(response, package_version!(), GIT_VERSION).await;

            let headers = response.headers();
            assert_eq!(
                headers.get(HEADER_KEYSERVER_VERSION).unwrap(),
                package_version!()
            );
            assert_eq!(
                headers.get(HEADER_KEYSERVER_GIT_VERSION).unwrap(),
                key_server::git_version!()
            );
        }
    }

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

        // Create AppState with threshold=3 and zero partial keys.
        let state = create_test_app_state(
            &mock_servers,
            3,
            vec![G2Element::zero(); mock_servers.len()],
        );

        // Create a FetchKeyRequest for testing.
        let mut rng = thread_rng();
        let (request, _, _) = create_test_fetch_key_request(&mut rng);

        // Call handle_fetch_key and check majority error.
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_CLIENT_SDK_VERSION, "0.9.6".parse().unwrap());
        let result = handle_fetch_key(State(state), headers, Json(request)).await;
        match result {
            Err(error) => {
                assert_eq!(error.error, "InvalidPTB");
            }
            Ok(_) => panic!("Expected error but got success"),
        }
    }
}
