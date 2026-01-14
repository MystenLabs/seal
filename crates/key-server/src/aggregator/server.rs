// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Aggregator server for Seal committee mode. It fetches encrypted partial keys from committee
//! servers, verifies and aggregates them into a single response if threshold is achieved, or
//! propagates the majority error otherwise.

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::map_response,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
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
use mysten_service::{get_mysten_service, package_name, package_version};
use seal_committee::{
    fetch_key_server_by_id,
    move_types::{PartialKeyServer, VecMap},
};
use seal_sdk::{FetchKeyRequest, FetchKeyResponse};
use semver::{Version, VersionReq};
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use sui_rpc::client::Client as SuiGrpcClient;
use sui_sdk_types::Address;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};
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

/// Configuration file format for aggregator server.
#[derive(Clone, Deserialize)]
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
    grpc_client: SuiGrpcClient,
    threshold: u16,
    committee_members: Arc<RwLock<VecMap<Address, PartialKeyServer>>>,
    options: AggregatorOptions,
    // TODO: API storage and rotation.
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
        "Starting aggregator for KeyServer {} on {:?} ({:?})",
        options.key_server_object_id, options.network, options.node_url
    );

    let state = load_committee_state(options).await?;

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
                .route("/v1/service", get(handle_get_service))
                .layer(map_response(|response| {
                    add_response_headers(response, package_version!(), GIT_VERSION)
                })),
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
    (StatusCode::BAD_REQUEST, "Unsupported").into_response()
}

/// Handle fetch_key request by fanning out to committee members and returns the aggregated
/// responses if threshold is achieved. Otherwise, propagates the majority error from key servers.
async fn handle_fetch_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<FetchKeyRequest>,
) -> Result<Json<FetchKeyResponse>, ErrorResponse> {
    // Extract headers and validate version.
    let version = headers.get(HEADER_CLIENT_SDK_VERSION);
    let sdk_type = headers.get(HEADER_CLIENT_SDK_TYPE);

    version
        .ok_or_else(|| {
            ErrorResponse::from(MissingRequiredHeader(HEADER_CLIENT_SDK_VERSION.to_string()))
        })
        .and_then(|v| {
            v.to_str()
                .map_err(|_| ErrorResponse::from(InvalidSDKVersion))
        })
        .and_then(|v| {
            state
                .validate_sdk_version(v, sdk_type)
                .map_err(ErrorResponse::from)
        })?;

    let req_id = headers
        .get("Request-Id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    // Call to committee members' servers in parallel.
    let ks_version_req = &state.options.key_server_version_requirement;
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
            async move {
                match fetch_from_member(
                    &partial_key_server,
                    &request.clone(),
                    req_id,
                    &ks_version_req,
                )
                .await
                {
                    Ok(response) => Ok((partial_key_server.party_id, response)),
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
    let mut errors = Vec::new();
    while let Some(result) = fetch_tasks.next().await {
        match result {
            Ok((party_id, response)) => {
                responses.push((party_id, response));
                if responses.len() >= state.threshold as usize {
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
    if responses.len() < state.threshold as usize {
        return Err(handle_insufficient_responses(
            responses.len(),
            state.threshold as usize,
            errors,
        ));
    }

    // Aggregate encrypted responses and return.
    let aggregated_response = aggregate_verified_encrypted_responses(state.threshold, responses)
        .map_err(|e| {
            let msg = format!("Aggregating responses failed: {e}");
            warn!("{}", msg);
            InternalError::Failure(msg)
        })?;
    Ok(Json(aggregated_response))
}

/// Fetch encrypted partial key from a single committee member's URL, use aggregator type and its version.
async fn fetch_from_member(
    member: &PartialKeyServer,
    request: &FetchKeyRequest,
    req_id: &str,
    ks_version_req: &VersionReq,
) -> Result<FetchKeyResponse, ErrorResponse> {
    info!("Fetching from party {} at {}", member.party_id, member.url);

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/v1/fetch_key", member.url))
        .header(HEADER_CLIENT_SDK_TYPE, SDK_TYPE_AGGREGATOR)
        .header(HEADER_CLIENT_SDK_VERSION, package_version!())
        .header("Request-Id", req_id)
        .header("Content-Type", "application/json")
        .body(request.to_json_string().expect("should not fail"))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| {
            let msg = format!("Request failed: {e}");
            warn!("{}", msg);
            InternalError::Failure(msg)
        })?;

    // If response is not success, relay error response from key server.
    let status = response.status();
    if !status.is_success() {
        if let Ok(error_response) = response.json::<ErrorResponse>().await {
            return Err(error_response);
        } else {
            let msg = format!("HTTP {status}");
            warn!("{}", msg);
            return Err(InternalError::Failure(msg).into());
        }
    }

    // Validate key server version in response.
    let version = response.headers().get(HEADER_KEYSERVER_VERSION);
    let git_version = response.headers().get(HEADER_KEYSERVER_GIT_VERSION);

    info!(
        "Received response from party {} ({}): version={}, git_version={}",
        member.party_id,
        member.url,
        version.and_then(|v| v.to_str().ok()).unwrap_or("unknown"),
        git_version
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
    );

    validate_key_server_version(version, ks_version_req)?;

    let mut body = response.json::<FetchKeyResponse>().await.map_err(|e| {
        let msg = format!("Parse failed: {e}");
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
        let msg = format!("Verification failed: {e}");
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
    warn!(
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
    let msg = format!("Insufficient responses: got {got}, need {threshold}");
    warn!("{}", msg);
    InternalError::Failure(msg).into()
}

/// Load committee state from onchain KeyServerV2 object.
async fn load_committee_state(options: AggregatorOptions) -> Result<AppState> {
    let mut grpc_client =
        SuiGrpcClient::new(options.node_url()).context("Failed to create SuiGrpcClient")?;
    let key_server_v2 =
        fetch_key_server_by_id(&mut grpc_client, &options.key_server_object_id).await?;
    let (threshold, members) = key_server_v2.extract_committee_info()?;

    Ok(AppState {
        grpc_client,
        committee_members: Arc::new(RwLock::new(members)),
        threshold,
        options,
    })
}

/// Background task that periodically refreshes committee members from onchain.
/// Polls every 30 seconds and updates the committee members.
async fn monitor_members_update(mut state: AppState) {
    let mut ticker = interval(Duration::from_secs(REFRESH_INTERVAL_SECS));

    loop {
        ticker.tick().await;

        // Fetch the current state from onchain.
        let (_, members) = match fetch_key_server_by_id(
            &mut state.grpc_client,
            &state.options.key_server_object_id,
        )
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

        let options = AggregatorOptions {
            network: Network::Testnet,
            node_url: None,
            key_server_object_id: Address::from([0u8; 32]),
            ts_sdk_version_requirement: VersionReq::parse(">=0.9.0").unwrap(),
            key_server_version_requirement: VersionReq::parse(">=0.5.14").unwrap(),
        };
        let grpc_client = SuiGrpcClient::new(options.node_url()).unwrap();
        AppState {
            grpc_client,
            threshold,
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
