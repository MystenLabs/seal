// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::errors::InternalError::{
    DeprecatedSDKVersion, InvalidSDKVersion, MissingRequiredHeader,
};
use crate::externals::{
    current_epoch_time, duration_since, get_reference_gas_price, safe_duration_since,
};
use crate::key_server_options::{ClientKeyType, ServerMode};
use crate::metrics::{call_with_duration, observation_callback, status_callback, Metrics};
use crate::mvr::mvr_forward_resolution;
use crate::signed_message::{signed_message, signed_request};
use crate::types::{MasterKeyPOP, Network};
use anyhow::{anyhow, Context, Result};
use axum::extract::{Query, Request};
use axum::http::{HeaderMap, HeaderValue};
use axum::middleware::{from_fn_with_state, map_response, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{extract::State, Json};
use core::time::Duration;
use crypto::elgamal::encrypt;
use crypto::ibe;
use crypto::ibe::{create_proof_of_possession, MASTER_KEY_LENGTH, SEED_LENGTH};
use errors::InternalError;
use externals::get_latest_checkpoint_timestamp;
use fastcrypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use fastcrypto::encoding::{Base64, Encoding, Hex};
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::VerifyingKey;
use jsonrpsee::core::ClientError;
use jsonrpsee::types::error::{INVALID_PARAMS_CODE, METHOD_NOT_FOUND_CODE};
use key_server_options::KeyServerOptions;
use metrics::metrics_middleware;
use mysten_service::get_mysten_service;
use mysten_service::metrics::start_prometheus_server;
use mysten_service::package_name;
use mysten_service::package_version;
use mysten_service::serve;
use rand::thread_rng;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use sui_sdk::error::{Error, SuiRpcResult};
use sui_sdk::rpc_types::SuiTransactionBlockEffectsAPI;
use sui_sdk::types::base_types::{ObjectID, SuiAddress};
use sui_sdk::types::signature::GenericSignature;
use sui_sdk::types::transaction::{ProgrammableTransaction, TransactionKind};
use sui_sdk::verify_personal_message_signature::verify_personal_message_signature;
use sui_sdk::{SuiClient, SuiClientBuilder};
use tap::tap::TapFallible;
use tokio::sync::watch::{channel, Receiver};
use tokio::task::JoinHandle;
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, error, info, warn};
use types::{ElGamalPublicKey, ElgamalEncryption, ElgamalVerificationKey, IbeMasterKey};
use valid_ptb::ValidPtb;

mod cache;
mod errors;
mod externals;
mod signed_message;
mod types;
mod utils;
mod valid_ptb;

mod key_server_options;
mod metrics;
mod mvr;
#[cfg(test)]
pub mod tests;

const GAS_BUDGET: u64 = 500_000_000;
const GIT_VERSION: &str = utils::git_version!();

/// Default encoding used for master and public keys for the key server.
type DefaultEncoding = Hex;

// The "session" certificate, signed by the user
#[derive(Clone, Serialize, Deserialize, Debug)]
struct Certificate {
    pub user: SuiAddress,
    pub session_vk: Ed25519PublicKey,
    pub creation_time: u64,
    pub ttl_min: u16,
    pub signature: GenericSignature,
    pub mvr_name: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct FetchKeyRequest {
    // Next fields must be signed to prevent others from sending requests on behalf of the user and
    // being able to fetch the key
    ptb: String, // must adhere specific structure, see ValidPtb
    // We don't want to rely on https only for restricting the response to this user, since in the
    // case of multiple services, one service can do a replay attack to get the key from other
    // services.
    enc_key: ElGamalPublicKey,
    enc_verification_key: ElgamalVerificationKey,
    request_signature: Ed25519Signature,

    certificate: Certificate,
}

type KeyId = Vec<u8>;

/// UNIX timestamp in milliseconds.
type Timestamp = u64;

#[derive(Serialize, Deserialize)]
struct DecryptionKey {
    id: KeyId,
    encrypted_key: ElgamalEncryption,
}

#[derive(Serialize, Deserialize)]
struct FetchKeyResponse {
    decryption_keys: Vec<DecryptionKey>,
}

#[derive(Clone)]
struct Server {
    sui_client: SuiClient,
    master_keys: MasterKeys,
    key_server_oid_to_pop: HashMap<ObjectID, MasterKeyPOP>,
    options: KeyServerOptions,
}

impl Server {
    async fn new(options: KeyServerOptions) -> Self {
        let sui_client = SuiClientBuilder::default()
            .build(&options.network.node_url())
            .await
            .expect("SuiClientBuilder should not failed unless provided with invalid network url");
        info!("Server started with network: {:?}", options.network);

        let master_keys = MasterKeys::load(&options).unwrap_or_else(|e| {
            panic!("Failed to load master keys: {}", e);
        });

        let key_server_oid_to_pop = options
            .get_supported_key_server_object_ids()
            .into_iter()
            .map(|ks_oid| {
                let key = master_keys
                    .get_key_for_key_server(&ks_oid)
                    .expect("checked already");
                let pop = create_proof_of_possession(key, &ks_oid.into_bytes());
                (ks_oid, pop)
            })
            .collect();

        Server {
            sui_client,
            master_keys,
            key_server_oid_to_pop,
            options,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn check_signature(
        &self,
        ptb: &ProgrammableTransaction,
        enc_key: &ElGamalPublicKey,
        enc_verification_key: &ElgamalVerificationKey,
        session_sig: &Ed25519Signature,
        cert: &Certificate,
        package_name: String,
        req_id: Option<&str>,
    ) -> Result<(), InternalError> {
        // Check certificate.
        if from_mins(cert.ttl_min) > self.options.session_key_ttl_max
            || cert.creation_time > current_epoch_time()
            || current_epoch_time() < 60_000 * (cert.ttl_min as u64) // checks for overflow
            || current_epoch_time() - 60_000 * (cert.ttl_min as u64) > cert.creation_time
        {
            debug!(
                "Certificate has invalid expiration time (req_id: {:?})",
                req_id
            );
            return Err(InternalError::InvalidCertificate);
        }

        let msg = signed_message(
            package_name,
            &cert.session_vk,
            cert.creation_time,
            cert.ttl_min,
        );
        debug!(
            "Checking signature on message: {:?} (req_id: {:?})",
            msg, req_id
        );
        verify_personal_message_signature(
            cert.signature.clone(),
            msg.as_bytes(),
            cert.user,
            Some(self.sui_client.clone()),
        )
        .await
        .tap_err(|e| {
            debug!(
                "Signature verification failed: {:?} (req_id: {:?})",
                e, req_id
            );
        })
        .map_err(|_| InternalError::InvalidSignature)?;

        // Check session signature
        let signed_msg = signed_request(ptb, enc_key, enc_verification_key);
        cert.session_vk
            .verify(&signed_msg, session_sig)
            .map_err(|_| {
                debug!(
                    "Session signature verification failed (req_id: {:?})",
                    req_id
                );
                InternalError::InvalidSessionSignature
            })
    }

    async fn check_policy(
        &self,
        sender: SuiAddress,
        vptb: &ValidPtb,
        gas_price: u64,
        req_id: Option<&str>,
    ) -> Result<(), InternalError> {
        debug!(
            "Checking policy for ptb: {:?} (req_id: {:?})",
            vptb.ptb(),
            req_id
        );
        // Evaluate the `seal_approve*` function
        let tx_data = self
            .sui_client
            .transaction_builder()
            .tx_data_for_dry_run(
                sender,
                TransactionKind::ProgrammableTransaction(vptb.ptb().clone()),
                GAS_BUDGET,
                gas_price,
                None,
                None,
            )
            .await;
        let dry_run_res = self
            .sui_client
            .read_api()
            .dry_run_transaction_block(tx_data)
            .await
            .map_err(|e| {
                if let Error::RpcError(ClientError::Call(ref e)) = e {
                    match e.code() {
                        INVALID_PARAMS_CODE => {
                            // A dry run will fail if called with a newly created object parameter that the FN has not yet seen.
                            // In that case, the user gets a FORBIDDEN status response.
                            debug!("Invalid parameter: This could be because the FN has not yet seen the object.");
                            return InternalError::InvalidParameter;
                        }
                        METHOD_NOT_FOUND_CODE => {
                            // This means that the seal_approve function is not found on the given module.
                            debug!("Function not found: {:?}", e);
                            return InternalError::InvalidPTB("The seal_approve function was not found on the module".to_string());
                        }
                        _ => {}
                    }
                }
                warn!("Dry run execution failed ({:?}) (req_id: {:?})", e, req_id);
                InternalError::Failure
            })?;
        debug!("Dry run response: {:?} (req_id: {:?})", dry_run_res, req_id);
        if dry_run_res.effects.status().is_err() {
            debug!("Dry run execution asserted (req_id: {:?})", req_id);
            // TODO: Should we return a different error per status, e.g., InsufficientGas?
            return Err(InternalError::NoAccess);
        }

        // all good!
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn check_request(
        &self,
        valid_ptb: &ValidPtb,
        enc_key: &ElGamalPublicKey,
        enc_verification_key: &ElgamalVerificationKey,
        request_signature: &Ed25519Signature,
        certificate: &Certificate,
        gas_price: u64,
        metrics: Option<&Metrics>,
        req_id: Option<&str>,
        mvr_name: Option<String>,
    ) -> Result<(ObjectID, Vec<KeyId>), InternalError> {
        // Handle package upgrades: Use the first as the namespace
        let first_pkg_id =
            call_with_duration(metrics.map(|m| &m.fetch_pkg_ids_duration), || async {
                externals::fetch_first_pkg_id(&valid_ptb.pkg_id(), &self.sui_client).await
            })
            .await?;

        // Make sure that the package is supported.
        self.master_keys.has_key_for_package(&first_pkg_id)?;

        // If an MVR name is provided, check that it points to the first package ID
        if let Some(mvr_name) = &mvr_name {
            let mvr_package_id =
                mvr_forward_resolution(&self.sui_client, mvr_name, &self.options.network).await?;
            if mvr_package_id != first_pkg_id {
                debug!(
                    "MVR name {} points to package ID {:?} while the first package ID is {:?} (req_id: {:?})",
                    mvr_name, mvr_package_id, first_pkg_id, req_id
                );
                return Err(InternalError::InvalidMVRName);
            }
        }

        // Check all conditions
        self.check_signature(
            valid_ptb.ptb(),
            enc_key,
            enc_verification_key,
            request_signature,
            certificate,
            mvr_name.unwrap_or(first_pkg_id.to_hex_uncompressed()),
            req_id,
        )
        .await?;

        call_with_duration(metrics.map(|m| &m.check_policy_duration), || async {
            self.check_policy(certificate.user, valid_ptb, gas_price, req_id)
                .await
        })
        .await?;

        // return the full id with the first package id as prefix
        Ok((first_pkg_id, valid_ptb.full_ids(&first_pkg_id)))
    }

    fn create_response(
        &self,
        first_pkg_id: ObjectID,
        ids: &[KeyId],
        enc_key: &ElGamalPublicKey,
    ) -> FetchKeyResponse {
        debug!("Creating response for ids: {:?}", ids);
        let master_key = self
            .master_keys
            .get_key_for_package(&first_pkg_id)
            .expect("checked already");
        let decryption_keys = ids
            .iter()
            .map(|id| {
                // Requested key
                let key = ibe::extract(master_key, id);
                // ElGamal encryption of key under the user's public key
                let encrypted_key = encrypt(&mut thread_rng(), &key, enc_key);
                DecryptionKey {
                    id: id.to_owned(),
                    encrypted_key,
                }
            })
            .collect();
        FetchKeyResponse { decryption_keys }
    }

    /// Helper function to spawn a thread that periodically fetches a value and sends it to a [Receiver].
    /// If a subscriber is provided, it will be called when the value is updated.
    /// If a duration_callback is provided, it will be called with the duration of each fetch operation.
    /// Returns the [Receiver].
    async fn spawn_periodic_updater<F, Fut, G, H, I>(
        &self,
        update_interval: Duration,
        fetch_fn: F,
        value_name: &'static str,
        subscriber: Option<G>,
        duration_callback: Option<H>,
        success_callback: Option<I>,
    ) -> (Receiver<u64>, JoinHandle<()>)
    where
        F: Fn(SuiClient) -> Fut + Send + 'static,
        Fut: Future<Output = SuiRpcResult<u64>> + Send,
        G: Fn(u64) + Send + 'static,
        H: Fn(Duration) + Send + 'static,
        I: Fn(bool) + Send + 'static,
    {
        let (sender, mut receiver) = channel(0);
        let local_client = self.sui_client.clone();
        let mut interval = tokio::time::interval(update_interval);

        // In case of a missed tick due to a slow-responding full node, we don't need to
        // catch up but rather just delay the next tick.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let handle = tokio::task::spawn(async move {
            loop {
                let now = Instant::now();
                let result = fetch_fn(local_client.clone()).await;
                if let Some(dcb) = &duration_callback {
                    dcb(now.elapsed());
                }
                if let Some(scb) = &success_callback {
                    scb(result.is_ok());
                }
                match result {
                    Ok(new_value) => {
                        sender
                            .send(new_value)
                            .expect("Channel closed, this should never happen");
                        debug!("{} updated to: {:?}", value_name, new_value);
                        if let Some(subscriber) = &subscriber {
                            subscriber(new_value);
                        }
                    }
                    Err(e) => warn!("Failed to get {}: {:?}", value_name, e),
                }
                interval.tick().await;
            }
        });

        // This blocks until a value is fetched.
        // This is done to ensure that the server will be ready to serve requests immediately after starting.
        // If this is not possible, we cannot update the value and the server should not start.
        receiver
            .changed()
            .await
            .unwrap_or_else(|_| panic!("Failed to get {}", value_name));
        (receiver, handle)
    }

    /// Spawns a thread that fetches the latest checkpoint timestamp and sends it to a [Receiver] once per `update_interval`.
    /// Returns the [Receiver].
    async fn spawn_latest_checkpoint_timestamp_updater(
        &self,
        metrics: Option<&Metrics>,
    ) -> (Receiver<Timestamp>, JoinHandle<()>) {
        self.spawn_periodic_updater(
            self.options.checkpoint_update_interval,
            get_latest_checkpoint_timestamp,
            "latest checkpoint timestamp",
            metrics.map(|m| {
                observation_callback(&m.checkpoint_timestamp_delay, |ts| {
                    duration_since(ts) as f64
                })
            }),
            metrics.map(|m| {
                observation_callback(&m.get_checkpoint_timestamp_duration, |d: Duration| {
                    d.as_millis() as f64
                })
            }),
            metrics.map(|m| status_callback(&m.get_checkpoint_timestamp_status)),
        )
        .await
    }

    /// Spawns a thread that fetches RGP and sends it to a [Receiver] once per `update_interval`.
    /// Returns the [Receiver].
    async fn spawn_reference_gas_price_updater(
        &self,
        metrics: Option<&Metrics>,
    ) -> (Receiver<u64>, JoinHandle<()>) {
        self.spawn_periodic_updater(
            self.options.rgp_update_interval,
            get_reference_gas_price,
            "RGP",
            None::<fn(u64)>,
            None::<fn(Duration)>,
            metrics.map(|m| status_callback(&m.get_reference_gas_price_status)),
        )
        .await
    }
}

async fn handle_fetch_key_internal(
    app_state: &MyState,
    payload: &FetchKeyRequest,
    req_id: Option<&str>,
    sdk_version: &str,
) -> Result<(ObjectID, Vec<KeyId>), InternalError> {
    app_state.check_full_node_is_fresh()?;

    let valid_ptb = ValidPtb::try_from_base64(&payload.ptb)?;

    // Report the number of id's in the request to the metrics.
    app_state
        .metrics
        .requests_per_number_of_ids
        .observe(valid_ptb.inner_ids().len() as f64);

    app_state
        .server
        .check_request(
            &valid_ptb,
            &payload.enc_key,
            &payload.enc_verification_key,
            &payload.request_signature,
            &payload.certificate,
            app_state.reference_gas_price(),
            Some(&app_state.metrics),
            req_id,
            payload.certificate.mvr_name.clone(),
        )
        .await.tap_ok(|_| info!(
            "Valid request: {}",
            json!({ "user": payload.certificate.user, "package_id": valid_ptb.pkg_id(), "req_id": req_id, "sdk_version": sdk_version })
        ))
}

async fn handle_fetch_key(
    State(app_state): State<MyState>,
    headers: HeaderMap,
    Json(payload): Json<FetchKeyRequest>,
) -> Result<Json<FetchKeyResponse>, InternalError> {
    let req_id = headers
        .get("Request-Id")
        .map(|v| v.to_str().unwrap_or_default());
    let sdk_version = headers
        .get("Client-Sdk-Version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    app_state.metrics.requests.inc();

    debug!(
        "Checking request for ptb: {:?}, cert {:?} (req_id: {:?})",
        payload.ptb, payload.certificate, req_id
    );

    handle_fetch_key_internal(&app_state, &payload, req_id, sdk_version)
        .await
        .tap_err(|e| app_state.metrics.observe_error(e.as_str()))
        .map(|(first_pkg_id, full_ids)| {
            Json(
                app_state
                    .server
                    .create_response(first_pkg_id, &full_ids, &payload.enc_key),
            )
        })
}

#[derive(Serialize, Deserialize)]
struct GetServiceResponse {
    service_id: ObjectID,
    pop: MasterKeyPOP,
}

async fn handle_get_service(
    State(app_state): State<MyState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<GetServiceResponse>, InternalError> {
    app_state.metrics.service_requests.inc();
    let service_id = match params.get("service_id") {
        Some(id) => ObjectID::from_hex_literal(id).map_err(|_| InternalError::InvalidServiceId)?,
        None => app_state.server.options.get_legacy_key_server_object_id()?,
    };

    let pop = *app_state
        .server
        .key_server_oid_to_pop
        .get(&service_id)
        .ok_or(InternalError::InvalidServiceId)?;

    Ok(Json(GetServiceResponse { service_id, pop }))
}

#[derive(Clone)]
struct MyState {
    metrics: Arc<Metrics>,
    server: Arc<Server>,
    latest_checkpoint_timestamp_receiver: Receiver<Timestamp>,
    reference_gas_price_receiver: Receiver<u64>,
}

impl MyState {
    fn check_full_node_is_fresh(&self) -> Result<(), InternalError> {
        // Compute the staleness of the latest checkpoint timestamp.
        let staleness = safe_duration_since(*self.latest_checkpoint_timestamp_receiver.borrow());
        if staleness > self.server.options.allowed_staleness {
            warn!(
                "Full node is stale. Latest checkpoint is {} ms old.",
                staleness.as_millis()
            );
            return Err(InternalError::Failure);
        }
        Ok(())
    }

    fn reference_gas_price(&self) -> u64 {
        *self.reference_gas_price_receiver.borrow()
    }

    fn validate_sdk_version(&self, version_string: &str) -> Result<(), InternalError> {
        let version = Version::parse(version_string).map_err(|_| InvalidSDKVersion)?;
        if !self
            .server
            .options
            .sdk_version_requirement
            .matches(&version)
        {
            return Err(DeprecatedSDKVersion);
        }
        Ok(())
    }
}

/// Middleware to validate the SDK version.
async fn handle_request_headers(
    state: State<MyState>,
    request: Request,
    next: Next,
) -> Result<Response, InternalError> {
    // Log the request id and SDK version
    let version = request.headers().get("Client-Sdk-Version");

    info!(
        "Request id: {:?}, SDK version: {:?}, SDK type: {:?}, Target API version: {:?}",
        request
            .headers()
            .get("Request-Id")
            .map(|v| v.to_str().unwrap_or_default()),
        version,
        request.headers().get("Client-Sdk-Type"),
        request.headers().get("Client-Target-Api-Version")
    );

    version
        .ok_or(MissingRequiredHeader("Client-Sdk-Version".to_string()))
        .and_then(|v| v.to_str().map_err(|_| InvalidSDKVersion))
        .and_then(|v| state.validate_sdk_version(v))
        .tap_err(|e| {
            warn!("Invalid SDK version: {:?}", e);
            state.metrics.observe_error(e.as_str());
        })?;
    Ok(next.run(request).await)
}

/// Middleware to add headers to all responses.
async fn add_response_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        "X-KeyServer-Version",
        HeaderValue::from_static(package_version!()),
    );
    headers.insert(
        "X-KeyServer-GitVersion",
        HeaderValue::from_static(GIT_VERSION),
    );
    response
}

/// Creates a [prometheus::core::Collector] that tracks the uptime of the server.
fn uptime_metric(version: &str) -> Box<dyn prometheus::core::Collector> {
    let opts = prometheus::opts!("uptime", "uptime of the key server in seconds")
        .variable_label("version");

    let start_time = std::time::Instant::now();
    let uptime = move || start_time.elapsed().as_secs();
    let metric = prometheus_closure_metric::ClosureMetric::new(
        opts,
        prometheus_closure_metric::ValueType::Counter,
        uptime,
        &[version],
    )
    .unwrap();

    Box::new(metric)
}

/// Spawn server's background tasks:
///  - background checkpoint downloader
///  - reference gas price updater.
///
/// The returned JoinHandle can be used to catch any tasks error or panic.
async fn start_server_background_tasks(
    server: Arc<Server>,
    metrics: Arc<Metrics>,
) -> (
    Receiver<Timestamp>,
    Receiver<u64>,
    JoinHandle<anyhow::Result<()>>,
) {
    // Spawn background checkpoint timestamp updater.
    let (latest_checkpoint_timestamp_receiver, latest_checkpoint_timestamp_handle) = server
        .spawn_latest_checkpoint_timestamp_updater(Some(&metrics))
        .await;

    // Spawn background reference gas price updater.
    let (reference_gas_price_receiver, reference_gas_price_handle) = server
        .spawn_reference_gas_price_updater(Some(&metrics))
        .await;

    // Spawn a monitor task that will exit the program if either updater task panics
    let handle: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        tokio::select! {
            result = latest_checkpoint_timestamp_handle => {
                if let Err(e) = result {
                    error!("Latest checkpoint timestamp updater panicked: {:?}", e);
                    if e.is_panic() {
                        std::panic::resume_unwind(e.into_panic());
                    }
                    return Err(e.into());
                }
            }
            result = reference_gas_price_handle => {
                if let Err(e) = result {
                    error!("Reference gas price updater panicked: {:?}", e);
                    if e.is_panic() {
                        std::panic::resume_unwind(e.into_panic());
                    }
                    return Err(e.into());
                }
            }
        }

        unreachable!("One of the background tasks should have returned an error");
    });

    (
        latest_checkpoint_timestamp_receiver,
        reference_gas_price_receiver,
        handle,
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let _guard = mysten_service::logging::init();

    // If CONFIG_PATH is set, read the configuration from the file.
    // Otherwise, use the legacy environment variables.
    let options = match env::var("CONFIG_PATH") {
        Ok(config_path) => {
            info!("Loading config file: {}", config_path);
            serde_yaml::from_reader(
                std::fs::File::open(&config_path)
                    .context(format!("Cannot open configuration file {config_path}"))?,
            )
            .expect("Failed to parse configuration file")
        }
        Err(_) => {
            info!("Using legacy environment variables for configuration");
            // TODO: remove this when the legacy key server is no longer needed
            let network = env::var("NETWORK")
                .map(|n| Network::from_str(&n))
                .unwrap_or(Network::Testnet);
            KeyServerOptions::new_open_server_with_default_values(
                network,
                decode_object_id("LEGACY_KEY_SERVER_OBJECT_ID")?,
                decode_object_id("KEY_SERVER_OBJECT_ID")?,
            )
        }
    };

    info!("Setting up metrics");
    let registry = start_prometheus_server(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        options.metrics_host_port,
    ))
    .default_registry();

    // Tracks the uptime of the server.
    let registry_clone = registry.clone();
    tokio::task::spawn(async move {
        registry_clone
            .register(uptime_metric(
                format!("{}-{}", package_version!(), GIT_VERSION).as_str(),
            ))
            .expect("metrics defined at compile time must be valid");
    });

    // hook up custom application metrics
    let metrics = Arc::new(Metrics::new(&registry));

    info!(
        "Starting server, version {}",
        format!("{}-{}", package_version!(), GIT_VERSION).as_str()
    );
    options.validate()?;
    let server = Arc::new(Server::new(options).await);

    let (latest_checkpoint_timestamp_receiver, reference_gas_price_receiver, monitor_handle) =
        start_server_background_tasks(server.clone(), metrics.clone()).await;

    let state = MyState {
        metrics,
        server,
        latest_checkpoint_timestamp_receiver,
        reference_gas_price_receiver,
    };

    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_origin(Any)
        .allow_headers(Any)
        .expose_headers(Any);

    let app = get_mysten_service(package_name!(), package_version!())
        .merge(
            axum::Router::new()
                .route("/v1/fetch_key", post(handle_fetch_key))
                .route("/v1/service", get(handle_get_service))
                .layer(from_fn_with_state(state.clone(), handle_request_headers))
                .layer(map_response(add_response_headers))
                // Outside most middlewares that tracks metrics for HTTP requests and response
                // status.
                .layer(from_fn_with_state(
                    state.metrics.clone(),
                    metrics_middleware,
                ))
                .with_state(state),
        )
        .layer(cors);

    tokio::select! {
        server_result = serve(app) => {
            error!("Server stopped with status {:?}", server_result);
            std::process::exit(1);
        }
        monitor_result = monitor_handle => {
            error!("Background tasks stopped with error: {:?}", monitor_result);
            std::process::exit(1);
        }
    }
}

/// Creates a [Duration] from a given number of minutes.
/// Can be removed once the `Duration::from_mins` method is stabilized.
pub const fn from_mins(mins: u16) -> Duration {
    // safe cast since 64 bits is more than enough to hold 2^16 * 60 seconds
    Duration::from_secs((mins * 60) as u64)
}

#[derive(Clone)]
enum MasterKeys {
    Open {
        master_key: IbeMasterKey,
    },
    Permissioned {
        pkg_id_to_key: HashMap<ObjectID, IbeMasterKey>,
        key_server_oid_to_key: HashMap<ObjectID, IbeMasterKey>,
    },
}

impl MasterKeys {
    fn load(options: &KeyServerOptions) -> Result<Self> {
        info!("Loading keys from env variables");
        match &options.server_mode {
            ServerMode::Open { .. } => {
                let master_key = match decode_master_key::<DefaultEncoding>("MASTER_KEY") {
                    Ok(master_key) => master_key,

                    // TODO: Fallback to Base64 encoding for backward compatibility.
                    Err(_) => decode_master_key::<Base64>("MASTER_KEY")?,
                };
                Ok(MasterKeys::Open { master_key })
            }
            ServerMode::Permissioned { client_configs } => {
                let mut pkg_id_to_key = HashMap::new();
                let mut key_server_oid_to_key = HashMap::new();
                for config in client_configs {
                    let key = match &config.client_master_key {
                        ClientKeyType::Derived { derivation_index } => ibe::derive_master_key(
                            &decode_byte_array::<DefaultEncoding, SEED_LENGTH>("MASTER_KEY")?,
                            *derivation_index,
                        ),
                        ClientKeyType::Imported { env_var } => {
                            decode_master_key::<DefaultEncoding>(env_var)?
                        }
                        ClientKeyType::Exported { .. } => continue,
                    };

                    info!(
                        "Client {:?} uses public key: {:?}",
                        config.name,
                        DefaultEncoding::encode(
                            bcs::to_bytes(&ibe::public_key_from_master_key(&key))
                                .expect("valid pk")
                        )
                    );

                    for pkg_id in &config.package_ids {
                        pkg_id_to_key.insert(*pkg_id, key);
                    }
                    key_server_oid_to_key.insert(config.key_server_object_id, key);
                }
                Ok(MasterKeys::Permissioned {
                    pkg_id_to_key,
                    key_server_oid_to_key,
                })
            }
        }
    }

    fn has_key_for_package(&self, id: &ObjectID) -> Result<(), InternalError> {
        self.get_key_for_package(id).map(|_| ())
    }

    fn get_key_for_package(&self, id: &ObjectID) -> Result<&IbeMasterKey, InternalError> {
        match self {
            MasterKeys::Open { master_key } => Ok(master_key),
            MasterKeys::Permissioned { pkg_id_to_key, .. } => pkg_id_to_key
                .get(id)
                .ok_or(InternalError::UnsupportedPackageId),
        }
    }

    fn get_key_for_key_server(&self, id: &ObjectID) -> Result<&IbeMasterKey, InternalError> {
        match self {
            MasterKeys::Open { master_key } => Ok(master_key),
            MasterKeys::Permissioned {
                key_server_oid_to_key,
                ..
            } => key_server_oid_to_key
                .get(id)
                .ok_or(InternalError::InvalidServiceId),
        }
    }
}

// test master keys

/// Read a byte array from an environment variable and decode it using the specified encoding.
fn decode_byte_array<E: Encoding, const N: usize>(env_name: &str) -> Result<[u8; N]> {
    let hex_string =
        env::var(env_name).map_err(|_| anyhow!("Environment variable {} must be set", env_name))?;
    let bytes = E::decode(&hex_string)
        .map_err(|_| anyhow!("Environment variable {} should be hex encoded", env_name))?;
    bytes.try_into().map_err(|_| {
        anyhow!(
            "Invalid byte array length for environment variable {env_name}. Must be {N} bytes long"
        )
    })
}

/// Read a master key from an environment variable.
fn decode_master_key<E: Encoding>(env_name: &str) -> Result<IbeMasterKey> {
    let bytes = decode_byte_array::<E, MASTER_KEY_LENGTH>(env_name)?;
    IbeMasterKey::from_byte_array(&bytes)
        .map_err(|_| anyhow!("Invalid master key for environment variable {env_name}"))
}

/// Read an ObjectID from an environment variable.
fn decode_object_id(env_name: &str) -> Result<ObjectID> {
    let hex_string =
        env::var(env_name).map_err(|_| anyhow!("Environment variable {} must be set", env_name))?;
    ObjectID::from_hex_literal(&hex_string)
        .map_err(|_| anyhow!("Invalid ObjectID for environment variable {env_name}"))
}

#[test]
fn test_master_keys_open_mode() {
    use fastcrypto::groups::GroupElement;
    use temp_env::with_vars;

    let options = KeyServerOptions::new_open_server_with_default_values(
        Network::Testnet,
        ObjectID::from_hex_literal("0x1").unwrap(),
        ObjectID::from_hex_literal("0x2").unwrap(),
    );

    with_vars([("MASTER_KEY", None::<&str>)], || {
        assert!(MasterKeys::load(&options).is_err());
    });

    let sk = IbeMasterKey::generator();
    let sk_as_bytes = DefaultEncoding::encode(bcs::to_bytes(&sk).unwrap());
    with_vars([("MASTER_KEY", Some(sk_as_bytes))], || {
        let mk = MasterKeys::load(&options);
        assert_eq!(
            mk.unwrap()
                .get_key_for_package(&ObjectID::from_hex_literal("0x1").unwrap())
                .unwrap(),
            &sk
        );
    });
}

#[test]
fn test_master_keys_permissioned_mode() {
    use crate::key_server_options::ClientConfig;
    use fastcrypto::groups::GroupElement;
    use temp_env::with_vars;

    let mut options = KeyServerOptions::new_open_server_with_default_values(
        Network::Testnet,
        ObjectID::from_hex_literal("0x1").unwrap(),
        ObjectID::from_hex_literal("0x2").unwrap(),
    );
    options.server_mode = ServerMode::Permissioned {
        client_configs: vec![
            ClientConfig {
                name: "alice".to_string(),
                package_ids: vec![ObjectID::from_hex_literal("0x1").unwrap()],
                key_server_object_id: ObjectID::from_hex_literal("0x2").unwrap(),
                client_master_key: ClientKeyType::Imported {
                    env_var: "ALICE_KEY".to_string(),
                },
            },
            ClientConfig {
                name: "bob".to_string(),
                package_ids: vec![ObjectID::from_hex_literal("0x3").unwrap()],
                key_server_object_id: ObjectID::from_hex_literal("0x4").unwrap(),
                client_master_key: ClientKeyType::Derived {
                    derivation_index: 100,
                },
            },
            ClientConfig {
                name: "dan".to_string(),
                package_ids: vec![ObjectID::from_hex_literal("0x5").unwrap()],
                key_server_object_id: ObjectID::from_hex_literal("0x6").unwrap(),
                client_master_key: ClientKeyType::Derived {
                    derivation_index: 200,
                },
            },
        ],
    };
    let sk = IbeMasterKey::generator();
    let sk_as_bytes = DefaultEncoding::encode(bcs::to_bytes(&sk).unwrap());
    let seed = [1u8; 32];
    with_vars(
        [
            ("MASTER_KEY", Some(sk_as_bytes.clone())),
            ("ALICE_KEY", Some(DefaultEncoding::encode(seed))),
        ],
        || {
            let mk = MasterKeys::load(&options).unwrap();
            let k1 = mk.get_key_for_key_server(&ObjectID::from_hex_literal("0x4").unwrap());
            let k2 = mk.get_key_for_key_server(&ObjectID::from_hex_literal("0x6").unwrap());
            assert!(k1.is_ok());
            assert_ne!(k1, k2);
        },
    );
    with_vars(
        [
            ("MASTER_KEY", None::<&str>),
            ("ALICE_KEY", Some(&DefaultEncoding::encode(seed))),
        ],
        || {
            assert!(MasterKeys::load(&options).is_err());
        },
    );
    with_vars(
        [
            ("MASTER_KEY", Some(&sk_as_bytes)),
            ("ALICE_KEY", None::<&String>),
        ],
        || {
            assert!(MasterKeys::load(&options).is_err());
        },
    );
}
