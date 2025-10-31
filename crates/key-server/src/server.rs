// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::errors::InternalError::{
    DeprecatedSDKVersion, InvalidSDKVersion, MissingRequiredHeader,
};
use crate::externals::get_reference_gas_price;
use crate::key_server_options::ServerMode;
use crate::metrics::{call_with_duration, status_callback, Metrics};
use crate::metrics_push::create_push_client;
use crate::mvr::mvr_forward_resolution;
use crate::periodic_updater::spawn_periodic_updater;
use crate::signed_message::signed_request;
use crate::time::current_epoch_time;
use crate::time::{checked_duration_since, from_mins};
use crate::types::{MasterKeyPOP, Network};
use anyhow::{Context, Result};
use axum::extract::{Query, Request};
use axum::http::{HeaderMap, HeaderValue};
use axum::middleware::{from_fn_with_state, map_response, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{extract::State, Json, Router};
use core::time::Duration;
use crypto::elgamal::encrypt;
use crypto::ibe;
use crypto::ibe::create_proof_of_possession;
use crypto::prefixed_hex::PrefixedHex;
use errors::InternalError;
use fastcrypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::traits::VerifyingKey;
use futures::future::pending;
use jsonrpsee::core::ClientError;
use jsonrpsee::types::error::{INVALID_PARAMS_CODE, METHOD_NOT_FOUND_CODE};
use key_server_options::KeyServerOptions;
use master_keys::MasterKeys;
use metrics::metrics_middleware;
use move_core_types::identifier::Identifier;
use mysten_service::get_mysten_service;
use mysten_service::metrics::start_prometheus_server;
use mysten_service::package_name;
use mysten_service::package_version;
use mysten_service::serve;
use rand::thread_rng;
use seal_sdk::types::{DecryptionKey, ElGamalPublicKey, ElgamalVerificationKey, KeyId};
use seal_sdk::{signed_message, FetchKeyResponse};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use sui_rpc::client::v2::Client as SuiGrpcClient;
use sui_rpc_client::SuiRpcClient;
use sui_sdk::error::Error;
use sui_sdk::rpc_types::{SuiExecutionStatus, SuiTransactionBlockEffectsAPI};
use sui_sdk::types::base_types::{ObjectID, SuiAddress};
use sui_sdk::types::signature::GenericSignature;
use sui_sdk::types::transaction::{ProgrammableTransaction, TransactionData, TransactionKind};
use sui_sdk::verify_personal_message_signature::verify_personal_message_signature;
use sui_sdk::SuiClientBuilder;
use sui_types::transaction::Argument::Input;
use sui_types::transaction::{CallArg, Command, ObjectArg};
use sui_types::SUI_CLOCK_OBJECT_ID;
use tap::tap::TapFallible;
use tap::Tap;
use tokio::sync::watch::Receiver;
use tokio::task::JoinHandle;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{debug, error, info, warn};
use valid_ptb::ValidPtb;

mod cache;
mod errors;
mod externals;
mod signed_message;
mod sui_rpc_client;
mod types;
mod utils;
mod valid_ptb;

mod key_server_options;
mod master_keys;
mod metrics;
mod metrics_push;
mod mvr;
mod periodic_updater;
#[cfg(test)]
pub mod tests;
mod time;

const GAS_BUDGET: u64 = 500_000_000;
const GIT_VERSION: &str = utils::git_version!();

// Transaction size limit: 128KB + 33% for base64 + some extra room for other parameters
const MAX_REQUEST_SIZE: usize = 180 * 1024;

/// Default encoding used for master and public keys for the key server.
type DefaultEncoding = PrefixedHex;

// TODO: Remove legacy once key-server crate uses sui-sdk-types.
#[derive(Clone, Serialize, Deserialize, Debug)]
struct Certificate {
    pub user: SuiAddress,
    pub session_vk: Ed25519PublicKey,
    pub creation_time: u64,
    pub ttl_min: u16,
    pub signature: GenericSignature,
    pub mvr_name: Option<String>,
}

// TODO: Remove legacy once key-server crate uses sui-sdk-types.
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

#[derive(Clone)]
struct Server {
    sui_rpc_client: SuiRpcClient,
    master_keys: MasterKeys,
    key_server_oid_to_pop: HashMap<ObjectID, MasterKeyPOP>,
    options: KeyServerOptions,
}

impl Server {
    async fn new(options: KeyServerOptions, metrics: Option<Arc<Metrics>>) -> Self {
        let sui_rpc_client = SuiRpcClient::new(
            SuiClientBuilder::default()
                .request_timeout(options.rpc_config.timeout)
                .build(&options.network.node_url())
                .await
                .expect(
                    "SuiClientBuilder should not failed unless provided with invalid network url",
                ),
            SuiGrpcClient::new(options.network.node_url()).expect("Failed to create SuiGrpcClient"),
            options.rpc_config.retry_config.clone(),
            metrics,
        );
        info!("Server started with network: {:?}", options.network);
        let master_keys = MasterKeys::load(&options).unwrap_or_else(|e| {
            panic!("Failed to load master keys: {e}");
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
            sui_rpc_client,
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
        // Check certificate

        // TTL of the session key must be smaller than the allowed max
        let ttl = from_mins(cert.ttl_min);
        if ttl > self.options.session_key_ttl_max {
            debug!(
                "Certificate has invalid time-to-live (req_id: {:?})",
                req_id
            );
            return Err(InternalError::InvalidCertificate);
        }

        // Check that the creation time is not in the future and that the certificate has not expired
        match checked_duration_since(cert.creation_time) {
            None => {
                debug!(
                    "Certificate has invalid creation time (req_id: {:?})",
                    req_id
                );
                return Err(InternalError::InvalidCertificate);
            }
            Some(duration) => {
                if duration > ttl {
                    debug!("Certificate has expired (req_id: {:?})", req_id);
                    return Err(InternalError::InvalidCertificate);
                }
            }
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
            Some(self.sui_rpc_client.sui_client().clone()),
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

    fn add_staleness_check_to_ptb(&self, ptb: &mut ProgrammableTransaction) {
        let now = current_epoch_time();
        ptb.inputs.push(CallArg::from(now));
        let now_index = ptb.inputs.len() - 1;

        let allowed_staleness = self.options.allowed_staleness.as_millis() as u64; // Two minutes
        ptb.inputs.push(CallArg::from(allowed_staleness));
        let allowed_staleness_index = ptb.inputs.len() - 1;

        let clock_index = match ptb.inputs.iter().position(|arg| {
            matches!(
                arg,
                CallArg::Object(ObjectArg::SharedObject {
                    id: SUI_CLOCK_OBJECT_ID,
                    ..
                })
            )
        }) {
            Some(i) => i, // The clock is already given as input i
            None => {
                // The clock is not already part of the PTB, so we add it
                ptb.inputs.push(CallArg::CLOCK_IMM);
                ptb.inputs.len() - 1
            }
        };

        let staleness_check = Command::move_call(
            self.options.seal_package,
            Identifier::from_str("time").unwrap(),
            Identifier::from_str("check_duration_since").unwrap(),
            vec![],
            vec![
                Input(now_index as u16),
                Input(allowed_staleness_index as u16),
                Input(clock_index as u16),
            ],
        );

        ptb.commands.insert(0, staleness_check);
    }

    async fn check_policy(
        &self,
        sender: SuiAddress,
        vptb: &ValidPtb,
        gas_price: u64,
        req_id: Option<&str>,
        metrics: Option<&Metrics>,
    ) -> Result<(), InternalError> {
        debug!(
            "Checking policy for ptb: {:?} (req_id: {:?})",
            vptb.ptb(),
            req_id
        );

        // Add a staleness check as the first command in the PTB
        let mut ptb = vptb.ptb().clone();
        self.add_staleness_check_to_ptb(&mut ptb);

        // Evaluate the `seal_approve*` function
        let tx_data = TransactionData::new_with_gas_coins(
            TransactionKind::ProgrammableTransaction(ptb),
            sender,
            vec![], // Empty gas payment for dry run
            GAS_BUDGET,
            gas_price,
        );
        let dry_run_res = self
            .sui_rpc_client
            .dry_run_transaction_block(tx_data.clone())
            .await
            .map_err(|e| {
                if let Error::RpcError(ClientError::Call(ref e)) = e {
                    match e.code() {
                        INVALID_PARAMS_CODE => {
                            // This error is generic and happens when one of the parameters of the Move call in the PTB is invalid.
                            // One reason is that one of the parameters does not exist, in which case it could be a newly created object that the FN has not yet seen.
                            // There are other possible reasons, so we return the entire message to the user to allow debugging.
                            // Note that the message is a message from the JSON RPC API, so it is already formatted and does not contain any sensitive information.
                            debug!("Invalid parameter: {}", e.message());
                            return InternalError::InvalidParameter(e.message().to_string());
                        }
                        METHOD_NOT_FOUND_CODE => {
                            // This means that the seal_approve function is not found on the given module.
                            debug!("Function not found: {:?}", e);
                            return InternalError::InvalidPTB(
                                "The seal_approve function was not found on the module".to_string(),
                            );
                        }
                        _ => {}
                    }
                }
                InternalError::Failure(format!(
                    "Dry run execution failed ({e:?}) (req_id: {req_id:?})"
                ))
            })?;

        // Record the gas cost. Only do this in permissioned mode to avoid high cardinality metrics in public mode.
        if let Some(m) = metrics {
            if matches!(
                self.options.server_mode,
                ServerMode::Permissioned { client_configs: _ }
            ) {
                let package = vptb.pkg_id().to_hex_uncompressed();
                m.dry_run_gas_cost_per_package
                    .with_label_values(&[&package])
                    .observe(dry_run_res.effects.gas_cost_summary().computation_cost as f64);
            }
        }

        debug!("Dry run response: {:?} (req_id: {:?})", dry_run_res, req_id);
        if let SuiExecutionStatus::Failure { error } = dry_run_res.effects.status() {
            debug!(
                "Dry run execution asserted (req_id: {:?}) {:?}",
                req_id, error
            );
            return Err(InternalError::NoAccess(error.clone()));
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
                externals::fetch_first_pkg_id(&valid_ptb.pkg_id(), &self.sui_rpc_client).await
            })
            .await?;

        // Make sure that the package is supported.
        self.master_keys.has_key_for_package(&first_pkg_id)?;

        // Check if the package id that MVR name points matches the first package ID, if provided.
        externals::check_mvr_package_id(
            &mvr_name,
            &self.sui_rpc_client,
            &self.options,
            first_pkg_id,
            req_id,
        )
        .await?;

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
            self.check_policy(certificate.user, valid_ptb, gas_price, req_id, metrics)
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
        debug!(
            "Creating response for ids: {:?}",
            ids.iter().map(Hex::encode).collect::<Vec<_>>()
        );
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

    /// Spawns a thread that fetches RGP and sends it to a [Receiver] once per `update_interval`.
    /// Returns the [Receiver].
    async fn spawn_reference_gas_price_updater(
        &self,
        metrics: Option<&Metrics>,
    ) -> (Receiver<u64>, JoinHandle<()>) {
        spawn_periodic_updater(
            &self.sui_rpc_client,
            self.options.rgp_update_interval,
            get_reference_gas_price,
            "RGP",
            None::<fn(u64)>,
            None::<fn(Duration)>,
            metrics.map(|m| status_callback(&m.get_reference_gas_price_status)),
        )
        .await
    }

    /// Spawn a metrics push background jobs that push metrics to seal-proxy
    fn spawn_metrics_push_job(&self, registry: prometheus::Registry) -> JoinHandle<()> {
        let push_config = self.options.metrics_push_config.clone();
        if let Some(push_config) = push_config {
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(push_config.push_interval);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                let mut client = create_push_client();
                tracing::info!("starting metrics push to '{}'", &push_config.push_url);
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            if let Err(error) = metrics_push::push_metrics(
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
}

#[allow(clippy::single_match)]
async fn handle_fetch_key_internal(
    app_state: &MyState,
    payload: &FetchKeyRequest,
    req_id: Option<&str>,
    sdk_version: &str,
) -> Result<(ObjectID, Vec<KeyId>), InternalError> {
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
        .await
        .tap(|r| {
            let request_info = json!({ "user": payload.certificate.user, "package_id": valid_ptb.pkg_id(), "req_id": req_id, "sdk_version": sdk_version });
            match r {
                Ok(_) => info!("Valid request: {request_info}"),
                Err(InternalError::Failure(s)) => warn!("Check request failed with debug message '{s}': {request_info}"),
                _ => {},
            }
        })
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

    let service_id = params
        .get("service_id")
        .ok_or(InternalError::InvalidServiceId)
        .and_then(|id| {
            ObjectID::from_hex_literal(id).map_err(|_| InternalError::InvalidServiceId)
        })?;

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
    reference_gas_price_receiver: Receiver<u64>,
}

impl MyState {
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
            debug!("Invalid SDK version: {:?}", e);
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
///  - reference gas price updater.
///  - optional metrics pusher (if configured).
///
/// The returned JoinHandle can be used to catch any tasks error or panic.
async fn start_server_background_tasks(
    server: Arc<Server>,
    metrics: Arc<Metrics>,
    registry: prometheus::Registry,
) -> (Receiver<u64>, JoinHandle<anyhow::Result<()>>) {
    // Spawn background reference gas price updater.
    let (reference_gas_price_receiver, reference_gas_price_handle) = server
        .spawn_reference_gas_price_updater(Some(&metrics))
        .await;

    // Spawn metrics push task
    let metrics_push_handle = server.spawn_metrics_push_job(registry);

    // Spawn a monitor task that will exit the program if any updater task panics
    let handle: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        tokio::select! {
            result = reference_gas_price_handle => {
                if let Err(e) = result {
                    error!("Reference gas price updater panicked: {:?}", e);
                    if e.is_panic() {
                        std::panic::resume_unwind(e.into_panic());
                    }
                    return Err(e.into());
                }
            }
            result = metrics_push_handle => {
                if let Err(e) = result {
                    error!("Metrics push task panicked: {:?}", e);
                    if e.is_panic() {
                        std::panic::resume_unwind(e.into_panic());
                    }
                    return Err(e.into());
                }
            }
        }

        unreachable!("One of the background tasks should have returned an error");
    });

    (reference_gas_price_receiver, handle)
}

#[tokio::main]
async fn main() -> Result<()> {
    let _guard = mysten_service::logging::init();
    let (monitor_handle, app) = app().await?;

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

pub(crate) async fn app() -> Result<(JoinHandle<Result<()>>, Router)> {
    // If CONFIG_PATH is set, read the configuration from the file.
    // Otherwise, use the local environment variables.
    let options = match env::var("CONFIG_PATH") {
        Ok(config_path) => {
            info!("Loading config file: {}", config_path);
            let mut opts: KeyServerOptions = serde_yaml::from_reader(
                std::fs::File::open(&config_path)
                    .context(format!("Cannot open configuration file {config_path}"))?,
            )
            .expect("Failed to parse configuration file");

            // Handle Custom network NODE_URL configuration
            if let Network::Custom {
                ref mut node_url, ..
            } = opts.network
            {
                let env_node_url = env::var("NODE_URL").ok();

                match (node_url.as_ref(), env_node_url.as_ref()) {
                    (Some(_), Some(_)) => {
                        panic!("NODE_URL cannot be provided in both config file and environment variable. Please use only one source.");
                    }
                    (None, Some(url)) => {
                        info!("Using NODE_URL from environment variable: {}", url);
                        *node_url = Some(url.clone());
                    }
                    (Some(url), None) => {
                        info!("Using NODE_URL from config file: {}", url);
                    }
                    (None, None) => {
                        panic!("Custom network requires NODE_URL to be set either in config file or as environment variable");
                    }
                }
            }

            opts
        }
        Err(_) => {
            info!("Using local environment variables for configuration, should only be used for testing");
            let network = env::var("NETWORK")
                .map(|n| Network::from_str(&n))
                .unwrap_or(Network::Testnet);
            KeyServerOptions::new_open_server_with_default_values(
                network,
                utils::decode_object_id("KEY_SERVER_OBJECT_ID")?,
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
    let server = Arc::new(Server::new(options, Some(metrics.clone())).await);

    let (reference_gas_price_receiver, monitor_handle) =
        start_server_background_tasks(server.clone(), metrics.clone(), registry.clone()).await;

    let state = MyState {
        metrics,
        server,
        reference_gas_price_receiver,
    };

    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_origin(Any)
        .allow_headers(Any)
        .expose_headers(Any);

    let app = get_mysten_service::<MyState>(package_name!(), package_version!())
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
                )),
        )
        .with_state(state)
        // Global body size limit
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_SIZE))
        .layer(cors);
    Ok((monitor_handle, app))
}
