// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::errors::InternalError::{DeprecatedSDKVersion, InvalidSDKVersion};
use crate::externals::{current_epoch_time, duration_since, get_reference_gas_price};
use crate::metrics::{call_with_duration, observation_callback, status_callback, Metrics};
use crate::signed_message::{signed_message, signed_request};
use crate::types::MasterKeyPOP;
use anyhow::Result;
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue};
use axum::middleware::{from_fn_with_state, map_response, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{extract::State, Json};
use core::time::Duration;
use crypto::elgamal::encrypt;
use crypto::ibe;
use crypto::ibe::create_proof_of_possession;
use errors::InternalError;
use externals::get_latest_checkpoint_timestamp;
use fastcrypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::VerifyingKey;
use jsonrpsee::core::ClientError;
use jsonrpsee::types::error::{INVALID_PARAMS_CODE, METHOD_NOT_FOUND_CODE};
use mysten_service::get_mysten_service;
use mysten_service::metrics::start_basic_prometheus_server;
use mysten_service::package_name;
use mysten_service::package_version;
use mysten_service::serve;
use rand::thread_rng;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use std::future::Future;
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
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, info, warn};
use types::{ElGamalPublicKey, ElgamalEncryption, ElgamalVerificationKey, IbeMasterKey, Network};
use valid_ptb::ValidPtb;

mod cache;
mod errors;
mod externals;
mod signed_message;
mod types;
mod valid_ptb;

mod metrics;
#[cfg(test)]
pub mod tests;

/// The allowed staleness of the full node.
/// When setting this duration, note a timestamp on Sui may be a bit late compared to
/// the current time, but it shouldn't be more than a second.
const ALLOWED_STALENESS: Duration = Duration::from_secs(120);

/// The interval at which the latest checkpoint timestamp is updated.
const CHECKPOINT_UPDATE_INTERVAL: Duration = Duration::from_secs(10);

/// The interval at which the reference gas price is updated.
const RGP_UPDATE_INTERVAL: Duration = Duration::from_secs(60);

/// The maximum time to live for a session key.
const SESSION_KEY_TTL_MAX: u16 = 30;

/// The 1% of the max budget.
const GAS_BUDGET: u64 = 500_000_000;

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The minimum version of the SDK that is required to use this service.
const SDK_VERSION_REQUIREMENT: &str = ">=0.3.5";

// The "session" certificate, signed by the user
#[derive(Clone, Serialize, Deserialize, Debug)]
struct Certificate {
    pub user: SuiAddress,
    pub session_vk: Ed25519PublicKey,
    pub creation_time: u64,
    pub ttl_min: u16,
    pub signature: GenericSignature,
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
    network: Network,
    master_key: IbeMasterKey,
    key_server_object_id: ObjectID,
    key_server_object_id_sig: MasterKeyPOP,
    sdk_version_requirement: VersionReq,
}

impl Server {
    async fn new(
        master_key: IbeMasterKey,
        network: Network,
        key_server_object_id: ObjectID,
    ) -> Self {
        let sui_client = SuiClientBuilder::default()
            .build(&network.node_url())
            .await
            .expect("SuiClientBuilder should not failed unless provided with invalid network url");
        info!(
            "Server started with public key: {:?} and network: {:?}",
            Base64::encode(
                bcs::to_bytes(&ibe::public_key_from_master_key(&master_key)).expect("valid pk")
            ),
            network
        );

        let key_server_object_id_sig =
            create_proof_of_possession(&master_key, &key_server_object_id.into_bytes());

        let sdk_version_requirement =
            VersionReq::parse(SDK_VERSION_REQUIREMENT).expect("valid SDK version requirement");

        Server {
            sui_client,
            network,
            master_key,
            key_server_object_id,
            key_server_object_id_sig,
            sdk_version_requirement,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn check_signature(
        &self,
        pkg_id: &ObjectID,
        ptb: &ProgrammableTransaction,
        enc_key: &ElGamalPublicKey,
        enc_verification_key: &ElgamalVerificationKey,
        session_sig: &Ed25519Signature,
        cert: &Certificate,
        req_id: Option<&str>,
    ) -> Result<(), InternalError> {
        // Check certificate.
        if cert.ttl_min > SESSION_KEY_TTL_MAX
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

        let msg = signed_message(pkg_id, &cert.session_vk, cert.creation_time, cert.ttl_min);
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
        ptb_str: &str,
        enc_key: &ElGamalPublicKey,
        enc_verification_key: &ElgamalVerificationKey,
        request_signature: &Ed25519Signature,
        certificate: &Certificate,
        gas_price: u64,
        metrics: Option<&Metrics>,
        req_id: Option<&str>,
    ) -> Result<Vec<KeyId>, InternalError> {
        debug!(
            "Checking request for ptb_str: {:?}, cert {:?} (req_id: {:?})",
            ptb_str, certificate, req_id
        );
        let ptb_b64 = Base64::decode(ptb_str)
            .map_err(|_| InternalError::InvalidPTB("Invalid Base64".to_string()))?;
        let ptb: ProgrammableTransaction = bcs::from_bytes(&ptb_b64)
            .map_err(|_| InternalError::InvalidPTB("Invalid BCS".to_string()))?;
        let valid_ptb = ValidPtb::try_from(ptb.clone())?;

        // Report the number of id's in the request to the metrics.
        if let Some(m) = metrics {
            m.requests_per_number_of_ids
                .observe(valid_ptb.inner_ids().len() as f64);
        }

        // Handle package upgrades: only call the latest version but use the first as the namespace
        let (first_pkg_id, last_pkg_id) =
            call_with_duration(metrics.map(|m| &m.fetch_pkg_ids_duration), || async {
                externals::fetch_first_and_last_pkg_id(&valid_ptb.pkg_id(), &self.network).await
            })
            .await?;

        if valid_ptb.pkg_id() != last_pkg_id {
            debug!(
                "Last package version is {:?} while ptb uses {:?} (req_id: {:?})",
                last_pkg_id,
                valid_ptb.pkg_id(),
                req_id
            );
            return Err(InternalError::OldPackageVersion);
        }

        // Check all conditions
        self.check_signature(
            &first_pkg_id,
            &ptb,
            enc_key,
            enc_verification_key,
            request_signature,
            certificate,
            req_id,
        )
        .await?;

        call_with_duration(metrics.map(|m| &m.check_policy_duration), || async {
            self.check_policy(certificate.user, &valid_ptb, gas_price, req_id)
                .await
        })
        .await?;

        info!(
            "Valid request: {}",
            json!({ "user": certificate.user, "package_id": valid_ptb.pkg_id(), "req_id": req_id })
        );

        // return the full id with the first package id as prefix
        Ok(valid_ptb.full_ids(&first_pkg_id))
    }

    fn create_response(&self, ids: &[KeyId], enc_key: &ElGamalPublicKey) -> FetchKeyResponse {
        debug!("Checking response for ids: {:?}", ids);
        let decryption_keys = ids
            .iter()
            .map(|id| {
                // Requested key
                let key = ibe::extract(&self.master_key, id);
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
    ) -> Receiver<u64>
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

        // In case of a missed tick due to a slow responding full node, we don't need to
        // catch up but rather just delay the next tick.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        tokio::task::spawn(async move {
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
        receiver
    }

    /// Spawns a thread that fetches the latest checkpoint timestamp and sends it to a [Receiver] once per `update_interval`.
    /// Returns the [Receiver].
    async fn spawn_latest_checkpoint_timestamp_updater(
        &self,
        update_interval: Duration,
        metrics: Option<&Metrics>,
    ) -> Receiver<Timestamp> {
        self.spawn_periodic_updater(
            update_interval,
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
        update_interval: Duration,
        metrics: Option<&Metrics>,
    ) -> Receiver<u64> {
        self.spawn_periodic_updater(
            update_interval,
            get_reference_gas_price,
            "RGP",
            None::<fn(u64)>,
            None::<fn(Duration)>,
            metrics.map(|m| status_callback(&m.get_reference_gas_price_status)),
        )
        .await
    }
}

async fn handle_fetch_key(
    State(app_state): State<MyState>,
    headers: HeaderMap,
    Json(payload): Json<FetchKeyRequest>,
) -> Result<Json<FetchKeyResponse>, InternalError> {
    let req_id = headers
        .get("Request-Id")
        .map(|v| v.to_str().unwrap_or_default());

    app_state.metrics.requests.inc();
    app_state.check_full_node_is_fresh(ALLOWED_STALENESS)?;

    app_state
        .server
        .check_request(
            &payload.ptb,
            &payload.enc_key,
            &payload.enc_verification_key,
            &payload.request_signature,
            &payload.certificate,
            app_state.reference_gas_price(),
            Some(&app_state.metrics),
            req_id,
        )
        .await
        .map(|full_id| Json(app_state.server.create_response(&full_id, &payload.enc_key)))
        .tap_err(|e| app_state.metrics.observe_error(e.as_str()))
}

#[derive(Serialize, Deserialize)]
struct GetServiceResponse {
    service_id: ObjectID,
    pop: MasterKeyPOP,
    version: String,
}

async fn handle_get_service(
    State(app_state): State<MyState>,
) -> Result<Json<GetServiceResponse>, InternalError> {
    app_state.metrics.service_requests.inc();
    Ok(Json(GetServiceResponse {
        service_id: app_state.server.key_server_object_id,
        pop: app_state.server.key_server_object_id_sig,
        version: PACKAGE_VERSION.to_string(),
    }))
}

#[derive(Clone)]
struct MyState {
    metrics: Arc<Metrics>,
    server: Arc<Server>,
    latest_checkpoint_timestamp_receiver: Receiver<Timestamp>,
    reference_gas_price: Receiver<u64>,
}

impl MyState {
    fn check_full_node_is_fresh(&self, allowed_staleness: Duration) -> Result<(), InternalError> {
        let staleness = duration_since(*self.latest_checkpoint_timestamp_receiver.borrow());
        if staleness > allowed_staleness.as_millis() as i64 {
            warn!(
                "Full node is stale. Latest checkpoint is {} ms old.",
                staleness
            );
            return Err(InternalError::Failure);
        }
        Ok(())
    }

    fn reference_gas_price(&self) -> u64 {
        *self.reference_gas_price.borrow()
    }

    fn validate_sdk_version(&self, version_string: &str) -> Result<(), InternalError> {
        let version = Version::parse(version_string).map_err(|_| InvalidSDKVersion)?;
        if !self.server.sdk_version_requirement.matches(&version) {
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
        .ok_or(InvalidSDKVersion)
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
    response.headers_mut().insert(
        "X-KeyServer-Version",
        HeaderValue::from_static(PACKAGE_VERSION),
    );
    response
}

#[tokio::main]
async fn main() -> Result<()> {
    let master_key = env::var("MASTER_KEY").expect("MASTER_KEY must be set");
    let object_id = env::var("KEY_SERVER_OBJECT_ID").expect("KEY_SERVER_OBJECT_ID must be set");
    let network = env::var("NETWORK")
        .map(|n| Network::from_str(&n))
        .unwrap_or(Network::Testnet);

    let _guard = mysten_service::logging::init();
    info!("Logging set up, setting up metrics");

    // initialize metrics
    let registry = start_basic_prometheus_server();
    // hook up custom application metrics
    let metrics = Arc::new(Metrics::new(&registry));
    info!("Metrics set up, starting service");

    info!("Starting server, version {}", PACKAGE_VERSION);

    let s = Server::new(
        IbeMasterKey::from_byte_array(
            &Base64::decode(&master_key)
                .expect("MASTER_KEY should be base64 encoded")
                .try_into()
                .expect("Invalid MASTER_KEY length"),
        )
        .expect("Invalid MASTER_KEY value"),
        network,
        ObjectID::from_hex_literal(&object_id).expect("Invalid KEY_SERVER_OBJECT_ID"),
    )
    .await;
    let server = Arc::new(s);

    // Spawn tasks that update the state of the server.
    let latest_checkpoint_timestamp_receiver = server
        .spawn_latest_checkpoint_timestamp_updater(CHECKPOINT_UPDATE_INTERVAL, Some(&metrics))
        .await;
    let reference_gas_price = server
        .spawn_reference_gas_price_updater(RGP_UPDATE_INTERVAL, Some(&metrics))
        .await;

    let state = MyState {
        metrics,
        server,
        latest_checkpoint_timestamp_receiver,
        reference_gas_price,
    };

    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_origin(Any)
        .allow_headers(Any);

    let app = get_mysten_service(package_name!(), package_version!())
        .merge(
            axum::Router::new()
                .route("/v1/fetch_key", post(handle_fetch_key))
                .route("/v1/service", get(handle_get_service))
                .layer(from_fn_with_state(state.clone(), handle_request_headers))
                .layer(map_response(add_response_headers))
                .with_state(state),
        )
        .layer(cors);

    serve(app).await
}
