// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::committee_monitor::{
    fetch_partial_key_server, monitor_committee_transition, validate_committee_at_startup,
    validate_committee_with_next_at_startup,
};
use crate::errors::InternalError::{
    DeprecatedSDKVersion, InvalidSDKVersion, MissingRequiredHeader,
};
use crate::externals::get_reference_gas_price;
use crate::key_server_options::ServerMode;
use crate::metrics::{call_with_duration, observation_callback, status_callback, Metrics};
use crate::metrics_push::create_push_client;
use crate::mvr::mvr_forward_resolution;
use crate::periodic_updater::spawn_periodic_updater;
use crate::signed_message::signed_request;
use crate::time::checked_duration_since;
use crate::time::from_mins;
use crate::time::{duration_since_as_f64, saturating_duration_since};
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
use externals::get_latest_checkpoint_timestamp;
use fastcrypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::traits::VerifyingKey;
use futures::future::pending;
use key_server_options::KeyServerOptions;
use master_keys::MasterKeys;
use metrics::metrics_middleware;
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
use std::sync::Arc;
use sui_crypto::{SuiVerifier, UserSignatureVerifier};
use sui_rpc::Client;
use sui_rpc_client::{SuiExecutionStatus, SuiRpcClient};
use sui_sdk::types::base_types::{ObjectID, SuiAddress};
use sui_sdk::types::signature::GenericSignature;
use sui_sdk::types::transaction::{ProgrammableTransaction, TransactionData, TransactionKind};
use tap::tap::TapFallible;
use tap::Tap;
use tokio::sync::watch::Receiver;
use tokio::task::JoinHandle;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{debug, error, info, warn};
use valid_ptb::ValidPtb;

mod cache;
mod committee_monitor;
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

/// UNIX timestamp in milliseconds.
type Timestamp = u64;

#[derive(Clone)]
struct Server {
    sui_rpc_client: SuiRpcClient,
    master_keys: MasterKeys,
    key_server_oid_to_pop: HashMap<ObjectID, MasterKeyPOP>,
    options: KeyServerOptions,
}

impl Server {
    async fn new(options: KeyServerOptions, metrics: Option<Arc<Metrics>>) -> Self {
        let grpc_url = &options.network.node_url();

        let sui_rpc_client = SuiRpcClient::new(
            Client::new(grpc_url)
                .expect("Grpc server should not failed unless provided with invalid network url"),
            options.rpc_config.retry_config.clone(),
            metrics,
        );

        info!("Server started with network: {:?}", options.network);
        let master_keys = MasterKeys::load(&options).unwrap_or_else(|e| {
            panic!("Failed to load master keys: {}", e);
        });

        let mut key_server_oid_to_pop: HashMap<ObjectID, MasterKeyPOP> = options
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

        // Validate committee at startup based on mode
        match options.server_mode {
            // Case 1: Committee mode without next_committee_id
            ServerMode::Committee {
                key_server_object_id,
                member_address,
                committee_id,
                next_committee_id: None,
            } => {
                info!("Committee mode without next_committee_id - validating committee at startup");
                let partial_key_server_id = validate_committee_at_startup(
                    &sui_rpc_client,
                    committee_id,
                    key_server_object_id,
                    member_address,
                )
                .await
                .unwrap_or_else(|e| {
                    panic!("Committee validation failed: {:?}", e);
                });

                // Use the PartialKeyServer object ID to create POP with MASTER_KEY
                let key = master_keys
                    .get_key_for_key_server(&key_server_object_id)
                    .expect("checked already");
                let pop = create_proof_of_possession(key, &partial_key_server_id.into_bytes());

                info!(
                    "Using PartialKeyServer {} for POP with MASTER_KEY (main KeyServer: {})",
                    partial_key_server_id, key_server_object_id
                );

                key_server_oid_to_pop.insert(partial_key_server_id, pop);
            }

            // Case 2: Committee mode with next_committee_id
            ServerMode::Committee {
                key_server_object_id,
                member_address,
                committee_id,
                next_committee_id: Some(next_committee_id),
            } => {
                info!("Committee mode with next_committee_id - validating committee transition at startup");
                let next_partial_key_server_id = validate_committee_with_next_at_startup(
                    &sui_rpc_client,
                    committee_id,
                    next_committee_id,
                    key_server_object_id,
                    member_address,
                )
                .await
                .unwrap_or_else(|e| {
                    panic!("Committee transition validation failed: {:?}", e);
                });

                if let Some(new_partial_key_server_id) = next_partial_key_server_id {
                    // Rotation complete: old committee deleted, next committee finalized
                    info!("Rotation complete: using NEXT_MASTER_KEY for new PartialKeyServer");

                    // Load NEXT_MASTER_KEY and create POP for new PartialKeyServer
                    let next_master_key =
                        crate::utils::decode_master_key::<DefaultEncoding>("NEXT_MASTER_KEY")
                            .unwrap_or_else(|e| {
                                panic!("Failed to load NEXT_MASTER_KEY: {:?}", e);
                            });

                    let new_pop = create_proof_of_possession(
                        &next_master_key,
                        &new_partial_key_server_id.into_bytes(),
                    );

                    info!(
                        "Stored POP for new PartialKeyServer {} with NEXT_MASTER_KEY",
                        new_partial_key_server_id
                    );

                    key_server_oid_to_pop.insert(new_partial_key_server_id, new_pop);
                } else {
                    // Rotation in progress: store POPs for both old and new PartialKeyServers
                    info!("Committee rotation in progress - storing POPs for both old and new PartialKeyServers");

                    // Get old PartialKeyServer ID and create POP with MASTER_KEY
                    let old_partial_key_server_id = fetch_partial_key_server(
                        &sui_rpc_client,
                        key_server_object_id,
                        member_address,
                    )
                    .await
                    .unwrap_or_else(|e| {
                        panic!("Failed to fetch old PartialKeyServer: {:?}", e);
                    })
                    .unwrap_or_else(|| {
                        panic!(
                            "No old PartialKeyServer found for member {}",
                            member_address
                        );
                    });

                    let old_key = master_keys
                        .get_key_for_key_server(&key_server_object_id)
                        .expect("checked already");
                    let old_pop = create_proof_of_possession(
                        old_key,
                        &old_partial_key_server_id.into_bytes(),
                    );

                    info!(
                        "Stored POP for old PartialKeyServer {} with MASTER_KEY",
                        old_partial_key_server_id
                    );

                    key_server_oid_to_pop.insert(old_partial_key_server_id, old_pop);

                    // If NEXT_MASTER_KEY is available, also create POP for new PartialKeyServer
                    if std::env::var("NEXT_MASTER_KEY").is_ok() {
                        // Try to fetch the new PartialKeyServer (it may not exist yet if next committee isn't finalized)
                        // This is best-effort - if it fails, we'll only have the old POP
                        if let Ok(Some(new_partial_key_server_id)) = fetch_partial_key_server(
                            &sui_rpc_client,
                            key_server_object_id,
                            member_address,
                        )
                        .await
                        {
                            // Check if this is different from the old one
                            if new_partial_key_server_id != old_partial_key_server_id {
                                // Load NEXT_MASTER_KEY
                                match crate::utils::decode_master_key::<DefaultEncoding>(
                                    "NEXT_MASTER_KEY",
                                ) {
                                    Ok(next_master_key) => {
                                        let new_pop = create_proof_of_possession(
                                            &next_master_key,
                                            &new_partial_key_server_id.into_bytes(),
                                        );

                                        info!(
                                            "Also stored POP for new PartialKeyServer {} with NEXT_MASTER_KEY",
                                            new_partial_key_server_id
                                        );

                                        key_server_oid_to_pop
                                            .insert(new_partial_key_server_id, new_pop);
                                    }
                                    Err(e) => {
                                        warn!("Failed to load NEXT_MASTER_KEY, skipping new POP: {:?}", e);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            _ => {
                // Open or Permissioned mode - no additional validation needed
            }
        }

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

        // Convert GenericSignature to UserSignature via BCS
        let sig_bytes =
            bcs::to_bytes(&cert.signature).map_err(|_| InternalError::InvalidSignature)?;
        let user_signature: sui_sdk_types::UserSignature =
            bcs::from_bytes(&sig_bytes).map_err(|_| InternalError::InvalidSignature)?;

        let personal_message =
            sui_sdk_types::PersonalMessage(std::borrow::Cow::Borrowed(msg.as_bytes()));

        // Check if this is a zklogin signature - use gRPC verification for zklogin
        if matches!(user_signature, sui_sdk_types::UserSignature::ZkLogin(_)) {
            // Use gRPC signature verification for zkLogin (which handles JWKs)
            // Send the raw message bytes
            self.sui_rpc_client
                .verify_signature(msg.as_bytes(), &user_signature)
                .await
                .tap_err(|e| {
                    debug!(
                        "zkLogin signature verification failed: {:?} (req_id: {:?})",
                        e, req_id
                    );
                })
                .map_err(|_| InternalError::InvalidSignature)?;
        } else {
            // For non-zkLogin signatures, use local verification
            UserSignatureVerifier::new()
                .verify_personal_message(&personal_message, &user_signature)
                .tap_err(|e| {
                    debug!(
                        "Signature verification failed: {:?} (req_id: {:?})",
                        e, req_id
                    );
                })
                .map_err(|_| InternalError::InvalidSignature)?;
        }

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
        metrics: Option<&Metrics>,
    ) -> Result<(), InternalError> {
        debug!(
            "Checking policy for ptb: {:?} (req_id: {:?})",
            vptb.ptb(),
            req_id
        );
        // Evaluate the `seal_approve*` function
        let tx_data = TransactionData::new_with_gas_coins(
            TransactionKind::ProgrammableTransaction(vptb.ptb().clone()),
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
                let error_msg = e.message().to_string();
                // Check for common error patterns in gRPC responses
                if error_msg.contains("Invalid") || error_msg.contains("parameter") {
                    debug!("Invalid parameter: {}", error_msg);
                    return InternalError::InvalidParameter(error_msg);
                }
                if error_msg.contains("not found") || error_msg.contains("Function") {
                    debug!("Function not found: {:?}", error_msg);
                    return InternalError::InvalidPTB(
                        "The seal_approve function was not found on the module".to_string(),
                    );
                }
                InternalError::Failure(format!(
                    "Dry run execution failed ({:?}) (req_id: {:?})",
                    e, req_id
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

    /// Spawns a thread that fetches the latest checkpoint timestamp and sends it to a [Receiver] once per `update_interval`.
    /// Returns the [Receiver].
    async fn spawn_latest_checkpoint_timestamp_updater(
        &self,
        metrics: Option<&Metrics>,
    ) -> (Receiver<Timestamp>, JoinHandle<()>) {
        spawn_periodic_updater(
            &self.sui_rpc_client,
            self.options.checkpoint_update_interval,
            get_latest_checkpoint_timestamp,
            "latest checkpoint timestamp",
            metrics.map(|m| {
                observation_callback(&m.checkpoint_timestamp_delay, |ts| {
                    let duration = duration_since_as_f64(ts);
                    debug!("Latest checkpoint timestamp delay is {duration} ms");
                    duration
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

    /// Spawn a background task to monitor the committee transition.
    ///
    /// This task will:
    /// - Monitor the next_committee until it reaches Finalized state
    /// - Once Finalized, check if the old committee object has been deleted
    /// - Exit the server if the old committee is deleted
    ///
    /// Only spawns the monitor if server is in Committee mode with next_committee_id provided.
    fn spawn_committee_monitor(&self) -> JoinHandle<()> {
        if let ServerMode::Committee {
            key_server_object_id,
            member_address,
            committee_id,
            next_committee_id: Some(next_committee_id),
        } = self.options.server_mode
        {
            let sui_rpc_client = self.sui_rpc_client.clone();
            let check_interval = self.options.checkpoint_update_interval;
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(check_interval);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                info!(
                    "Starting committee monitor: old committee {}, next committee {}",
                    committee_id, next_committee_id
                );
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            match monitor_committee_transition(
                                sui_rpc_client.clone(),
                                committee_id,
                                next_committee_id,
                            ).await {
                                Ok(true) => {
                                    // Continue monitoring
                                }
                                Ok(false) => {
                                    // Next committee is finalized and old committee is still valid
                                    // Fetch the PartialKeyServer for this member
                                    info!("Committee {} is finalized. Fetching PartialKeyServer for member {}", next_committee_id, member_address);
                                    match fetch_partial_key_server(&sui_rpc_client, key_server_object_id, member_address).await {
                                        Ok(Some(partial_key_server_id)) => {
                                            info!("Successfully fetched PartialKeyServer: {}", partial_key_server_id);
                                        }
                                        Ok(None) => {
                                            error!("Could not find PartialKeyServer for member {}. Server will exit.", member_address);
                                            std::process::exit(1);
                                        }
                                        Err(e) => {
                                            error!("Failed to fetch PartialKeyServer: {:?}. Server will exit.", e);
                                            std::process::exit(1);
                                        }
                                    }
                                    // Stop monitoring
                                    info!("Stopping committee monitor - next committee {} is finalized", next_committee_id);
                                    break;
                                }
                                Err(e) => {
                                    error!("Failed to monitor committee transition: {:?}", e);
                                }
                            }
                        }
                    }
                }
            })
        } else {
            tokio::spawn(async move { pending().await })
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
    latest_checkpoint_timestamp_receiver: Receiver<Timestamp>,
    reference_gas_price_receiver: Receiver<u64>,
}

impl MyState {
    fn check_full_node_is_fresh(&self) -> Result<(), InternalError> {
        // Compute the staleness of the latest checkpoint timestamp.
        let staleness =
            saturating_duration_since(*self.latest_checkpoint_timestamp_receiver.borrow());
        if staleness > self.server.options.allowed_staleness {
            return Err(InternalError::Failure(format!(
                "Full node is stale. Latest checkpoint is {} ms old.",
                staleness.as_millis()
            )));
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
///  - background checkpoint downloader
///  - reference gas price updater.
///  - optional metrics pusher (if configured).
///  - optional committee monitor (if in Committee mode).
///
/// The returned JoinHandle can be used to catch any tasks error or panic.
async fn start_server_background_tasks(
    server: Arc<Server>,
    metrics: Arc<Metrics>,
    registry: prometheus::Registry,
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

    // Spawn metrics push task
    let metrics_push_handle = server.spawn_metrics_push_job(registry);

    // Spawn committee monitor task
    let committee_monitor_handle = server.spawn_committee_monitor();

    // Spawn a monitor task that will exit the program if any updater task panics
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
            result = metrics_push_handle => {
                if let Err(e) = result {
                    error!("Metrics push task panicked: {:?}", e);
                    if e.is_panic() {
                        std::panic::resume_unwind(e.into_panic());
                    }
                    return Err(e.into());
                }
            }
            result = committee_monitor_handle => {
                if let Err(e) = result {
                    error!("Committee monitor task panicked: {:?}", e);
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

    let (latest_checkpoint_timestamp_receiver, reference_gas_price_receiver, monitor_handle) =
        start_server_background_tasks(server.clone(), metrics.clone(), registry.clone()).await;

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
