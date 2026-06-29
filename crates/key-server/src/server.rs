// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::common::add_response_headers;
use crate::errors::InternalError::{InvalidSDKVersion, MissingRequiredHeader};
use crate::externals::get_reference_gas_price;
use crate::key_server_options::ServerMode;
use crate::metrics::{call_with_duration, status_callback, uptime_metric, KeyServerMetrics};
use crate::metrics_push::create_push_client;
use crate::mvr::mvr_forward_resolution;
use crate::periodic_updater::spawn_periodic_updater;
use crate::signed_message::signed_request;
use crate::time::{checked_duration_since, from_mins};
use crate::types::{IbeMasterKey, IbePublicKey, MasterKeyPOP, Network};
use crate::InternalError::DeprecatedSDKVersion;
use anyhow::{Context, Result};
use axum::extract::{Query, Request};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{from_fn_with_state, map_response, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{extract::State, Json, Router};
use common::{
    normalize_sdk_version_label, ClientSdkType, HEADER_CLIENT_SDK_TYPE, HEADER_CLIENT_SDK_VERSION,
};
use core::time::Duration;
use crypto::elgamal::encrypt;
use crypto::ibe::create_proof_of_possession;
use crypto::ibe::{self};
use crypto::prefixed_hex::PrefixedHex;
use errors::InternalError;
use fastcrypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::traits::VerifyingKey;
use futures::future::pending;
use key_server::sui_rpc_client::{build_grpc_client, SuiRpcClient};
use key_server_options::KeyServerOptions;
use master_keys::{CommitteeKeyState, MasterKeys};
use metrics::metrics_middleware;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::{StructTag, TypeTag};
use mysten_service::get_mysten_service;
use mysten_service::metrics::start_prometheus_server;
use mysten_service::package_name;
use mysten_service::package_version;
use rand::thread_rng;
use seal_committee::move_types::CommitteeRotationInitiatedEvent;
use seal_sdk::types::{DecryptionKey, ElGamalPublicKey, ElgamalVerificationKey, KeyId};
use seal_sdk::{signed_message, FetchKeyResponse};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use sui_rpc::proto::sui::rpc::v2::execution_error::ExecutionErrorKind;
use sui_sdk::rpc_types::EventFilter;
use sui_sdk::types::base_types::{ObjectID, SuiAddress};
use sui_sdk::types::signature::GenericSignature;
use sui_sdk::types::transaction::{ProgrammableTransaction, TransactionData, TransactionKind};
use sui_sdk::verify_personal_message_signature::verify_personal_message_signature;
use sui_sdk::SuiClientBuilder;
use sui_sdk_types::Address;
use sui_types::event::EventID;
use sui_types::{derived_object, SUI_ADDRESS_ALIAS_STATE_OBJECT_ID, SUI_FRAMEWORK_ADDRESS};
use tap::tap::TapFallible;
use tap::Tap;
use tokio::sync::watch::Receiver;
use tokio::task::JoinHandle;
use tonic::Code;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{debug, error, info, warn};
use valid_ptb::ValidPtb;
mod cache;
mod common;
mod errors;
mod externals;
mod signed_message;
mod types;
mod utils;
mod valid_ptb;

use common::NetworkConfig;

mod key_server_options;
mod master_keys;
mod metrics;
mod metrics_push;
mod mvr;
mod periodic_updater;
mod seal_package;
#[cfg(test)]
pub mod tests;
mod time;

const MAX_COMPUTATION_UNITS: u64 = 55_000; // 50K tier + 10% extra buffer
const GIT_VERSION: &str = crate::git_version!();
const DEFAULT_PORT: u16 = 2024;

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
    master_keys: Arc<MasterKeys>,
    key_server_oid_to_pop: Arc<RwLock<HashMap<ObjectID, MasterKeyPOP>>>,
    options: KeyServerOptions,
}

async fn has_address_aliases(
    sui_rpc_client: &SuiRpcClient,
    address: SuiAddress,
) -> Result<bool, InternalError> {
    let alias_key_type = TypeTag::Struct(Box::new(StructTag {
        address: SUI_FRAMEWORK_ADDRESS,
        module: Identifier::new("address_alias").unwrap(),
        name: Identifier::new("AliasKey").unwrap(),
        type_params: vec![],
    }));

    let key_bytes = bcs::to_bytes(&address).unwrap();
    let address_aliases_id = derived_object::derive_object_id(
        SuiAddress::from(SUI_ADDRESS_ALIAS_STATE_OBJECT_ID),
        &alias_key_type,
        &key_bytes,
    )
    .map_err(|_| InternalError::InvalidSignature)?;

    sui_rpc_client
        .object_exists(Address::new(address_aliases_id.into_bytes()))
        .await
        .map_err(|e| InternalError::Failure(format!("Failed to check address aliases: {}", e)))
}

async fn fetch_and_validate_committee_partial_pk(
    sui_rpc_client: &SuiRpcClient,
    key_server_obj_id: &Address,
    member_address: &Address,
    master_share: &IbeMasterKey,
) -> Result<()> {
    let member_info = sui_rpc_client
        .fetch_partial_key_server_for_member(key_server_obj_id, member_address)
        .await?;

    let local_partial_pk = ibe::public_key_from_master_key(master_share);
    if local_partial_pk != member_info.partial_pk {
        anyhow::bail!(
            "Configured committee master share public key does not match onchain partial public key"
        );
    }
    Ok(())
}

impl Server {
    /// Check if the server is in committee mode.
    fn is_committee_mode(&self) -> bool {
        matches!(self.options.server_mode, ServerMode::Committee { .. })
    }

    /// Helper to extract committee server parameters for metrics and other uses.
    /// Returns (key_server_object_id, server_name).
    /// Returns None if not in committee mode.
    fn get_committee_server_params(&self) -> Option<(Address, String)> {
        match &self.options.server_mode {
            ServerMode::Committee {
                key_server_obj_id,
                server_name,
                ..
            } => Some((*key_server_obj_id, server_name.clone())),
            _ => None,
        }
    }

    async fn new(mut options: KeyServerOptions, metrics: Option<Arc<KeyServerMetrics>>) -> Self {
        // The legacy JSON-RPC client is only used by the event monitors, only
        // initialize it when event monitoring is enabled.
        let sui_client = if options.enable_event_monitoring {
            info!("Event monitoring enabled; initializing legacy Sui JSON-RPC client");
            Some(
                SuiClientBuilder::default()
                    .request_timeout(options.rpc_config.timeout)
                    .build(&options.node_url())
                    .await
                    .expect(
                        "Failed to initialize legacy Sui JSON-RPC client required for event monitoring",
                    ),
            )
        } else {
            info!("Event monitoring disabled; skipping legacy Sui JSON-RPC client initialization");
            None
        };

        let sui_rpc_client = SuiRpcClient::new_with_optional_sui_client(
            sui_client,
            build_grpc_client(options.node_url()).expect("Failed to create SuiGrpcClient"),
            options.rpc_config.retry_config.clone(),
            metrics
                .as_ref()
                .map(|m| m.sui_rpc_request_duration_millis.clone()),
        );
        info!("Server started with network: {:?}", options.network);

        let committee_version = match &options.server_mode {
            ServerMode::Committee {
                key_server_obj_id, ..
            } => Some(
                sui_rpc_client
                    .fetch_committee_server_version(key_server_obj_id)
                    .await
                    .expect("Failed to fetch committee server version"),
            ),
            _ => None,
        };

        let master_keys = MasterKeys::load(&options, committee_version).unwrap_or_else(|e| {
            panic!("Failed to load master keys: {e}");
        });

        if let (
            ServerMode::Committee {
                key_server_obj_id,
                member_address,
                ..
            },
            MasterKeys::Committee {
                key_state: CommitteeKeyState::Active { master_share },
                ..
            },
        ) = (&mut options.server_mode, &master_keys)
        {
            fetch_and_validate_committee_partial_pk(
                &sui_rpc_client,
                key_server_obj_id,
                member_address,
                master_share,
            )
            .await
            .unwrap_or_else(|e| {
                panic!("Failed to validate active committee partial public key: {e}");
            });
        }

        let key_server_oid_to_pop = Self::build_key_server_pop_map(&options, &master_keys).await;

        Server {
            sui_rpc_client,
            master_keys: Arc::new(master_keys),
            key_server_oid_to_pop: Arc::new(RwLock::new(key_server_oid_to_pop)),
            options,
        }
    }

    /// Build the key_server_oid -> PoP HashMap for all server modes.
    /// Returns empty map for Committee mode as it doesn't support /service endpoint.
    pub(crate) async fn build_key_server_pop_map(
        options: &KeyServerOptions,
        master_keys: &MasterKeys,
    ) -> HashMap<ObjectID, MasterKeyPOP> {
        match &options.server_mode {
            ServerMode::Open { .. } | ServerMode::Permissioned { .. } => options
                .get_supported_key_server_object_ids()
                .into_iter()
                .map(|ks_oid| {
                    let key = master_keys
                        .get_key_for_key_server(&ks_oid)
                        .expect("checked already");
                    let pop = create_proof_of_possession(key, &ks_oid.into_bytes());
                    (ks_oid, pop)
                })
                .collect(),

            ServerMode::Committee { .. } => {
                // Committee mode doesn't support /service endpoint, return empty map
                HashMap::new()
            }
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

        // Check if the address has aliases enabled - if so, reject verification
        match has_address_aliases(&self.sui_rpc_client, cert.user).await {
            Ok(true) => {
                debug!(
                    "Address has aliases enabled, rejecting signature verification (req_id: {:?})",
                    req_id
                );
                return Err(InternalError::InvalidSignature);
            }
            Ok(false) => {} // no alias
            Err(e) => {
                return Err(e);
            }
        }

        verify_personal_message_signature(
            cert.signature.clone(),
            msg.as_bytes(),
            cert.user,
            Some(self.sui_rpc_client.sui_grpc_client()),
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
        metrics: Option<&KeyServerMetrics>,
    ) -> Result<(), InternalError> {
        debug!(
            "Checking policy for ptb: {:?} (req_id: {:?})",
            vptb.ptb(),
            req_id
        );

        // Add a staleness check as the first command in the PTB
        let ptb = self
            .options
            .network
            .seal_package()
            .add_staleness_check_to_ptb(self.options.allowed_staleness, vptb.ptb().clone())?;

        // Evaluate the `seal_approve*` function
        let gas_budget = MAX_COMPUTATION_UNITS * gas_price;
        let tx_data = TransactionData::new_with_gas_coins(
            TransactionKind::ProgrammableTransaction(ptb),
            sender,
            vec![], // Empty gas payment for dry run
            gas_budget,
            gas_price,
        );
        let simulate_res = self
            .sui_rpc_client
            .simulate_transaction(tx_data)
            .await
            .map_err(|e| {
                // `InvalidArgument` = malformed request; `NotFound` = an input
                // object does not yet exist on the fullnode (e.g. a freshly
                // created object the FN has not indexed).
                if matches!(e.code, Some(Code::InvalidArgument) | Some(Code::NotFound)) {
                    debug!("Invalid parameter: {}", e.message);
                    return InternalError::InvalidParameter(e.message);
                }
                InternalError::Failure(format!(
                    "Simulate transaction failed ({e}) (req_id: {req_id:?})"
                ))
            })?;

        debug!(
            "Simulate response: {:?} (req_id: {:?})",
            simulate_res, req_id
        );

        // Record the gas cost. Only do this in permissioned mode to avoid high cardinality metrics in public mode.
        if let Some(m) = metrics
            && matches!(self.options.server_mode, ServerMode::Permissioned { .. })
        {
            let package = vptb.pkg_id().to_hex_uncompressed();
            m.dry_run_gas_cost_per_package
                .with_label_values(&[&package])
                .observe(
                    simulate_res
                        .transaction()
                        .effects()
                        .gas_used()
                        .computation_cost() as f64,
                );
        }

        // Check if the staleness check failed
        if self
            .options
            .network
            .seal_package()
            .is_staleness_error(&simulate_res)
        {
            debug!("Fullnode is stale (req_id: {:?})", req_id);
            if let Some(m) = metrics {
                m.requests_failed_due_to_staleness.inc()
            }
            return Err(InternalError::Failure("Fullnode is stale".to_string()));
        }

        // Handle errors in the simulation
        let status = simulate_res.transaction().effects().status();
        if let Some(error) = &status.error {
            if error.kind() == ExecutionErrorKind::FunctionNotFound {
                debug!("Function not found (req_id: {:?})", req_id);
                return Err(InternalError::InvalidPTB(
                    "The seal_approve function was not found on the module".to_string(),
                ));
            }

            // Use `description` and fall back to `kind`
            let msg = error
                .description
                .clone()
                .unwrap_or_else(|| format!("{:?}", error.kind()));
            debug!(
                "Simulate transaction execution asserted (req_id: {:?}) error: {:?}",
                req_id, error
            );
            return Err(InternalError::NoAccess(msg));
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
        metrics: Option<&KeyServerMetrics>,
        req_id: Option<&str>,
        mvr_name: Option<String>,
    ) -> Result<(ObjectID, Vec<KeyId>), InternalError> {
        // Handle package upgrades: Use the first as the namespace
        let first_pkg_id =
            call_with_duration(metrics.map(|m| &m.fetch_pkg_ids_duration), || async {
                common::fetch_first_pkg_id(&self.sui_rpc_client, &valid_ptb.pkg_id()).await
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
        ids: Vec<KeyId>,
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
            .into_iter()
            .map(|id| {
                // Requested key
                let key = ibe::extract(master_key, &id);
                // ElGamal encryption of key under the user's public key
                let encrypted_key = encrypt(&mut thread_rng(), &key, enc_key);
                DecryptionKey { id, encrypted_key }
            })
            .collect();
        FetchKeyResponse { decryption_keys }
    }

    /// Spawns a thread that fetches RGP and sends it to a [Receiver] once per `update_interval`.
    /// Returns the [Receiver].
    async fn spawn_reference_gas_price_updater(
        &self,
        metrics: Option<&KeyServerMetrics>,
    ) -> (Receiver<u64>, JoinHandle<()>) {
        spawn_periodic_updater(
            &self.sui_rpc_client,
            self.options.rgp_update_interval,
            get_reference_gas_price,
            "RGP",
            metrics.map(|m| status_callback(&m.get_reference_gas_price_status)),
        )
        .await
    }

    /// Spawn a metrics push background jobs that push metrics to seal-proxy
    fn spawn_metrics_push_job(&self, registry: prometheus::Registry) -> JoinHandle<()> {
        let push_config = self.options.metrics_push_config.clone();
        if let Some(push_config) = push_config {
            let params = self.get_committee_server_params();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(push_config.push_interval);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                let mut client = create_push_client();
                tracing::info!("starting metrics push to '{}'", &push_config.push_url);
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            let mut dynamic_config = push_config.clone();
                            let mut labels = dynamic_config.labels.unwrap_or_default();
                            if let Some((key_server_obj_id, server_name)) = &params {
                                labels.insert("key_server_object_id".to_string(), key_server_obj_id.to_string());
                                labels.insert("server_name".to_string(), server_name.clone());
                            }
                            dynamic_config.labels = Some(labels);

                            if let Err(error) = metrics_push::push_metrics(
                                dynamic_config,
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

    /// Spawns a background task that fetches committee key server version from onchain and updates
    /// the committee version in MasterKeys::Committee. Only spawns a task if the loaded committee
    /// key state is waiting for a target rotation version, and the task is stopped once the version
    /// is updated.
    async fn spawn_committee_version_updater(&self) -> Option<JoinHandle<()>> {
        let ServerMode::Committee {
            member_address,
            key_server_obj_id,
            ..
        } = &self.options.server_mode
        else {
            return None;
        };
        let member_address = *member_address;

        let (current_version, target_version, committee_version_arc, target_master_share) =
            match self.master_keys.as_ref() {
                MasterKeys::Committee {
                    key_state:
                        CommitteeKeyState::Rotation {
                            next_master_share,
                            target_version,
                            ..
                        },
                    committee_version,
                } => (
                    committee_version.load(Ordering::SeqCst),
                    *target_version,
                    Arc::clone(committee_version),
                    *next_master_share,
                ),
                _ => return None,
            };

        if current_version == target_version {
            info!("Rotation already completed. You can restart in Active mode with only MASTER_SHARE_V{} set.", current_version);
            return None;
        }

        info!(
            "Rotation mode: current version {current_version}, target version {target_version}. Starting version monitor."
        );

        {
            // Define the fetch function for the periodic updater.
            let key_server_obj_id_clone = *key_server_obj_id;
            let fetch_fn = move |client: SuiRpcClient| async move {
                client
                    .fetch_committee_server_version(&key_server_obj_id_clone)
                    .await
                    .map(|v| v as u64)
            };

            // Define the periodic updater.
            let (receiver, updater_handle) = spawn_periodic_updater(
                &self.sui_rpc_client,
                Duration::from_secs(30),
                fetch_fn,
                "committee key server version",
                None::<fn(bool)>,
            )
            .await;

            let mut receiver_clone = receiver;
            let key_server_obj_id_for_validation = *key_server_obj_id;
            let sui_rpc_client_for_validation = self.sui_rpc_client.clone();

            // Spawn the background task to monitor version changes.
            Some(tokio::spawn(async move {
                loop {
                    match receiver_clone.changed().await {
                        Ok(_) => {
                            // Safe cast: onchain Committee.version is u32, so value always fits.
                            let version = *receiver_clone.borrow() as u32;

                            // Rotation completes.
                            if version == target_version {
                                info!(
                                    "Rotation complete at version {version}. Validating rotated partial public key."
                                );

                                fetch_and_validate_committee_partial_pk(
                                    &sui_rpc_client_for_validation,
                                    &key_server_obj_id_for_validation,
                                    &member_address,
                                    &target_master_share,
                                )
                                .await
                                .unwrap_or_else(|e| {
                                    panic!(
                                        "Failed to validate rotated committee partial public key: {e}"
                                    )
                                });

                                // Update the committee version
                                committee_version_arc.store(target_version, Ordering::SeqCst);
                                info!("Committee version refreshed to {target_version}.");

                                updater_handle.abort();
                                break;
                            } else if version.checked_add(1) == Some(target_version) {
                                continue; // Still in rotation, keep monitoring.
                            } else {
                                // Unexpected version state - onchain version skipped or went backwards.
                                panic!(
                                    "CRITICAL: Unexpected onchain version {version} (expected {target_version} or {})",
                                    target_version.saturating_sub(1)
                                );
                            }
                        }
                        Err(e) => {
                            panic!("Version monitor channel closed unexpectedly: {e}");
                        }
                    }
                }
            }))
        }
    }

    /// Spawns a background task that monitors for CommitteeRotationInitiated events.
    /// Only spawns in Committee mode. Alerts when a new committee rotation is initiated.
    /// Refreshes committee_id and package_id from key server object.
    async fn spawn_committee_rotation_event_monitor(&self, metrics: Arc<KeyServerMetrics>) {
        // Only run in committee mode
        let ServerMode::Committee {
            key_server_obj_id, ..
        } = &self.options.server_mode
        else {
            return;
        };
        let key_server_obj_id = *key_server_obj_id;

        info!(
            "Starting committee rotation event monitor for key_server_obj_id: {}",
            key_server_obj_id
        );

        let sui_client = self.sui_rpc_client.sui_client();
        let sui_rpc_client = self.sui_rpc_client.clone();

        // Spawn the background task to poll for events.
        tokio::spawn(async move {
            info!("Committee rotation event monitor task started");
            let mut last_event_seq: Option<EventID> = None;
            let mut initialized = false;

            loop {
                // Fetch current committee ID and package ID from key server object
                let (committee_id, committee_pkg_id) = match sui_rpc_client
                    .fetch_committee_from_key_server(&key_server_obj_id)
                    .await
                {
                    Ok((id, pkg_id)) => {
                        debug!("Current committee_id: {}, package_id: {}", id, pkg_id);
                        (id, pkg_id)
                    }
                    Err(e) => {
                        warn!(
                            "Failed to fetch committee ID and package ID from key server: {}",
                            e
                        );
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        continue;
                    }
                };

                let event_filter = EventFilter::MoveEventType(
                    format!(
                        "{}::seal_committee::CommitteeRotationInitiated",
                        committee_pkg_id
                    )
                    .parse()
                    .expect("Parsing should not fail"),
                );

                if !initialized {
                    match sui_client
                        .event_api()
                        .query_events(event_filter.clone(), None, Some(1), true)
                        .await
                    {
                        Ok(page) => {
                            last_event_seq = page.data.first().map(|event| event.id);
                            initialized = true;
                            debug!(
                                "Committee rotation event monitor initialized at cursor: {:?}",
                                last_event_seq
                            );
                        }
                        Err(e) => {
                            warn!(
                                "Failed to initialize committee rotation event cursor: {}",
                                e
                            );
                        }
                    }

                    tokio::time::sleep(Duration::from_secs(30)).await;
                    continue;
                }

                let events_result = sui_client
                    .event_api()
                    .query_events(
                        event_filter,
                        last_event_seq,
                        Some(1), // Fetch the next unseen event.
                        false,   // ascending order
                    )
                    .await;

                match events_result {
                    Ok(page) => {
                        for event in &page.data {
                            let event_data = bcs::from_bytes::<CommitteeRotationInitiatedEvent>(
                                event.bcs.bytes(),
                            )
                            .expect("BCS should not fail");

                            if event_data.old_committee_id != committee_id {
                                // This means a different committee is initialized with this committee package ID and being rotated, should never happen.
                                error!(
                                    "Committee ID mismatch detected! Event committee_id: {}, old_committee_id: {}, Current committee_id: {}",
                                    event_data.committee_id, event_data.old_committee_id, committee_id
                                );
                            }

                            warn!(
                                "Committee rotation initiation detected! New committee_id: {}, Old committee_id: {}",
                                event_data.committee_id, event_data.old_committee_id
                            );

                            metrics.committee_mode_rotation_initiated_total.inc();

                            last_event_seq = Some(event.id);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to query committee rotation events: {}", e);
                    }
                }

                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
    }

    /// Spawns a background task that monitors for package digest changes from UpgradeManager.
    /// Only spawns in Committee mode. Alerts when a new upgrade proposal is detected.
    async fn spawn_package_digest_monitor(&self, metrics: Arc<KeyServerMetrics>) {
        // Only run in committee mode
        let ServerMode::Committee {
            key_server_obj_id, ..
        } = &self.options.server_mode
        else {
            return;
        };
        let key_server_obj_id = *key_server_obj_id;

        info!(
            "Starting package upgrade proposal monitor for key_server_obj_id: {}",
            key_server_obj_id
        );

        // Define the fetch function for upgrade proposal existence
        let fetch_fn = move |client: SuiRpcClient| async move {
            let (committee_id, _) = client
                .fetch_committee_from_key_server(&key_server_obj_id)
                .await?;

            client
                .fetch_upgrade_proposal(&committee_id)
                .await
                .map(|proposal_opt| {
                    proposal_opt
                        .as_ref()
                        .map(|proposal| proposal.version)
                        .unwrap_or(0)
                })
        };

        // Spawn periodic updater
        let (receiver, _updater_handle) = spawn_periodic_updater(
            &self.sui_rpc_client,
            Duration::from_secs(30),
            fetch_fn,
            "upgrade proposal",
            None::<fn(bool)>,
        )
        .await;

        let mut receiver_clone = receiver;
        let mut last_proposal_id = *receiver_clone.borrow_and_update();

        // Spawn the background task to monitor upgrade proposal changes
        tokio::spawn(async move {
            loop {
                match receiver_clone.changed().await {
                    Ok(_) => {
                        let proposal_id = *receiver_clone.borrow_and_update();

                        // Warn if a new upgrade proposal was created.
                        if proposal_id != 0 && proposal_id != last_proposal_id {
                            warn!("New package upgrade proposal detected!");

                            metrics.committee_mode_package_upgrade_initiated_total.inc();
                        }

                        last_proposal_id = proposal_id;
                    }
                    Err(e) => {
                        warn!("Package digest monitor channel closed: {}", e);
                        break;
                    }
                }
            }
        });
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
                Err(e) => debug!("Check request failed with error {e:?}: {request_info}"),
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
        .get(HEADER_CLIENT_SDK_VERSION)
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
                    .create_response(first_pkg_id, full_ids, &payload.enc_key),
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
        .read()
        .map_err(|e| InternalError::Failure(format!("Failed to read PoP map: {e}")))?
        .get(&service_id)
        .ok_or(InternalError::InvalidServiceId)?;

    Ok(Json(GetServiceResponse { service_id, pop }))
}

#[derive(Serialize, Deserialize)]
struct GetCommitteePartialPkResponse {
    partial_pk: IbePublicKey,
}

/// Return the corresponding partial public key for its master share. Debug endpoint only supported
/// in Committee mode.
async fn handle_get_committee_server_partial_pk(State(app_state): State<MyState>) -> Response {
    app_state.metrics.service_requests.inc();

    if !app_state.server.is_committee_mode() {
        return (StatusCode::BAD_REQUEST, "Unsupported").into_response();
    }

    let partial_pk = match app_state.server.master_keys.get_committee_partial_pk() {
        Ok(pk) => pk,
        Err(e) => return e.into_response(),
    };

    Json(GetCommitteePartialPkResponse { partial_pk }).into_response()
}

#[derive(Clone)]
struct MyState {
    metrics: Arc<KeyServerMetrics>,
    server: Arc<Server>,
    reference_gas_price_receiver: Receiver<u64>,
}

impl MyState {
    fn reference_gas_price(&self) -> u64 {
        *self.reference_gas_price_receiver.borrow()
    }

    /// Validates the version based on SDK type.
    fn validate_sdk_version(
        &self,
        version_string: &str,
        sdk_type: ClientSdkType,
    ) -> Result<(), InternalError> {
        validate_sdk_version_for_type(
            version_string,
            sdk_type,
            &self.server.options.aggregator_version_requirement,
            &self.server.options.ts_sdk_version_requirement,
            &self.server.options.rust_sdk_version_requirement,
            &self.server.options.python_sdk_version_requirement,
        )
    }
}

fn validate_sdk_version_for_type(
    version_string: &str,
    sdk_type: ClientSdkType,
    aggregator_requirement: &VersionReq,
    ts_requirement: &VersionReq,
    rust_requirement: &VersionReq,
    python_requirement: &VersionReq,
) -> Result<(), InternalError> {
    let version = Version::parse(version_string).map_err(|_| InvalidSDKVersion)?;

    let requirement = match sdk_type {
        ClientSdkType::Aggregator => aggregator_requirement,
        ClientSdkType::TypeScript => ts_requirement,
        ClientSdkType::Rust => rust_requirement,
        ClientSdkType::Python => python_requirement,
        ClientSdkType::Other => return Ok(()), // Ignore if sdk type is unknown string or not provided
    };

    if !requirement.matches(&version) {
        return Err(DeprecatedSDKVersion);
    }

    Ok(())
}

/// Middleware to validate the SDK version.
async fn handle_request_headers(
    state: State<MyState>,
    request: Request,
    next: Next,
) -> Result<Response, InternalError> {
    // Log the request id and SDK version
    let version = request.headers().get(HEADER_CLIENT_SDK_VERSION);
    let sdk_type_header = request.headers().get(HEADER_CLIENT_SDK_TYPE);

    info!(
        "Request id: {:?}, SDK version: {:?}, SDK type: {:?}, Target API version: {:?}",
        request
            .headers()
            .get("Request-Id")
            .map(|v| v.to_str().unwrap_or_default()),
        version,
        sdk_type_header,
        request.headers().get("Client-Target-Api-Version")
    );

    let sdk_type = ClientSdkType::from_header(sdk_type_header.and_then(|t| t.to_str().ok()))?;
    let version_str = version
        .ok_or(MissingRequiredHeader(HEADER_CLIENT_SDK_VERSION.to_string()))
        .and_then(|v| v.to_str().map_err(|_| InvalidSDKVersion))
        .and_then(|v| {
            state.validate_sdk_version(v, sdk_type)?;
            Ok(v)
        })
        .tap_err(|e| {
            debug!(
                "Invalid SDK version: {:?}, sdk_version: {:?}, sdk_type: {:?}",
                e, version, sdk_type
            );
            state.metrics.observe_error(e.as_str());
        })?;

    // Track client SDK version by type
    state
        .metrics
        .client_sdk_version
        .with_label_values(&[sdk_type.as_str(), &normalize_sdk_version_label(version_str)])
        .inc();

    Ok(next.run(request).await)
}

/// Spawn server's background tasks:
///  - reference gas price updater.
///  - optional metrics pusher (if configured).
///
/// The returned JoinHandle can be used to catch any tasks error or panic.
async fn start_server_background_tasks(
    server: Arc<Server>,
    metrics: Arc<KeyServerMetrics>,
    registry: prometheus::Registry,
) -> (Receiver<u64>, JoinHandle<anyhow::Result<()>>) {
    // Spawn background reference gas price updater.
    let (reference_gas_price_receiver, reference_gas_price_handle) = server
        .spawn_reference_gas_price_updater(Some(&metrics))
        .await;

    // Spawn committee version updater only if the server is in committee mode and is during
    // rotation (current onchain version is target-1).
    let committee_version_updater_handle = server.spawn_committee_version_updater().await;

    // Spawn committee rotation and package upgrade monitors (committee mode only) if enabled.
    if server.options.enable_event_monitoring {
        // Spawn committee rotation event monitor to detect CommitteeRotationInitiated events
        server
            .spawn_committee_rotation_event_monitor(metrics.clone())
            .await;

        // Spawn package digest monitor to alert on package upgrades
        server.spawn_package_digest_monitor(metrics.clone()).await;
    } else {
        info!("Committee rotation and package upgrade monitoring is disabled via config");
    }

    // Spawn metrics push task
    let metrics_push_handle = server.spawn_metrics_push_job(registry);

    // Spawn a monitor task that will exit the program if any updater task panics
    let handle: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        let committee_version_monitor_handle = tokio::spawn(async move {
            if let Some(handle) = committee_version_updater_handle {
                if let Err(e) = handle.await {
                    if e.is_panic() {
                        std::panic::resume_unwind(e.into_panic());
                    }
                    panic!("Committee version updater stopped unexpectedly: {e}");
                }
                info!("Committee version updater completed.");
            }
            pending::<()>().await;
        });

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
            result = committee_version_monitor_handle => {
                if let Err(e) = result {
                    error!("Committee version updater panicked: {:?}", e);
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

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| DEFAULT_PORT.to_string())
        .parse()
        .context("Invalid PORT")?;

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Key server listening on http://localhost:{}", port);

    tokio::select! {
        server_result = axum::serve(listener, app) => {
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
            match (&opts.node_url, env::var("NODE_URL").ok()) {
                (Some(_), Some(_)) => {
                    panic!("NODE_URL cannot be provided in both config file and environment variable. Please use only one source.");
                }
                (None, Some(url)) => {
                    info!("Using NODE_URL from environment variable: {}", url);
                    opts.node_url = Some(url.clone());
                }
                (Some(_), None) => {
                    info!("Using NODE_URL from config file: {}", opts.node_url());
                }
                (None, None) => {
                    info!("Using default NODE_URL: {}", opts.node_url());
                }
            }
            opts
        }
        Err(_) => {
            info!("Using local environment variables for configuration, should only be used for testing");
            let network = env::var("NETWORK")
                .ok()
                .and_then(|n| n.parse().ok())
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
                "key server",
                format!("{}-{}", package_version!(), GIT_VERSION).as_str(),
            ))
            .expect("metrics defined at compile time must be valid");
    });

    // hook up custom application metrics
    let metrics = Arc::new(KeyServerMetrics::new(&registry));

    info!(
        "Starting server, version {}",
        format!("{}-{}", package_version!(), GIT_VERSION).as_str()
    );
    options.validate()?;
    let server = Arc::new(Server::new(options, Some(metrics.clone())).await);

    // Report the current version as to the dashboard.
    // Counters are reset on startup, so only the counter with version equal to package_version is 1.
    metrics
        .key_server_version
        .with_label_values(&[package_version!()])
        .inc();

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
                .route(
                    "/v1/debug/committee_partial_pk",
                    get(handle_get_committee_server_partial_pk),
                )
                .layer(from_fn_with_state(state.clone(), handle_request_headers))
                .layer(map_response(|response| {
                    add_response_headers(response, package_version!(), GIT_VERSION)
                }))
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

#[cfg(test)]
mod sdk_validation_tests {
    use super::*;

    #[test]
    fn key_server_validates_sdk_versions_by_type() {
        let aggregator_requirement = VersionReq::parse(">=3.0.0").unwrap();
        let ts_requirement = VersionReq::parse(">=1.2.3").unwrap();
        let rust_requirement = VersionReq::parse(">=2.0.0").unwrap();
        let python_requirement = VersionReq::parse("=0.0.0").unwrap();

        let validate = |version, sdk_type| {
            validate_sdk_version_for_type(
                version,
                sdk_type,
                &aggregator_requirement,
                &ts_requirement,
                &rust_requirement,
                &python_requirement,
            )
        };

        assert_eq!(validate("3.0.0", ClientSdkType::Aggregator), Ok(()));
        assert_eq!(
            validate("2.9.9", ClientSdkType::Aggregator),
            Err(DeprecatedSDKVersion)
        );
        assert_eq!(validate("1.2.3", ClientSdkType::TypeScript), Ok(()));
        assert_eq!(
            validate("1.2.2", ClientSdkType::TypeScript),
            Err(DeprecatedSDKVersion)
        );
        assert_eq!(validate("2.0.0", ClientSdkType::Rust), Ok(()));
        assert_eq!(
            validate("1.9.9", ClientSdkType::Rust),
            Err(DeprecatedSDKVersion)
        );
        assert_eq!(validate("0.0.1", ClientSdkType::Other), Ok(()));
        assert_eq!(
            validate("not-semver", ClientSdkType::Other),
            Err(InvalidSDKVersion)
        );
    }
}
