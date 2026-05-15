// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared gRPC client wrapper used by both the key-server and aggregator binaries.
//! All public methods retry via [`sui_rpc_with_retries`] and observe per-call
//! metrics through the optional `sui_rpc_request_duration_millis` histogram.

use prometheus::HistogramVec;
use prost_types::FieldMask;
use seal_committee::grpc_helper::{
    extract_object, fetch_committee_from_key_server as grpc_fetch_committee_from_key_server,
    fetch_key_server_by_id as grpc_fetch_key_server_by_id, fetch_object as grpc_fetch_object,
    fetch_upgrade_proposal as grpc_fetch_upgrade_proposal,
};
use seal_committee::move_types::{
    KeyServerV2, PartialKeyServer, PartialKeyServerInfo, SealCommittee, ServerType, UpgradeProposal,
};
pub use seal_committee::{RpcError, RpcResult};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use sui_rpc::client::Client as SuiGrpcClient;
use sui_rpc::proto::sui::rpc::v2::{
    Bcs, GetEpochRequest, GetObjectRequest, SimulateTransactionRequest,
    SimulateTransactionResponse, Transaction,
};
use sui_sdk::SuiClient;
use sui_sdk_types::Address;
use sui_types::object::Data;
use sui_types::transaction::TransactionData;

/// Configuration for the retry logic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// The maximum number of retries.
    pub max_retries: u32,

    /// The minimum delay between retries.
    pub min_delay: Duration,

    /// The maximum delay between retries.
    pub max_delay: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            min_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
        }
    }
}

/// Configuration for the Sui RPC client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    /// Timeout for individual RPC requests.
    pub timeout: Duration,

    /// Retry configuration applied to retriable transport-level failures.
    pub retry_config: RetryConfig,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            retry_config: RetryConfig::default(),
        }
    }
}

/// Trait for determining if an error is retriable
pub trait RetriableError {
    /// Returns true if the error is transient and the operation should be retried
    fn is_retriable_error(&self) -> bool;
}

impl RetriableError for sui_sdk::error::Error {
    fn is_retriable_error(&self) -> bool {
        match self {
            // Low level networking errors are retriable.
            // TODO: Add more retriable errors here
            sui_sdk::error::Error::RpcError(rpc_error) => {
                matches!(
                    rpc_error,
                    jsonrpsee::core::ClientError::Transport(_)
                        | jsonrpsee::core::ClientError::RequestTimeout
                )
            }
            _ => false,
        }
    }
}

impl RetriableError for RpcError {
    fn is_retriable_error(&self) -> bool {
        // Retry only transient gRPC statuses; `code: None` (local decode failures) is deterministic.
        self.code.is_some_and(|code| {
            matches!(
                code,
                tonic::Code::Unavailable
                    | tonic::Code::DeadlineExceeded
                    | tonic::Code::ResourceExhausted
                    | tonic::Code::Aborted
            )
        })
    }
}

/// Status label constants for `observe_attempt` callbacks.
pub const RPC_STATUS_SUCCESS: &str = "success";
pub const RPC_STATUS_RETRIABLE_ERROR: &str = "retriable_error";
pub const RPC_STATUS_ERROR: &str = "error";

/// Executes an async function with automatic retries for retriable errors.
/// `observe_attempt(status, duration_ms)` is called after each attempt where
/// `status` is one of `RPC_STATUS_SUCCESS | RPC_STATUS_RETRIABLE_ERROR | RPC_STATUS_ERROR`.
pub async fn sui_rpc_with_retries<T, E, F, Fut>(
    rpc_config: &RetryConfig,
    label: &str,
    mut func: F,
    mut observe_attempt: impl FnMut(&'static str, f64),
) -> Result<T, E>
where
    E: RetriableError + std::fmt::Debug,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut attempts_remaining = rpc_config.max_retries;
    let mut current_delay = rpc_config.min_delay;

    loop {
        let start_time = std::time::Instant::now();
        let result = func().await;

        // Return immediately on success
        if result.is_ok() {
            observe_attempt(RPC_STATUS_SUCCESS, start_time.elapsed().as_millis() as f64);
            return result;
        }

        // Check if error is retriable and we have attempts left
        if let Err(ref error) = result
            && error.is_retriable_error()
            && attempts_remaining > 1
        {
            tracing::debug!(
                "Retrying RPC call to {} due to retriable error: {:?}. Remaining attempts: {}",
                label,
                error,
                attempts_remaining
            );

            observe_attempt(
                RPC_STATUS_RETRIABLE_ERROR,
                start_time.elapsed().as_millis() as f64,
            );

            // Wait before retrying with exponential backoff
            tokio::time::sleep(current_delay).await;

            // Implement exponential backoff.
            // Double the delay for next retry, but cap at max_delay
            current_delay = std::cmp::min(current_delay * 2, rpc_config.max_delay);
            attempts_remaining -= 1;
            continue;
        }

        tracing::debug!(
            "RPC call to {} failed with error: {:?}. No more attempts remaining.",
            label,
            result.as_ref().err().expect("should be error")
        );

        observe_attempt(RPC_STATUS_ERROR, start_time.elapsed().as_millis() as f64);

        // Either non-retriable error or no attempts remaining
        return result;
    }
}

/// Client for interacting with the Sui RPC API.
#[derive(Clone)]
pub struct SuiRpcClient {
    sui_client: SuiClient,
    sui_grpc_client: SuiGrpcClient,
    rpc_retry_config: RetryConfig,
    request_duration_millis: Option<HistogramVec>,
}

impl SuiRpcClient {
    pub fn new(
        sui_client: SuiClient,
        sui_grpc_client: SuiGrpcClient,
        rpc_retry_config: RetryConfig,
        request_duration_millis: Option<HistogramVec>,
    ) -> Self {
        Self {
            sui_client,
            sui_grpc_client,
            rpc_retry_config,
            request_duration_millis,
        }
    }

    /// Returns a clone of the underlying Sui client.
    pub fn sui_client(&self) -> SuiClient {
        self.sui_client.clone()
    }

    /// Returns a reference to the underlying gRPC client.
    pub fn sui_grpc_client(&self) -> SuiGrpcClient {
        self.sui_grpc_client.clone()
    }

    /// Returns a clone of the request-duration histogram (if any).
    pub fn request_duration_millis(&self) -> Option<HistogramVec> {
        self.request_duration_millis.clone()
    }

    /// Call grpc through retry and metrics.
    async fn run_grpc_with_retries<T, E, F, Fut>(
        &self,
        method: &'static str,
        mut op: F,
    ) -> Result<T, E>
    where
        E: RetriableError + std::fmt::Debug,
        F: FnMut(SuiGrpcClient) -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
    {
        let hist = self.request_duration_millis.clone();
        sui_rpc_with_retries(
            &self.rpc_retry_config,
            method,
            || op(self.sui_grpc_client.clone()),
            move |status, duration_ms| {
                if let Some(h) = hist.as_ref() {
                    h.with_label_values(&[method, status]).observe(duration_ms);
                }
            },
        )
        .await
    }

    /// Simulates a transaction block via gRPC.
    pub async fn simulate_transaction(
        &self,
        tx_data: TransactionData,
    ) -> RpcResult<SimulateTransactionResponse> {
        self.run_grpc_with_retries("simulate_transaction", |mut grpc_client| {
            let tx_data = tx_data.clone();
            async move {
                let tx_bcs = Bcs::from(
                    bcs::to_bytes(&tx_data)
                        .map_err(|e| RpcError::new(&format!("BCS encode failed: {e}")))?,
                );
                let mut transaction = Transaction::default();
                transaction.bcs = Some(tx_bcs);

                let request =
                    SimulateTransactionRequest::new(transaction).with_read_mask(FieldMask {
                        paths: vec![
                            "transaction.effects.status".to_string(),
                            "transaction.effects.gas_used".to_string(),
                        ],
                    });

                grpc_client
                    .execution_client()
                    .simulate_transaction(request)
                    .await
                    .map(|r| r.into_inner())
                    .map_err(RpcError::from_grpc)
            }
        })
        .await
    }

    /// Fetches a Move object via gRPC and deserializes its contents as type T.
    pub async fn get_object<T: serde::de::DeserializeOwned>(
        &self,
        object_id: Address,
    ) -> RpcResult<T> {
        self.run_grpc_with_retries("get_object", move |mut grpc| async move {
            grpc_fetch_object::<T>(&mut grpc, &object_id).await
        })
        .await
    }

    /// Returns true if an object exists.
    pub async fn object_exists(&self, object_id: Address) -> RpcResult<bool> {
        self.run_grpc_with_retries("object_exists", move |mut grpc_client| async move {
            let request = GetObjectRequest::default().with_object_id(object_id.to_string());

            match grpc_client.ledger_client().get_object(request).await {
                Ok(_) => Ok(true),
                Err(status) if status.code() == tonic::Code::NotFound => Ok(false),
                Err(status) => Err(RpcError::from_grpc(status)),
            }
        })
        .await
    }

    /// Fetch the on-chain `KeyServerV2` for `ks_obj_id`.
    pub async fn fetch_key_server_by_id(&self, ks_obj_id: &Address) -> RpcResult<KeyServerV2> {
        let ks_obj_id = *ks_obj_id;
        self.run_grpc_with_retries("fetch_key_server_by_id", move |mut grpc| async move {
            grpc_fetch_key_server_by_id(&mut grpc, &ks_obj_id).await
        })
        .await
    }

    /// Fetch the on-chain `KeyServerV2` and extract the committee `(threshold, members)`
    /// in one call.
    pub async fn fetch_committee_info(
        &self,
        ks_obj_id: &Address,
    ) -> RpcResult<(u16, Vec<PartialKeyServer>)> {
        let key_server_v2 = self.fetch_key_server_by_id(ks_obj_id).await?;
        key_server_v2
            .extract_committee_info()
            .map_err(|e| RpcError::new(&e.to_string()))
    }

    /// Fetch the committee server version for the on-chain `KeyServerV2` at `ks_obj_id`.
    pub async fn fetch_committee_server_version(&self, ks_obj_id: &Address) -> RpcResult<u32> {
        match self.fetch_key_server_by_id(ks_obj_id).await?.server_type {
            ServerType::Committee { version, .. } => Ok(version),
            _ => Err(RpcError::new("KeyServer is not of type Committee")),
        }
    }

    /// Fetch the partial key server info for `member_address` from the committee
    /// rooted at `key_server_obj_id`.
    pub async fn fetch_partial_key_server_for_member(
        &self,
        key_server_obj_id: &Address,
        member_address: &Address,
    ) -> RpcResult<PartialKeyServerInfo> {
        let (committee_id, _) = self
            .fetch_committee_from_key_server(key_server_obj_id)
            .await?;
        let ks = self.fetch_key_server_by_id(key_server_obj_id).await?;
        let committee: SealCommittee = self.get_object(committee_id).await?;
        let partials = ks
            .to_partial_key_servers(&committee.members)
            .map_err(|e| RpcError::new(&e.to_string()))?;
        partials.get(member_address).cloned().ok_or_else(|| {
            RpcError::new(&format!(
                "PartialKeyServerInfo not found for member {member_address}"
            ))
        })
    }

    /// Fetch (committee_id, package_id) for the on-chain `KeyServer` at `ks_obj_id`.
    pub async fn fetch_committee_from_key_server(
        &self,
        ks_obj_id: &Address,
    ) -> RpcResult<(Address, Address)> {
        let ks_obj_id = *ks_obj_id;
        self.run_grpc_with_retries(
            "fetch_committee_from_key_server",
            move |mut grpc| async move {
                let (committee_id, pkg_id) =
                    grpc_fetch_committee_from_key_server(&mut grpc, &ks_obj_id).await?;
                Ok((committee_id, Address::new(pkg_id.into_bytes())))
            },
        )
        .await
    }

    /// Fetch the active upgrade proposal from the committee's UpgradeManager DOF.
    pub async fn fetch_upgrade_proposal(
        &self,
        committee_id: &Address,
    ) -> RpcResult<Option<UpgradeProposal>> {
        let committee_id = *committee_id;
        self.run_grpc_with_retries("fetch_upgrade_proposal", move |mut grpc| async move {
            grpc_fetch_upgrade_proposal(&mut grpc, &committee_id).await
        })
        .await
    }

    /// Fetches a package object and returns its original package id.
    pub async fn fetch_package_original_id(&self, package_id: Address) -> RpcResult<Address> {
        self.run_grpc_with_retries(
            "fetch_package_original_id",
            move |mut grpc_client| async move {
                let mut request = GetObjectRequest::default();
                request.object_id = Some(package_id.to_string());
                request.read_mask = Some(FieldMask {
                    paths: vec!["bcs".to_string()],
                });

                let response = grpc_client
                    .ledger_client()
                    .get_object(request)
                    .await
                    .map(|r| r.into_inner())
                    .map_err(RpcError::from_grpc)?;

                let obj = extract_object(response).map_err(|_| RpcError::new("Invalid package"))?;
                match &obj.data {
                    Data::Package(p) => Ok(Address::new(p.original_package_id().into_bytes())),
                    _ => Err(RpcError::new("Invalid package")),
                }
            },
        )
        .await
    }

    /// Returns the current reference gas price via gRPC.
    pub async fn get_reference_gas_price(&self) -> RpcResult<u64> {
        self.run_grpc_with_retries("get_reference_gas_price", |mut grpc_client| async move {
            let mut client = grpc_client.ledger_client();
            let mut request = GetEpochRequest::default();
            request.read_mask = Some(FieldMask {
                paths: vec!["reference_gas_price".to_string()],
            });
            client
                .get_epoch(request)
                .await
                .map(|r| r.into_inner().epoch().reference_gas_price())
                .map_err(RpcError::from_grpc)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::{sui_rpc_with_retries, RetriableError, RetryConfig};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// Mock error type for testing retry behavior
    #[derive(Debug, Clone)]
    struct MockError {
        is_retriable: bool,
    }

    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "MockError(retriable: {})", self.is_retriable)
        }
    }

    impl std::error::Error for MockError {}

    impl RetriableError for MockError {
        fn is_retriable_error(&self) -> bool {
            self.is_retriable
        }
    }

    /// Mock function that tracks call count and returns errors as configured
    async fn mock_function_with_counter(
        counter: Arc<AtomicU32>,
        fail_count: u32,
        error_type: MockError,
    ) -> Result<String, MockError> {
        let call_count = counter.fetch_add(1, Ordering::SeqCst) + 1;

        if call_count <= fail_count {
            Err(error_type)
        } else {
            Ok(format!("Success on attempt {call_count}"))
        }
    }

    fn noop_observer(_status: &'static str, _duration_ms: f64) {}

    #[tokio::test]
    async fn test_sui_rpc_with_retries_success_first_attempt() {
        let retry_config = RetryConfig {
            max_retries: 3,
            min_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(100),
        };

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = sui_rpc_with_retries(
            &retry_config,
            "mock_function",
            || async {
                mock_function_with_counter(
                    counter_clone.clone(),
                    0, // Don't fail any attempts
                    MockError { is_retriable: true },
                )
                .await
            },
            noop_observer,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Success on attempt 1");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_sui_rpc_with_retries_success_after_retriable_failures() {
        let retry_config = RetryConfig {
            max_retries: 3,
            min_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(100),
        };

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = sui_rpc_with_retries(
            &retry_config,
            "mock_function",
            || async {
                mock_function_with_counter(
                    counter_clone.clone(),
                    2, // Fail first 2 attempts, succeed on 3rd
                    MockError { is_retriable: true },
                )
                .await
            },
            noop_observer,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Success on attempt 3");
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_sui_rpc_with_retries_exhausts_all_retries() {
        let retry_config = RetryConfig {
            max_retries: 3,
            min_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(100),
        };

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = sui_rpc_with_retries(
            &retry_config,
            "mock_function",
            || async {
                mock_function_with_counter(
                    counter_clone.clone(),
                    10, // Fail more attempts than max_retries
                    MockError { is_retriable: true },
                )
                .await
            },
            noop_observer,
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().is_retriable);
        assert_eq!(counter.load(Ordering::SeqCst), 3); // max_retries attempts
    }

    #[tokio::test]
    async fn test_sui_rpc_with_retries_non_retriable_error() {
        let retry_config = RetryConfig {
            max_retries: 3,
            min_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(100),
        };

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = sui_rpc_with_retries(
            &retry_config,
            "mock_function",
            || async {
                mock_function_with_counter(
                    counter_clone.clone(),
                    10, // Fail more attempts than max_retries
                    MockError {
                        is_retriable: false,
                    }, // Non-retriable error
                )
                .await
            },
            noop_observer,
        )
        .await;

        assert!(result.is_err());
        assert!(!result.unwrap_err().is_retriable);
        assert_eq!(counter.load(Ordering::SeqCst), 1); // Should only attempt once
    }

    #[tokio::test]
    async fn test_sui_rpc_with_retries_zero_retries() {
        let retry_config = RetryConfig {
            max_retries: 1, // Only one attempt
            min_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(100),
        };

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = sui_rpc_with_retries(
            &retry_config,
            "mock_function",
            || async {
                mock_function_with_counter(
                    counter_clone.clone(),
                    10, // Always fail
                    MockError { is_retriable: true },
                )
                .await
            },
            noop_observer,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 1); // Should only attempt once
    }

    #[tokio::test]
    async fn test_exponential_backoff_delays() {
        let retry_config = RetryConfig {
            max_retries: 6,
            min_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(1000),
        };

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let start_time = std::time::Instant::now();

        let result = sui_rpc_with_retries(
            &retry_config,
            "mock_function",
            || async {
                mock_function_with_counter(
                    counter_clone.clone(),
                    5, // Fail first 5 attempts, succeed on 6th
                    MockError { is_retriable: true },
                )
                .await
            },
            noop_observer,
        )
        .await;

        let elapsed = start_time.elapsed();

        assert!(result.is_ok());
        assert_eq!(counter.load(Ordering::SeqCst), 6);

        // Expected delays: 100ms, 200ms, 400ms, 800ms, 1000ms (exponential backoff with max cap)
        // Total expected minimum delay: 2500ms
        let expected_min_duration = Duration::from_millis(2500);
        assert!(
            elapsed >= expected_min_duration,
            "Expected at least {expected_min_duration:?} but got {elapsed:?}"
        );
    }
}
