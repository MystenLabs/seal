// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use sui_rpc::client::Client;
use sui_rpc::field::FieldMaskUtil;
use sui_types::base_types::ObjectID;

use crate::{key_server_options::RetryConfig, metrics::Metrics};

/// Maximum page size for paginated requests
const MAX_PAGE_SIZE: u32 = 1000;

/// Conversion factor from seconds to milliseconds
const SECONDS_TO_MILLIS: u64 = 1000;

/// Conversion factor from nanoseconds to milliseconds
const NANOS_TO_MILLIS: u64 = 1_000_000;

/// Maximum BCS data size (10MB) to prevent excessive memory usage
const MAX_BCS_SIZE: usize = 10 * 1024 * 1024;

/// Result type for RPC operations
pub type RpcResult<T> = Result<T, RpcError>;

/// Error type for RPC operations
#[derive(Debug)]
pub struct RpcError {
    message: String,
    code: Option<tonic::Code>,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for RpcError {}

impl RpcError {
    /// Create a new RpcError from a message
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: None,
        }
    }

    /// Create a new RpcError with a specific gRPC status code
    pub fn with_code(message: impl Into<String>, code: tonic::Code) -> Self {
        Self {
            message: message.into(),
            code: Some(code),
        }
    }

    /// Get the error message
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Get the gRPC status code if available
    pub fn code(&self) -> Option<tonic::Code> {
        self.code
    }
}

/// Response type for object queries
pub struct SuiObjectResponse {
    inner: sui_rpc::proto::sui::rpc::v2beta2::GetObjectResponse,
}

impl SuiObjectResponse {
    /// Get object ID from the response
    pub fn object_id(&self) -> Result<ObjectID, RpcError> {
        self.inner
            .object
            .as_ref()
            .and_then(|o| o.object_id.as_ref())
            .and_then(|id| id.parse().ok())
            .ok_or_else(|| RpcError::new("No object ID in response"))
    }

    /// Get the BCS bytes from a Move object
    pub fn move_object_bcs(&self) -> Result<Vec<u8>, RpcError> {
        let bytes = self
            .inner
            .object
            .as_ref()
            .and_then(|o| o.bcs.as_ref())
            .and_then(|bcs| bcs.value.as_ref())
            .ok_or_else(|| RpcError::new("No BCS data in object"))?;

        if bytes.len() > MAX_BCS_SIZE {
            return Err(RpcError::new(format!(
                "BCS data too large: {} bytes (max: {})",
                bytes.len(),
                MAX_BCS_SIZE
            )));
        }

        Ok(bytes.to_vec())
    }
}

/// Transaction simulation response (replaces DryRunTransactionBlockResponse)
#[derive(Debug)]
pub struct DryRunTransactionBlockResponse {
    pub effects: TransactionEffects,
}

/// Transaction effects
#[derive(Debug)]
pub struct TransactionEffects {
    inner: sui_rpc::proto::sui::rpc::v2beta2::TransactionEffects,
}

impl TransactionEffects {
    /// Get gas cost summary
    pub fn gas_cost_summary(&self) -> GasCostSummary {
        GasCostSummary {
            computation_cost: self
                .inner
                .gas_used
                .as_ref()
                .and_then(|g| g.computation_cost)
                .unwrap_or(0),
        }
    }

    /// Get execution status
    pub fn status(&self) -> SuiExecutionStatus {
        if let Some(ref status) = self.inner.status {
            if status.success.unwrap_or(false) {
                SuiExecutionStatus::Success
            } else {
                SuiExecutionStatus::Failure {
                    error: status
                        .error
                        .as_ref()
                        .map(|e| format!("{:?}", e))
                        .unwrap_or_default(),
                }
            }
        } else {
            // Missing status should be treated as an error, not success
            SuiExecutionStatus::Failure {
                error: "Missing execution status in response".to_string(),
            }
        }
    }
}

/// Gas cost summary
pub struct GasCostSummary {
    pub computation_cost: u64,
}

/// Execution status
pub enum SuiExecutionStatus {
    Success,
    Failure { error: String },
}

/// Trait for determining if an error is retriable
pub trait RetriableError {
    /// Returns true if the error is transient and the operation should be retried
    fn is_retriable_error(&self) -> bool;
}

impl RetriableError for RpcError {
    fn is_retriable_error(&self) -> bool {
        // Only gRPC errors with specific status codes should be retried
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

impl RpcError {
    /// Helper to convert gRPC errors to RpcError
    fn from_grpc(e: tonic::Status) -> Self {
        Self {
            message: format!("gRPC error: {}", e),
            code: Some(e.code()),
        }
    }
}

/// Executes an async function with automatic retries for retriable errors
async fn sui_rpc_with_retries<T, E, F, Fut>(
    rpc_config: &RetryConfig,
    label: &str,
    metrics: Option<Arc<Metrics>>,
    mut func: F,
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
            if let Some(metrics) = metrics.as_ref() {
                metrics
                    .sui_rpc_request_duration_millis
                    .with_label_values(&[label, "success"])
                    .observe(start_time.elapsed().as_millis() as f64);
            }
            return result;
        }

        // Check if error is retriable and we have attempts left
        if let Err(ref error) = result {
            if error.is_retriable_error() && attempts_remaining > 1 {
                tracing::debug!(
                    "Retrying RPC call to {} due to retriable error: {:?}. Remaining attempts: {}",
                    label,
                    error,
                    attempts_remaining
                );

                if let Some(metrics) = metrics.as_ref() {
                    metrics
                        .sui_rpc_request_duration_millis
                        .with_label_values(&[label, "retriable_error"])
                        .observe(start_time.elapsed().as_millis() as f64);
                }

                // Wait before retrying with exponential backoff
                tokio::time::sleep(current_delay).await;

                // Implement exponential backoff.
                // Double the delay for next retry, but cap at max_delay
                current_delay = std::cmp::min(current_delay * 2, rpc_config.max_delay);
                attempts_remaining -= 1;
                continue;
            }
        }

        tracing::debug!(
            "RPC call to {} failed with error: {:?}. No more attempts remaining.",
            label,
            result.as_ref().err().expect("should be error")
        );

        if let Some(metrics) = metrics.as_ref() {
            metrics
                .sui_rpc_request_duration_millis
                .with_label_values(&[label, "error"])
                .observe(start_time.elapsed().as_millis() as f64);
        }

        // Either non-retriable error or no attempts remaining
        return result;
    }
}

/// Client for interacting with the Sui gRPC API.
#[derive(Clone)]
pub struct SuiRpcClient {
    grpc_client: Client,
    rpc_retry_config: RetryConfig,
    metrics: Option<Arc<Metrics>>,
}

impl SuiRpcClient {
    pub fn new(
        grpc_client: Client,
        rpc_retry_config: RetryConfig,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        Self {
            grpc_client,
            rpc_retry_config,
            metrics,
        }
    }

    /// Returns a clone of the metrics object.
    pub fn get_metrics(&self) -> Option<Arc<Metrics>> {
        self.metrics.clone()
    }

    /// Returns an object with the given options.
    pub async fn get_object_with_options(
        &self,
        object_id: ObjectID,
        show_bcs: bool,
    ) -> RpcResult<SuiObjectResponse> {
        // Build read mask - always include object_id, optionally include bcs
        let mut read_mask_paths = vec!["object_id".to_string()];
        if show_bcs {
            read_mask_paths.push("bcs".to_string());
        }

        let response = sui_rpc_with_retries(
            &self.rpc_retry_config,
            "get_object",
            self.metrics.clone(),
            || {
                let mut grpc_client = self.grpc_client.clone();
                let read_mask_paths = read_mask_paths.clone();
                async move {
                    let mut client = grpc_client.ledger_client();
                    let mut request =
                        sui_rpc::proto::sui::rpc::v2beta2::GetObjectRequest::default();
                    request.object_id = Some(object_id.to_hex_literal());
                    let mask = prost_types::FieldMask::from_paths(
                        read_mask_paths.iter().map(|s| s.as_str()),
                    );
                    request.read_mask = Some(mask);
                    client
                        .get_object(request)
                        .await
                        .map(|r| r.into_inner())
                        .map_err(RpcError::from_grpc)
                }
            },
        )
        .await?;

        Ok(SuiObjectResponse { inner: response })
    }

    /// Returns the latest checkpoint sequence number.
    pub async fn get_latest_checkpoint_sequence_number(&self) -> RpcResult<u64> {
        let response = sui_rpc_with_retries(
            &self.rpc_retry_config,
            "get_latest_checkpoint",
            self.metrics.clone(),
            || {
                let mut grpc_client = self.grpc_client.clone();
                async move {
                    let mut client = grpc_client.ledger_client();
                    let mut request =
                        sui_rpc::proto::sui::rpc::v2beta2::GetCheckpointRequest::default();
                    request.read_mask = Some(prost_types::FieldMask {
                        paths: vec!["sequence_number".to_string()],
                    });
                    client
                        .get_checkpoint(request)
                        .await
                        .map(|r| r.into_inner())
                        .map_err(RpcError::from_grpc)
                }
            },
        )
        .await?;

        response
            .checkpoint
            .and_then(|c| c.sequence_number)
            .ok_or_else(|| RpcError::new("No checkpoint sequence number in response"))
    }

    /// Returns a checkpoint timestamp in milliseconds by its sequence number.
    pub async fn get_checkpoint(&self, checkpoint_seq: u64) -> RpcResult<u64> {
        let response = sui_rpc_with_retries(
            &self.rpc_retry_config,
            "get_checkpoint",
            self.metrics.clone(),
            || {
                let mut grpc_client = self.grpc_client.clone();
                async move {
                    let mut client = grpc_client.ledger_client();
                    let mut request = sui_rpc::proto::sui::rpc::v2beta2::GetCheckpointRequest::default();
                    request.checkpoint_id = Some(
                        sui_rpc::proto::sui::rpc::v2beta2::get_checkpoint_request::CheckpointId::SequenceNumber(
                            checkpoint_seq,
                        ),
                    );
                    request.read_mask = Some(prost_types::FieldMask {
                        paths: vec!["summary.timestamp".to_string()],
                    });
                    client.get_checkpoint(request).await.map(|r| r.into_inner())
                        .map_err(RpcError::from_grpc)
                }
            },
        )
        .await?;

        let checkpoint = response
            .checkpoint
            .ok_or_else(|| RpcError::new("No checkpoint in response"))?;

        let timestamp = checkpoint
            .summary
            .and_then(|s| s.timestamp)
            .ok_or_else(|| RpcError::new("No timestamp in checkpoint"))?;

        (timestamp.seconds as u64)
            .checked_mul(SECONDS_TO_MILLIS)
            .and_then(|ms| ms.checked_add((timestamp.nanos as u64) / NANOS_TO_MILLIS))
            .ok_or_else(|| RpcError::new("Timestamp overflow"))
    }

    /// Returns the current reference gas price.
    pub async fn get_reference_gas_price(&self) -> RpcResult<u64> {
        let response = sui_rpc_with_retries(
            &self.rpc_retry_config,
            "get_epoch",
            self.metrics.clone(),
            || {
                let mut grpc_client = self.grpc_client.clone();
                async move {
                    let mut client = grpc_client.ledger_client();
                    let mut request = sui_rpc::proto::sui::rpc::v2beta2::GetEpochRequest::default();
                    request.read_mask = Some(prost_types::FieldMask {
                        paths: vec!["reference_gas_price".to_string()],
                    });
                    client
                        .get_epoch(request)
                        .await
                        .map(|r| r.into_inner())
                        .map_err(RpcError::from_grpc)
                }
            },
        )
        .await?;

        response
            .epoch
            .and_then(|e| e.reference_gas_price)
            .ok_or_else(|| RpcError::new("No reference gas price in response"))
    }

    /// Verify a user signature using the gRPC signature verification service.
    /// This is used primarily for zkLogin signatures which require JWK verification.
    pub async fn verify_signature(
        &self,
        message: &[u8],
        signature: &sui_sdk_types::UserSignature,
    ) -> RpcResult<()> {
        // Convert signature to BCS
        let sig_bcs = bcs::to_bytes(signature)
            .map_err(|e| RpcError::new(format!("Failed to serialize signature: {}", e)))?;

        let response = sui_rpc_with_retries(
            &self.rpc_retry_config,
            "verify_signature",
            self.metrics.clone(),
            || {
                let mut grpc_client = self.grpc_client.clone();
                let message = message.to_vec();
                let sig_bcs = sig_bcs.clone();
                async move {
                    let mut client = grpc_client.signature_verification_client();
                    let mut request =
                        sui_rpc::proto::sui::rpc::v2beta2::VerifySignatureRequest::default();

                    // Set the message with name for PersonalMessage
                    // PersonalMessage is a newtype around Vec<u8>, so we need to BCS-serialize the Vec<u8>
                    let message_vec = message.to_vec();
                    let message_bcs = bcs::to_bytes(&message_vec).map_err(|e| {
                        RpcError::new(format!("Failed to serialize message: {}", e))
                    })?;

                    let mut msg = sui_rpc::proto::sui::rpc::v2beta2::Bcs::default();
                    msg.value = Some(message_bcs.into());
                    msg.name = Some("PersonalMessage".to_string());
                    request.message = Some(msg);

                    // Set the signature
                    let mut sig = sui_rpc::proto::sui::rpc::v2beta2::UserSignature::default();
                    sig.bcs = Some(sig_bcs.into());
                    request.signature = Some(sig);

                    client
                        .verify_signature(request)
                        .await
                        .map(|r| r.into_inner())
                        .map_err(RpcError::from_grpc)
                }
            },
        )
        .await?;

        // Check if verification was successful
        if response.is_valid.unwrap_or(false) {
            Ok(())
        } else {
            let reason = response
                .reason
                .unwrap_or_else(|| "Unknown reason".to_string());
            Err(RpcError::new(format!(
                "Signature verification failed: {}",
                reason
            )))
        }
    }

    /// Simulate a transaction (dry run)
    pub async fn dry_run_transaction_block(
        &self,
        tx_data: sui_types::transaction::TransactionData,
    ) -> RpcResult<DryRunTransactionBlockResponse> {
        // Convert TransactionData to BCS bytes
        let tx_bytes = bcs::to_bytes(&tx_data)
            .map_err(|e| RpcError::new(format!("Failed to serialize transaction: {}", e)))?;

        let response = sui_rpc_with_retries(
            &self.rpc_retry_config,
            "simulate_transaction",
            self.metrics.clone(),
            || {
                let mut grpc_client = self.grpc_client.clone();
                let tx_bytes = tx_bytes.clone();
                async move {
                    let mut client = grpc_client.live_data_client();
                    let mut request =
                        sui_rpc::proto::sui::rpc::v2beta2::SimulateTransactionRequest::default();
                    // Create transaction with BCS bytes
                    let mut transaction = sui_rpc::proto::sui::rpc::v2beta2::Transaction::default();
                    transaction.bcs = Some(tx_bytes.into());
                    request.transaction = Some(transaction);
                    client
                        .simulate_transaction(request)
                        .await
                        .map(|r| r.into_inner())
                        .map_err(RpcError::from_grpc)
                }
            },
        )
        .await?;

        let executed_tx = response
            .transaction
            .ok_or_else(|| RpcError::new("No transaction in simulation response"))?;

        let effects = executed_tx
            .effects
            .ok_or_else(|| RpcError::new("No effects in executed transaction"))?;

        Ok(DryRunTransactionBlockResponse {
            effects: TransactionEffects { inner: effects },
        })
    }

    /// Returns a package using the MovePackageService.GetPackage method.
    pub async fn get_package(
        &self,
        package_id: ObjectID,
    ) -> RpcResult<sui_rpc::proto::sui::rpc::v2beta2::Package> {
        let response = sui_rpc_with_retries(
            &self.rpc_retry_config,
            "get_package",
            self.metrics.clone(),
            || {
                let mut grpc_client = self.grpc_client.clone();
                async move {
                    let mut client = grpc_client.package_client();
                    let mut request =
                        sui_rpc::proto::sui::rpc::v2beta2::GetPackageRequest::default();
                    request.package_id = Some(package_id.to_hex_literal());
                    client
                        .get_package(request)
                        .await
                        .map(|r| r.into_inner())
                        .map_err(RpcError::from_grpc)
                }
            },
        )
        .await?;

        response
            .package
            .ok_or_else(|| RpcError::new("No package in response"))
    }

    /// Returns an object with the given dynamic field name BCS bytes.
    /// The dynamic_field_name_bcs should be the BCS-serialized name value.
    pub async fn get_dynamic_field_object(
        &self,
        object_id: ObjectID,
        dynamic_field_name_bcs: Vec<u8>,
    ) -> RpcResult<SuiObjectResponse> {
        // List all dynamic fields with pagination
        let mut page_token: Option<Vec<u8>> = None;
        let mut matching_field = None;

        loop {
            let list_response = sui_rpc_with_retries(
                &self.rpc_retry_config,
                "list_dynamic_fields",
                self.metrics.clone(),
                || {
                    let mut grpc_client = self.grpc_client.clone();
                    let page_token = page_token.clone();
                    async move {
                        let mut client = grpc_client.live_data_client();
                        let mut request =
                            sui_rpc::proto::sui::rpc::v2beta2::ListDynamicFieldsRequest::default();
                        request.parent = Some(object_id.to_hex_literal());
                        request.read_mask = Some(prost_types::FieldMask {
                            paths: vec![
                                "parent".to_string(),
                                "field_id".to_string(),
                                "name_value".to_string(),
                            ],
                        });
                        request.page_size = Some(MAX_PAGE_SIZE);
                        if let Some(token) = &page_token {
                            request.page_token = Some(token.clone().into());
                        }
                        client
                            .list_dynamic_fields(request)
                            .await
                            .map(|r| r.into_inner())
                            .map_err(RpcError::from_grpc)
                    }
                },
            )
            .await?;

            // Search for matching field in this page
            for field in list_response.dynamic_fields {
                if let Some(ref name_value) = field.name_value {
                    if name_value.as_ref() == dynamic_field_name_bcs.as_slice() {
                        matching_field = Some(field);
                        break;
                    }
                }
            }

            // If we found the field, stop searching
            if matching_field.is_some() {
                break;
            }

            // If there's a next page, continue
            if let Some(next_token) = list_response.next_page_token {
                if !next_token.is_empty() {
                    page_token = Some(next_token.to_vec());
                    continue;
                }
            }

            // No more pages and field not found
            break;
        }

        let matching_field = matching_field
            .ok_or_else(|| RpcError::with_code("Dynamic field not found", tonic::Code::NotFound))?;

        // Get the field object ID
        let field_object_id_str = matching_field
            .field_id
            .ok_or_else(|| RpcError::new("Field has no object ID"))?;

        let response = sui_rpc_with_retries(
            &self.rpc_retry_config,
            "get_object",
            self.metrics.clone(),
            || {
                let mut grpc_client = self.grpc_client.clone();
                let field_object_id_str = field_object_id_str.clone();
                async move {
                    let mut client = grpc_client.ledger_client();
                    let mut request =
                        sui_rpc::proto::sui::rpc::v2beta2::GetObjectRequest::default();
                    request.object_id = Some(field_object_id_str);
                    client
                        .get_object(request)
                        .await
                        .map(|r| r.into_inner())
                        .map_err(RpcError::from_grpc)
                }
            },
        )
        .await?;

        Ok(SuiObjectResponse { inner: response })
    }
}

#[cfg(test)]
mod tests {
    use crate::key_server_options::RetryConfig;
    use crate::sui_rpc_client::sui_rpc_with_retries;
    use crate::sui_rpc_client::RetriableError;
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
            Ok(format!("Success on attempt {}", call_count))
        }
    }

    #[tokio::test]
    async fn test_sui_rpc_with_retries_success_first_attempt() {
        let retry_config = RetryConfig {
            max_retries: 3,
            min_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(100),
        };

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = sui_rpc_with_retries(&retry_config, "mock_function", None, || async {
            mock_function_with_counter(
                counter_clone.clone(),
                0, // Don't fail any attempts
                MockError { is_retriable: true },
            )
            .await
        })
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

        let result = sui_rpc_with_retries(&retry_config, "mock_function", None, || async {
            mock_function_with_counter(
                counter_clone.clone(),
                2, // Fail first 2 attempts, succeed on 3rd
                MockError { is_retriable: true },
            )
            .await
        })
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

        let result = sui_rpc_with_retries(&retry_config, "mock_function", None, || async {
            mock_function_with_counter(
                counter_clone.clone(),
                10, // Fail more attempts than max_retries
                MockError { is_retriable: true },
            )
            .await
        })
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

        let result = sui_rpc_with_retries(&retry_config, "mock_function", None, || async {
            mock_function_with_counter(
                counter_clone.clone(),
                10, // Fail more attempts than max_retries
                MockError {
                    is_retriable: false,
                }, // Non-retriable error
            )
            .await
        })
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

        let result = sui_rpc_with_retries(&retry_config, "mock_function", None, || async {
            mock_function_with_counter(
                counter_clone.clone(),
                10, // Always fail
                MockError { is_retriable: true },
            )
            .await
        })
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

        let result = sui_rpc_with_retries(&retry_config, "mock_function", None, || async {
            mock_function_with_counter(
                counter_clone.clone(),
                5, // Fail first 5 attempts, succeed on 6th
                MockError { is_retriable: true },
            )
            .await
        })
        .await;

        let elapsed = start_time.elapsed();

        assert!(result.is_ok());
        assert_eq!(counter.load(Ordering::SeqCst), 6);

        // Expected delays: 100ms, 200ms, 400ms, 800ms, 1000ms (exponential backoff with max cap)
        // Total expected minimum delay: 2500ms
        let expected_min_duration = Duration::from_millis(2500);
        assert!(
            elapsed >= expected_min_duration,
            "Expected at least {:?} but got {:?}",
            expected_min_duration,
            elapsed
        );
    }
}
