// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use sui_rpc::Client;
use sui_rpc::proto::sui::rpc::v2beta2::{
    GetCheckpointRequest, GetCheckpointResponse,
    GetObjectRequest, GetObjectResponse,
    ListDynamicFieldsRequest, ListDynamicFieldsResponse,
    SimulateTransactionRequest, SimulateTransactionResponse,
};
use sui_sdk_types::Address as ObjectId;
use sui_sdk_types::{Transaction, TypeTag};
use prost_types::FieldMask;

use crate::{key_server_options::RetryConfig, metrics::Metrics};

/// Error type for RPC operations
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("RPC error: {0}")]
    Status(String),
    #[error("Other error: {0}")]
    Other(String),
}

pub type RpcResult<T> = Result<T, RpcError>;

/// Trait for determining if an error is retriable
pub trait RetriableError {
    /// Returns true if the error is transient and the operation should be retried
    fn is_retriable_error(&self) -> bool;
}

impl RetriableError for RpcError {
    fn is_retriable_error(&self) -> bool {
        match self {
            RpcError::Status(status_msg) => {
                // Simple heuristic: retry on common network/timeout error messages
                status_msg.contains("Unavailable")
                    || status_msg.contains("DeadlineExceeded")
                    || status_msg.contains("Internal")
                    || status_msg.contains("Unknown")
            }
            _ => false,
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

/// Client for interacting with the Sui RPC API.
#[derive(Clone)]
pub struct SuiRpcClient {
    client: Client,
    rpc_retry_config: RetryConfig,
    metrics: Option<Arc<Metrics>>,
}

impl SuiRpcClient {
    pub fn new(
        url: &str,
        rpc_retry_config: RetryConfig,
        metrics: Option<Arc<Metrics>>,
    ) -> Result<Self, RpcError> {
        let client = Client::new(url).map_err(|e| RpcError::Other(e.to_string()))?;
        Ok(Self {
            client,
            rpc_retry_config,
            metrics,
        })
    }

    /// Returns a clone of the metrics object.
    pub fn get_metrics(&self) -> Option<Arc<Metrics>> {
        self.metrics.clone()
    }

    /// Simulates a transaction (dry run).
    pub async fn dry_run_transaction_block(
        &mut self,
        tx_data: Transaction,
    ) -> RpcResult<SimulateTransactionResponse> {
        // Convert Transaction to proto format
        let transaction_bytes = bcs::to_bytes(&tx_data)
            .map_err(|e| RpcError::Other(format!("Failed to serialize transaction: {}", e)))?;

        let mut request = SimulateTransactionRequest::default();
        let mut transaction = sui_rpc::proto::sui::rpc::v2beta2::Transaction::default();
        let mut bcs = sui_rpc::proto::sui::rpc::v2beta2::Bcs::default();
        bcs.name = Some("Transaction".to_string());
        bcs.value = Some(transaction_bytes.into());
        transaction.bcs = Some(bcs);
        request.transaction = Some(transaction);
        request.do_gas_selection = Some(false);

        self.client
            .live_data_client()
            .simulate_transaction(request)
            .await
            .map(|r| r.into_inner())
            .map_err(|e| RpcError::Status(e.to_string()))
    }

    /// Returns an object with the given options.
    pub async fn get_object_with_options(
        &mut self,
        object_id: ObjectId,
        read_mask: Option<FieldMask>,
    ) -> RpcResult<GetObjectResponse> {
        let mut request = GetObjectRequest::default();
        request.object_id = Some(object_id.to_string());
        request.read_mask = read_mask.clone();

        self.client
            .ledger_client()
            .get_object(request)
            .await
            .map(|r| r.into_inner())
            .map_err(|e| RpcError::Status(e.to_string()))
    }

    /// Returns the latest checkpoint sequence number.
    pub async fn get_latest_checkpoint_sequence_number(&mut self) -> RpcResult<u64> {
        // Get the latest checkpoint
        let mut request = GetCheckpointRequest::default();
        request.checkpoint_id = None; // None means latest

        let response = self.client
            .ledger_client()
            .get_checkpoint(request)
            .await
            .map_err(|e| RpcError::Status(e.to_string()))?
            .into_inner();

        response
            .checkpoint
            .and_then(|c| c.sequence_number)
            .ok_or_else(|| RpcError::Other("No sequence number in response".to_string()))
    }

    /// Returns a checkpoint by its sequence number.
    pub async fn get_checkpoint(&mut self, sequence_number: u64) -> RpcResult<GetCheckpointResponse> {
        let mut request = GetCheckpointRequest::default();
        request.checkpoint_id = Some(sui_rpc::proto::sui::rpc::v2beta2::get_checkpoint_request::CheckpointId::SequenceNumber(sequence_number));

        self.client
            .ledger_client()
            .get_checkpoint(request)
            .await
            .map(|r| r.into_inner())
            .map_err(|e| RpcError::Status(e.to_string()))
    }

    /// Returns the current reference gas price.
    pub async fn get_reference_gas_price(&mut self) -> RpcResult<u64> {
        // Get latest epoch info which contains gas price
        let mut epoch_request = sui_rpc::proto::sui::rpc::v2beta2::GetEpochRequest::default();
        epoch_request.epoch = None; // None means latest

        let response = self.client
            .ledger_client()
            .get_epoch(epoch_request)
            .await
            .map_err(|e| RpcError::Status(e.to_string()))?
            .into_inner();

        response
            .epoch
            .and_then(|e| e.reference_gas_price)
            .ok_or_else(|| RpcError::Other("No reference gas price in response".to_string()))
    }

    /// Returns an object with the given dynamic field name.
    pub async fn get_dynamic_field_object(
        &mut self,
        object_id: ObjectId,
        _dynamic_field_name: DynamicFieldName,
    ) -> RpcResult<ListDynamicFieldsResponse> {
        let mut request = ListDynamicFieldsRequest::default();
        request.parent = Some(object_id.to_string());
        request.page_size = Some(1);

        self.client
            .live_data_client()
            .list_dynamic_fields(request)
            .await
            .map(|r| r.into_inner())
            .map_err(|e| RpcError::Status(e.to_string()))
    }
}

/// Dynamic field name for querying
#[derive(Debug, Clone)]
pub struct DynamicFieldName {
    pub type_: TypeTag,
    pub value: serde_json::Value,
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