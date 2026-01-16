// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use axum::{extract::State, middleware};
use prometheus::{
    register_histogram_vec_with_registry, register_histogram_with_registry,
    register_int_counter_vec_with_registry, register_int_counter_with_registry,
    register_int_gauge_vec_with_registry, Histogram, HistogramVec, IntCounter, IntCounterVec,
    IntGaugeVec, Registry,
};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug)]
pub struct KeyServerMetrics {
    /// Total number of requests received
    pub requests: IntCounter,

    /// Total number of service requests received
    pub service_requests: IntCounter,

    /// Total number of internal errors by type
    errors: IntCounterVec,

    /// Status of requests of getting the reference gas price
    pub get_reference_gas_price_status: IntCounterVec,

    /// Duration of check_policy
    pub check_policy_duration: Histogram,

    /// Duration of fetch_pkg_ids
    pub fetch_pkg_ids_duration: Histogram,

    /// Total number of requests per number of ids
    pub requests_per_number_of_ids: Histogram,

    /// HTTP request latency by route and status code
    pub http_request_duration_millis: HistogramVec,

    /// HTTP request count by route and status code
    pub http_requests_total: IntCounterVec,

    /// HTTP request in flight by route
    pub http_request_in_flight: IntGaugeVec,

    /// Sui RPC request duration by label
    pub sui_rpc_request_duration_millis: HistogramVec,

    /// Dry run gas cost per package
    pub dry_run_gas_cost_per_package: HistogramVec,

    /// Total number of requests failed due to stale FN
    pub requests_failed_due_to_staleness: IntCounter,

    /// The current key server version
    pub key_server_version: IntCounterVec,

    /// Client SDK versions by type seen in requests
    pub client_sdk_version: IntCounterVec,
}

impl KeyServerMetrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            requests: register_int_counter_with_registry!(
                "total_requests",
                "Total number of fetch_key requests received",
                registry
            )
            .unwrap(),
            errors: register_int_counter_vec_with_registry!(
                "internal_errors",
                "Total number of internal errors by type",
                &["internal_error_type"],
                registry
            )
            .unwrap(),
            service_requests: register_int_counter_with_registry!(
                "service_requests",
                "Total number of service requests received",
                registry
            )
            .unwrap(),
            fetch_pkg_ids_duration: register_histogram_with_registry!(
                "fetch_pkg_ids_duration",
                "Duration of fetch_pkg_ids",
                default_fast_call_duration_buckets(),
                registry
            )
            .unwrap(),
            check_policy_duration: register_histogram_with_registry!(
                "check_policy_duration",
                "Duration of check_policy",
                default_fast_call_duration_buckets(),
                registry
            )
            .unwrap(),
            get_reference_gas_price_status: register_int_counter_vec_with_registry!(
                "get_reference_gas_price_status",
                "Status of requests of getting the reference gas price",
                &["status"],
                registry
            )
            .unwrap(),
            requests_per_number_of_ids: register_histogram_with_registry!(
                "requests_per_number_of_ids",
                "Total number of requests per number of ids",
                buckets(0.0, 5.0, 1.0),
                registry
            )
            .unwrap(),
            http_request_duration_millis: register_histogram_vec_with_registry!(
                "http_request_duration_millis",
                "HTTP request duration in milliseconds",
                &["route", "status"],
                default_fast_call_duration_buckets(),
                registry
            )
            .unwrap(),
            http_requests_total: register_int_counter_vec_with_registry!(
                "http_requests_total",
                "Total number of HTTP requests",
                &["route", "status"],
                registry
            )
            .unwrap(),
            http_request_in_flight: register_int_gauge_vec_with_registry!(
                "http_request_in_flight",
                "Number of HTTP requests in flight",
                &["route"],
                registry
            )
            .unwrap(),
            sui_rpc_request_duration_millis: register_histogram_vec_with_registry!(
                "sui_rpc_request_duration_millis",
                "Sui RPC request duration and status in milliseconds",
                &["method", "status"],
                default_fast_call_duration_buckets(),
                registry
            )
            .unwrap(),
            dry_run_gas_cost_per_package: register_histogram_vec_with_registry!(
                "dry_run_gas_cost_per_package",
                "Dry run gas cost per package",
                &["package"],
                buckets(0.0, 500_000_000.0, 5_000_000.0),
                registry
            )
            .unwrap(),
            requests_failed_due_to_staleness: register_int_counter_with_registry!(
                "requests_failed_due_to_staleness",
                "Total number of requests that failed due to a stale fullnode",
                registry
            )
            .unwrap(),
            key_server_version: register_int_counter_vec_with_registry!(
                "key_server_version",
                "The current key server version",
                &["version"],
                registry
            )
            .unwrap(),
            client_sdk_version: register_int_counter_vec_with_registry!(
                "client_sdk_version",
                "Client SDK versions by type seen in requests",
                &["sdk_type", "version"],
                registry
            )
            .unwrap(),
        }
    }

    pub fn observe_error(&self, error_type: &str) {
        self.errors.with_label_values(&[error_type]).inc();
    }
}

/// If metrics is Some, apply the closure and measure the duration of the closure and call set_duration with the duration.
/// Otherwise, just call the closure.
#[allow(dead_code)]
pub(crate) fn call_with_duration<T>(metrics: Option<&Histogram>, closure: impl FnOnce() -> T) -> T {
    if let Some(metrics) = metrics {
        let start = Instant::now();
        let result = closure();
        metrics.observe(start.elapsed().as_millis() as f64);
        result
    } else {
        closure()
    }
}

#[allow(dead_code)]
pub(crate) fn status_callback(metrics: &IntCounterVec) -> impl Fn(bool) + use<> {
    let metrics = metrics.clone();
    move |status: bool| {
        let label = match status {
            true => "success",
            false => "failure",
        };
        metrics.with_label_values(&[label]).inc();
    }
}

fn buckets(start: f64, end: f64, step: f64) -> Vec<f64> {
    let mut buckets = vec![];
    let mut current = start;
    while current < end {
        buckets.push(current);
        current += step;
    }
    buckets.push(end);
    buckets
}

fn default_fast_call_duration_buckets() -> Vec<f64> {
    buckets(10.0, 100.0, 10.0)
}

/// Collector that tracks the uptime of the server.
pub fn uptime_metric(service_name: &str, version: &str) -> Box<dyn prometheus::core::Collector> {
    let opts = prometheus::opts!(
        "uptime",
        format!("uptime of the {} in seconds", service_name)
    )
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

pub type Metrics = KeyServerMetrics;

#[allow(dead_code)]
#[derive(Debug)]
pub struct AggregatorMetrics {
    /// Total number of requests received
    pub requests: IntCounter,

    /// Total number of internal errors by type
    errors: IntCounterVec,

    /// HTTP request latency by route and status code
    pub http_request_duration_millis: HistogramVec,

    /// HTTP request count by route and status code
    pub http_requests_total: IntCounterVec,

    /// HTTP request in flight by route
    pub http_request_in_flight: IntGaugeVec,

    /// Client SDK versions by type seen in requests
    pub client_sdk_version: IntCounterVec,

    /// Key server versions seen in responses from committee members
    pub upstream_key_server_version: IntCounterVec,
}

#[allow(dead_code)]
impl AggregatorMetrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            requests: register_int_counter_with_registry!(
                "total_requests",
                "Total number of fetch_key requests received",
                registry
            )
            .unwrap(),
            errors: register_int_counter_vec_with_registry!(
                "internal_errors",
                "Total number of internal errors by type",
                &["internal_error_type"],
                registry
            )
            .unwrap(),
            http_request_duration_millis: register_histogram_vec_with_registry!(
                "http_request_duration_millis",
                "HTTP request duration in milliseconds",
                &["route", "status"],
                default_fast_call_duration_buckets(),
                registry
            )
            .unwrap(),
            http_requests_total: register_int_counter_vec_with_registry!(
                "http_requests_total",
                "Total number of HTTP requests",
                &["route", "status"],
                registry
            )
            .unwrap(),
            http_request_in_flight: register_int_gauge_vec_with_registry!(
                "http_request_in_flight",
                "Number of HTTP requests in flight",
                &["route"],
                registry
            )
            .unwrap(),
            client_sdk_version: register_int_counter_vec_with_registry!(
                "client_sdk_version",
                "Client SDK versions by type seen in requests",
                &["sdk_type", "version"],
                registry
            )
            .unwrap(),
            upstream_key_server_version: register_int_counter_vec_with_registry!(
                "upstream_key_server_version",
                "Key server versions seen in responses from committee members",
                &["version"],
                registry
            )
            .unwrap(),
        }
    }

    pub fn observe_error(&self, error_type: &str) {
        self.errors.with_label_values(&[error_type]).inc();
    }
}

/// Middleware that tracks metrics for HTTP requests and response status (for key server).
pub async fn metrics_middleware(
    State(metrics): State<Arc<KeyServerMetrics>>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    let route = request.uri().path().to_string();
    let start = std::time::Instant::now();

    metrics
        .http_request_in_flight
        .with_label_values(&[&route])
        .inc();

    let response = next.run(request).await;

    metrics
        .http_request_in_flight
        .with_label_values(&[&route])
        .dec();

    let duration = start.elapsed().as_millis() as f64;
    let status = response.status().as_str().to_string();

    metrics
        .http_request_duration_millis
        .with_label_values(&[&route, &status])
        .observe(duration);
    metrics
        .http_requests_total
        .with_label_values(&[&route, &status])
        .inc();

    response
}

/// Middleware that tracks metrics for HTTP requests and response status (for aggregator).
#[allow(dead_code)]
pub async fn aggregator_metrics_middleware(
    State(metrics): State<Arc<AggregatorMetrics>>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    let route = request.uri().path().to_string();
    let start = std::time::Instant::now();

    metrics
        .http_request_in_flight
        .with_label_values(&[&route])
        .inc();

    let response = next.run(request).await;

    metrics
        .http_request_in_flight
        .with_label_values(&[&route])
        .dec();

    let duration = start.elapsed().as_millis() as f64;
    let status = response.status().as_str().to_string();

    metrics
        .http_request_duration_millis
        .with_label_values(&[&route, &status])
        .observe(duration);
    metrics
        .http_requests_total
        .with_label_values(&[&route, &status])
        .inc();

    response
}
