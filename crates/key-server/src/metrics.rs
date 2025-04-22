// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use prometheus::{
    register_histogram_with_registry, register_int_counter_vec_with_registry,
    register_int_counter_with_registry, Histogram, IntCounter, IntCounterVec, Registry,
};
use std::time::Instant;

#[derive(Debug)]
pub(crate) struct Metrics {
    /// Total number of requests received
    pub requests: IntCounter,

    /// Total number of service requests received
    pub service_requests: IntCounter,

    /// Total number of internal errors by type
    errors: IntCounterVec,

    /// Delay of timestamp of the latest checkpoint
    pub checkpoint_timestamp_delay: Histogram,

    /// Duration of getting the latest checkpoint timestamp
    pub get_checkpoint_timestamp_duration: Histogram,

    /// Status of requests of getting the latest checkpoint timestamp
    pub get_checkpoint_timestamp_status: IntCounterVec,

    /// Status of requests of getting the reference gas price
    pub get_reference_gas_price_status: IntCounterVec,

    /// Duration of check_policy
    pub check_policy_duration: Histogram,

    /// Duration of fetch_pkg_ids
    pub fetch_pkg_ids_duration: Histogram,

    /// Total number of requests per number of ids
    pub requests_per_number_of_ids: Histogram,
}

impl Metrics {
    pub(crate) fn new(registry: &Registry) -> Self {
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
            checkpoint_timestamp_delay: register_histogram_with_registry!(
                "checkpoint_timestamp_delay",
                "Delay of timestamp of the latest checkpoint",
                buckets(0.0, 120000.0, 1000.0),
                registry
            )
            .unwrap(),
            get_checkpoint_timestamp_duration: register_histogram_with_registry!(
                "checkpoint_timestamp_duration",
                "Duration of getting the latest checkpoint timestamp",
                default_external_call_duration_buckets(),
                registry
            )
            .unwrap(),
            get_checkpoint_timestamp_status: register_int_counter_vec_with_registry!(
                "checkpoint_timestamp_status",
                "Status of request to get the latest timestamp",
                &["status"],
                registry,
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
        }
    }

    pub(crate) fn observe_error(&self, error_type: &str) {
        self.errors.with_label_values(&[error_type]).inc();
    }
}

/// If metrics is Some, apply the closure and measure the duration of the closure and call set_duration with the duration.
/// Otherwise, just call the closure.
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

/// Create a callback function which when called will add the input transformed by f to the histogram.
pub(crate) fn observation_callback<T>(histogram: &Histogram, f: impl Fn(T) -> f64) -> impl Fn(T) {
    let histogram = histogram.clone();
    move |t| {
        histogram.observe(f(t));
    }
}

pub(crate) fn status_callback(metrics: &IntCounterVec) -> impl Fn(bool) {
    let metrics = metrics.clone();
    move |status: bool| {
        let value = match status {
            true => "success",
            false => "failure",
        };
        metrics.with_label_values(&[value]).inc();
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

fn default_external_call_duration_buckets() -> Vec<f64> {
    buckets(50.0, 2000.0, 50.0)
}

fn default_fast_call_duration_buckets() -> Vec<f64> {
    buckets(10.0, 100.0, 10.0)
}
