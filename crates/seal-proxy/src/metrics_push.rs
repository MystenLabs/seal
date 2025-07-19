use crate::config::EnableMetricsPush;
use axum::{extract::Extension, http::StatusCode, routing::get, Router};
use prometheus::{Registry, TextEncoder};
use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
pub const METRICS_ROUTE: &str = "/metrics";
use anyhow::{anyhow, Error, Result};
use prost::Message;

// Prometheus Remote Write Protocol Buffers
// Based on https://github.com/prometheus/prometheus/blob/main/prompb/types.proto

#[derive(Clone, PartialEq, Message)]
pub struct WriteRequest {
    #[prost(message, repeated, tag = "1")]
    pub timeseries: Vec<TimeSeries>,
    // Cortex uses this field to determine the source of the write request.
    // We reserve field 2 to avoid any compatibility issues.
    // reserved 2;
    #[prost(message, repeated, tag = "3")]
    pub metadata: Vec<MetricMetadata>,
}

#[derive(Clone, PartialEq, Message)]
pub struct TimeSeries {
    #[prost(message, repeated, tag = "1")]
    pub labels: Vec<Label>,
    #[prost(message, repeated, tag = "2")]
    pub samples: Vec<Sample>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Label {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub value: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct Sample {
    #[prost(double, tag = "1")]
    pub value: f64,
    #[prost(int64, tag = "2")]
    pub timestamp: i64,
}

#[derive(Clone, PartialEq, Message)]
pub struct MetricMetadata {
    #[prost(enumeration = "MetricType", tag = "1")]
    pub r#type: i32,
    #[prost(string, tag = "2")]
    pub metric_family_name: String,
    #[prost(string, tag = "4")]
    pub help: String,
    #[prost(string, tag = "5")]
    pub unit: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum MetricType {
    Unknown = 0,
    Counter = 1,
    Gauge = 2,
    Histogram = 3,
    GaugeHistogram = 4,
    Summary = 5,
    Info = 6,
    Stateset = 7,
}

pub async fn metrics(Extension(registry): Extension<Registry>) -> (StatusCode, String) {
    let metrics_families = registry.gather();
    match TextEncoder.encode_to_string(&metrics_families) {
        Ok(metrics) => (StatusCode::OK, metrics),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("unable to encode metrics: {error}"),
        ),
    }
}

// Creates a new http server that has as a sole purpose to expose
// and endpoint that prometheus agent can use to poll for the metrics.
// A RegistryService is returned that can be used to get access in prometheus Registries.
pub fn start_prometheus_server(addr: SocketAddr) -> Registry {
    let registry = Registry::new();

    let app = Router::new()
        .route(METRICS_ROUTE, get(metrics))
        .layer(Extension(registry.clone()));

    tokio::spawn(async move {
        let listener = TcpListener::bind(&addr).await.unwrap();
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });

    registry
}

/// Create a request client builder that is used to push metrics to mimir.
fn create_push_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("unable to build client")
}

/// Push metrics directly to Prometheus remote write endpoint
/// This function converts Registry metrics to the Prometheus remote write protobuf format
/// and sends them via HTTP POST with Bearer token authentication
pub async fn push_metrics_to_prometheus(
    mp_config: &EnableMetricsPush,
    client: &reqwest::Client,
    registry: &Registry,
    external_labels: Option<HashMap<String, String>>,
) -> Result<(), Error> {
    let push_url = mp_config.config.push_url.clone();
    tracing::debug!(push_url, "pushing metrics to prometheus remote write");

    // Get current timestamp in milliseconds
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    let metric_families = registry.gather();
    let mut timeseries_vec = Vec::new();
    let mut metadata_vec = Vec::new();

    // Convert metric families to TimeSeries format
    for metric_family in metric_families {
        let metric_name = metric_family.get_name();
        let metric_type = metric_family.get_field_type();
        let help = metric_family.get_help();
        // Note: Prometheus MetricFamily doesn't include unit information
        let unit = "";

        // Add metadata for this metric family
        metadata_vec.push(MetricMetadata {
            r#type: match metric_type {
                prometheus::proto::MetricType::COUNTER => MetricType::Counter as i32,
                prometheus::proto::MetricType::GAUGE => MetricType::Gauge as i32,
                prometheus::proto::MetricType::HISTOGRAM => MetricType::Histogram as i32,
                prometheus::proto::MetricType::SUMMARY => MetricType::Summary as i32,
                prometheus::proto::MetricType::UNTYPED => MetricType::Unknown as i32,
            },
            metric_family_name: metric_name.to_string(),
            help: help.to_string(),
            unit: unit.to_string(),
        });

        for metric in metric_family.get_metric() {
            let mut labels = Vec::new();

            // Add metric name as __name__ label
            labels.push(Label {
                name: "__name__".to_string(),
                value: metric_name.to_string(),
            });

            // Add metric labels
            for label_pair in metric.get_label() {
                labels.push(Label {
                    name: label_pair.get_name().to_string(),
                    value: label_pair.get_value().to_string(),
                });
            }

            // Add external labels if provided
            if let Some(ref ext_labels) = external_labels {
                for (name, value) in ext_labels {
                    labels.push(Label {
                        name: name.clone(),
                        value: value.clone(),
                    });
                }
            }

            // Sort labels by name (required by Prometheus)
            labels.sort_by(|a, b| a.name.cmp(&b.name));

            // Extract value based on metric type
            let value = match metric_type {
                prometheus::proto::MetricType::COUNTER => {
                    if metric.has_counter() {
                        metric.get_counter().get_value()
                    } else {
                        continue;
                    }
                }
                prometheus::proto::MetricType::GAUGE => {
                    if metric.has_gauge() {
                        metric.get_gauge().get_value()
                    } else {
                        continue;
                    }
                }
                prometheus::proto::MetricType::HISTOGRAM => {
                    if metric.has_histogram() {
                        let histogram = metric.get_histogram();

                        // Add histogram buckets
                        for bucket in histogram.get_bucket() {
                            let mut bucket_labels = labels.clone();
                            bucket_labels.push(Label {
                                name: "le".to_string(),
                                value: format!("{}", bucket.get_upper_bound()),
                            });
                            bucket_labels.sort_by(|a, b| a.name.cmp(&b.name));

                            let mut bucket_name = metric_name.to_string();
                            bucket_name.push_str("_bucket");
                            bucket_labels[0].value = bucket_name;

                            timeseries_vec.push(TimeSeries {
                                labels: bucket_labels,
                                samples: vec![Sample {
                                    value: bucket.get_cumulative_count() as f64,
                                    timestamp: now,
                                }],
                            });
                        }

                        // Add histogram count
                        let mut count_labels = labels.clone();
                        count_labels[0].value = format!("{}_count", metric_name);
                        timeseries_vec.push(TimeSeries {
                            labels: count_labels,
                            samples: vec![Sample {
                                value: histogram.get_sample_count() as f64,
                                timestamp: now,
                            }],
                        });

                        // Add histogram sum
                        let mut sum_labels = labels.clone();
                        sum_labels[0].value = format!("{}_sum", metric_name);
                        timeseries_vec.push(TimeSeries {
                            labels: sum_labels,
                            samples: vec![Sample {
                                value: histogram.get_sample_sum(),
                                timestamp: now,
                            }],
                        });

                        continue;
                    } else {
                        continue;
                    }
                }
                _ => continue, // Skip unsupported metric types
            };

            // Create TimeSeries with single sample
            timeseries_vec.push(TimeSeries {
                labels,
                samples: vec![Sample {
                    value,
                    timestamp: now,
                }],
            });
        }
    }

    // Create WriteRequest
    let write_request = WriteRequest {
        timeseries: timeseries_vec,
        metadata: metadata_vec,
    };

    // Serialize to protobuf
    let mut buf = Vec::new();
    write_request
        .encode(&mut buf)
        .map_err(|e| anyhow!("Failed to encode protobuf: {}", e))?;

    // Compress with snappy
    let mut encoder = snap::raw::Encoder::new();
    let compressed = encoder
        .compress_vec(&buf)
        .map_err(|e| anyhow!("Failed to compress: {}", e))?;

    // Send HTTP request
    let bearer_token_formatted = format!("Bearer {}", mp_config.bearer_token);

    let response = client
        .post(&push_url)
        .header(reqwest::header::AUTHORIZATION, bearer_token_formatted)
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .header(reqwest::header::CONTENT_ENCODING, "snappy")
        .header("X-Prometheus-Remote-Write-Version", "0.1.0")
        .body(compressed)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = match response.text().await {
            Ok(body) => body,
            Err(error) => format!("couldn't decode response body; {error}"),
        };
        return Err(anyhow!(
            "prometheus remote write failed: [{}]: {}",
            status,
            body
        ));
    }

    tracing::debug!(
        "successfully pushed {} timeseries to prometheus remote write",
        write_request.timeseries.len()
    );
    Ok(())
}

/// Create a task that periodically pushes metrics to Prometheus remote write endpoint
pub fn prometheus_push_task(
    mp_config: EnableMetricsPush,
    registry: Registry,
    external_labels: Option<HashMap<String, String>>,
) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(mp_config.config.push_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut client = create_push_client();

        tracing::info!(
            "starting prometheus remote write push to '{}'",
            &mp_config.config.push_url
        );

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(error) = push_metrics_to_prometheus(
                        &mp_config,
                        &client,
                        &registry,
                        external_labels.clone(),
                    ).await {
                        tracing::warn!(?error, "unable to push metrics to prometheus");
                        // Recreate client on error
                        client = create_push_client();
                    }
                }
                _ = mp_config.cancel.cancelled() => {
                    tracing::info!("received cancellation request, shutting down prometheus push");
                    return Ok(());
                }
            }
        }
    })
}
