// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use prometheus::{Registry, Encoder};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use serde_json;
use reqwest;
use anyhow;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::DurationSeconds;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EnableMetricsPush {
    pub bearer_token: String,
    pub config: MetricsPushConfig,
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MetricsPushConfig {
    pub push_url: String,
    #[serde_as(as = "DurationSeconds<u64>")]
    #[serde(
        rename = "push_interval_secs",
        default = "push_interval_default",
        skip_serializing_if = "is_push_interval_default"
    )]
    pub push_interval: Duration,
    pub labels: Option<HashMap<String, String>>,
}

fn push_interval_default() -> Duration {
    Duration::from_secs(10)
}

fn is_push_interval_default(duration: &Duration) -> bool {
    *duration == Duration::from_secs(10)
}

#[derive(Debug, Deserialize, Serialize)]
/// MetricPayload holds static labels and metric data
/// the static labels are always sent and will be merged within the proxy
pub struct MetricPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// static labels defined in config, eg host, network, etc
    pub labels: Option<HashMap<String, String>>,
    /// protobuf encoded metric families. these must be decoded on the proxy side
    pub buf: Vec<u8>,
}

/// Responsible for sending data to seal-proxy, used within the async scope of
pub async fn push_metrics(
    mp_config: EnableMetricsPush,
    client: &reqwest::Client,
    registry: &Registry,
) -> Result<(), anyhow::Error> {
    tracing::info!(mp_config.config.push_url, "pushing metrics to remote");

    // now represents a collection timestamp for all of the metrics we send to the proxy.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time is definitely after the UNIX epoch")
        .as_millis()
        .try_into()
        .expect("timestamp must fit into an i64");

    let mut metric_families = registry.gather();
    for mf in metric_families.iter_mut() {
        for m in mf.mut_metric() {
            m.set_timestamp_ms(now);
        }
    }

    let mut buf: Vec<u8> = vec![];
    let encoder = prometheus::ProtobufEncoder::new();
    encoder.encode(&metric_families, &mut buf)?;

    // serialize the MetricPayload to JSON using serde_json and then compress the entire thing
    let serialized = serde_json::to_vec(&MetricPayload { labels: mp_config.config.labels, buf }).inspect_err(|error| {
        tracing::warn!(?error, "unable to serialize MetricPayload to JSON");
    })?;

    let mut s = snap::raw::Encoder::new();
    let compressed = s.compress_vec(&serialized).inspect_err(|error| {
        tracing::warn!(?error, "unable to snappy encode metrics");
    })?;

    let response = client
        .post(&mp_config.config.push_url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", mp_config.bearer_token))
        .header(reqwest::header::CONTENT_ENCODING, "snappy")
        .body(compressed)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = match response.text().await {
            Ok(body) => body,
            Err(error) => format!("couldn't decode response body; {error}"),
        };
        return Err(anyhow::anyhow!(
            "metrics push failed: [{}]:{}",
            status,
            body
        ));
    }
    tracing::debug!("successfully pushed metrics to {}", mp_config.config.push_url);
    Ok(())
}

/// Create a request client builder that is used to push metrics to mimir.
pub fn create_push_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("unable to build client")
}