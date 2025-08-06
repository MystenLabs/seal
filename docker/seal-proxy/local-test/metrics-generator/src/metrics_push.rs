// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use prometheus::{Registry, Encoder};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use serde_json;
use reqwest;
use anyhow;
use serde::{Deserialize, Serialize};
use crate::EnableMetricsPush;

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