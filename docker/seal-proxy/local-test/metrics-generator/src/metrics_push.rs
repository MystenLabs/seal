// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use seal_proxy::client::create_push_client;
use seal_proxy::metrics_push::push_metrics_to_prometheus;
use seal_proxy::client::EnableMetricsPush;
use tokio::task::JoinHandle;
use prometheus::Registry;
use std::collections::HashMap;
use tokio_util::sync::CancellationToken;

/// Responsible for sending data to walrus-proxy, used within the async scope of
/// MetricPushRuntime::start.
async fn push_metrics(
    client: &reqwest::Client,
    push_url: &str,
    registry: &Registry,
    label_actions: Option<HashMap<String, String>>,
) -> Result<(), anyhow::Error> {
    tracing::debug!(push_url, "pushing metrics to remote");

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
    let serialized = serde_json::to_vec(&MetricPayload { labels, buf }).inspect_err(|error| {
        tracing::warn!(?error, "unable to serialize MetricPayload to JSON");
    })?;

    let mut s = snap::raw::Encoder::new();
    let compressed = s.compress_vec(&serialized).inspect_err(|error| {
        tracing::warn!(?error, "unable to snappy encode metrics");
    })?;

    let uid = Uuid::now_v7();
    let uids = uid.simple().to_string();
    let signature = network_key_pair.sign_recoverable(uid.as_bytes());
    let auth = serde_json::json!({"signature":signature.encode_base64(), "message":uids});
    let auth_encoded_with_scheme = format!(
        "Secp256k1-recoverable: {}",
        Base64::from_bytes(auth.to_string().as_bytes()).encoded()
    );
    let response = client
        .post(push_url)
        .header(reqwest::header::AUTHORIZATION, auth_encoded_with_scheme)
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
    tracing::debug!("successfully pushed metrics to {push_url}");
    Ok(())
}