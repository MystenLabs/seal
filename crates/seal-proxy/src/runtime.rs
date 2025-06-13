use std::{collections::HashMap, net::SocketAddr, time::{Duration, SystemTime, UNIX_EPOCH}};
use anyhow::Context;
use tokio::{runtime::Runtime, task::JoinHandle};
use prometheus::{Registry, Encoder, TextEncoder};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use axum::{extract::Extension, http::StatusCode, routing::get, Router};
use crate::config::MetricsPushConfig;
use tokio::runtime;

pub struct MetricsRuntime {
    /// The Prometheus registry.
    pub registry: Registry,
    pub runtime: Option<Runtime>,
}

pub const METRICS_ROUTE: &str = "/metrics";

impl MetricsRuntime {
    /// Start metrics and log collection in a new runtime
    pub fn start(metrics_address: SocketAddr) -> anyhow::Result<Self> {
        let runtime = runtime::Builder::new_multi_thread()
            .thread_name("metrics-runtime")
            .worker_threads(2)
            .enable_all()
            .build()
            .context("metrics runtime creation failed")?;
        let _guard = runtime.enter();

        Self::new(metrics_address, Some(runtime))
    }

    /// Create a new runtime for metrics and logging.
    pub fn new(metrics_address: SocketAddr, runtime: Option<Runtime>) -> anyhow::Result<Self> {
        let registry = start_prometheus_server(metrics_address);

        Ok(Self {
            runtime,
            registry,
        })
    }

}


pub async fn metrics(
    Extension(registry): Extension<Registry>,
) -> (StatusCode, String) {
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
        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });

    registry
}

/// A config struct to initialize the push metrics. Some binaries that depend on
/// MetricPushRuntime do not need nor is it appropriate to have push metrics.
#[derive(Debug)]
pub struct EnableMetricsPush {
    /// token that is used to gracefully shut down the metrics push process
    pub cancel: CancellationToken,
    pub bearer_token: String,
    /// the url, timeouts, etc used to push the metrics
    pub config: MetricsPushConfig,
}

/// MetricPushRuntime to manage the metric push task.
/// We run this in a dedicated runtime to avoid being blocked by others.
#[allow(missing_debug_implementations)]
pub struct MetricPushRuntime {
    metric_push_handle: JoinHandle<anyhow::Result<()>>,
    // INV: Runtime must be dropped last.
    runtime: Runtime,
}

impl MetricPushRuntime {
    /// Starts a task to periodically push metrics to a configured endpoint
    /// if a metrics push endpoint is configured.
    pub fn start(registry: Registry, mp_config: EnableMetricsPush) -> anyhow::Result<Self> {
        let runtime = runtime::Builder::new_multi_thread()
            .thread_name("metric-push-runtime")
            .worker_threads(1)
            .enable_all()
            .build()
            .context("metric push runtime creation failed")?;
        let _guard = runtime.enter();

        let metric_push_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(mp_config.config.push_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut client = create_push_client();
            tracing::info!("starting metrics push to '{}'", &mp_config.config.push_url);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(error) = push_metrics(
                            &mp_config.bearer_token,
                            &client,
                            &mp_config.config.push_url,
                            &registry,
                            // clone because we serialize this with our metrics
                            mp_config.config.labels.clone(),
                        ).await {
                            tracing::warn!(?error, "unable to push metrics");
                            client = create_push_client();
                        }
                    }
                    _ = mp_config.cancel.cancelled() => {
                        tracing::info!("received cancellation request, shutting down metrics push");
                        return Ok(());
                    }
                }
            }
        });

        Ok(Self {
            runtime,
            metric_push_handle,
        })
    }

    /// join handle for the task
    pub fn join(&mut self) -> Result<(), anyhow::Error> {
        tracing::debug!("waiting for the metric push to shutdown...");
        self.runtime.block_on(&mut self.metric_push_handle)?
    }
}

/// Create a request client builder that is used to push metrics to mimir.
fn create_push_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("unable to build client")
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

/// Responsible for sending data to walrus-proxy, used within the async scope of
/// MetricPushRuntime::start.
async fn push_metrics(
    bearer_token: &str,
    client: &reqwest::Client,
    push_url: &str,
    registry: &Registry,
    labels: Option<HashMap<String, String>>,
) -> Result<(), anyhow::Error> {
    tracing::debug!(push_url, "pushing metrics to remote");

    // now represents a collection timestamp for all of the metrics we send to the proxy.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

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

    let response = client
        .post(push_url)
        .header(reqwest::header::AUTHORIZATION, bearer_token)
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