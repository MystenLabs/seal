use std::net::SocketAddr;

use anyhow::Result;
use tokio::{sync::oneshot, time::{sleep, Duration}, task::{JoinHandle, JoinSet}, runtime::Runtime};
use seal_proxy::runtime::{EnableMetricsPush, start_prometheus_server};
use seal_proxy::config::MetricsPushConfig;
use tokio_util::sync::CancellationToken;
use std::collections::HashMap;
use prometheus::Registry;
use seal_proxy::runtime::MetricsPushRuntime;

fn main() -> Result<()> {
    let metrics_address = SocketAddr::from(([0, 0, 0, 0], 9185));
    let cancel = CancellationToken::new();
    let bearer_token = "1234567890";
    let config = EnableMetricsPush {
        cancel: cancel.child_token(),
        bearer_token: bearer_token.to_string(),
        config: MetricsPushConfig {
            push_url: "http://seal-proxy:8000/publish/metrics".to_string(),
            push_interval: Duration::from_secs(5),
            labels: Some(HashMap::from([("host".to_string(), "demo".to_string())])),
        },
    };
    let registry = start_prometheus_server(metrics_address);
    let metrics_push_runtime = MetricsPushRuntime::start(config, registry.clone());
    let metrics_generation_runtime = MetricsGenerationRuntime::new(registry.clone());
    let (_, exit_listener) = oneshot::channel::<()>();

    if let Ok(metrics_push_runtime)  = metrics_push_runtime {
        if let Ok(metrics_generation_runtime) = metrics_generation_runtime {
            monitor_runtimes(metrics_push_runtime, metrics_generation_runtime, exit_listener, cancel)?;
        }
    }

    Ok(())
}

// this function should post metrics to 127.0.0.1:9185/metrics
fn generate_metrics(registry: &Registry) {
    let timestamp = chrono::Utc::now().timestamp_millis();
    let opts = prometheus::opts!("current_time", "Current time");
    let metric = prometheus::register_int_gauge_with_registry!(opts, registry)
        .expect("static metric is valid");
    metric .set(timestamp);

    let version = "0.1.0";
    let opts = prometheus::opts!("seal_build_info", "Seal binary info");
    let metric = prometheus::register_int_gauge_vec_with_registry!(opts, &["version"], registry)
        .expect("static metric is valid");
    metric
        .get_metric_with_label_values(&[version])
        .expect("metric exists")
        .set(1);
}

struct MetricsGenerationRuntime {
    join_handle: JoinHandle<()>,
    runtime: Runtime,
}

impl MetricsGenerationRuntime {
    fn new(registry: Registry) -> anyhow::Result<Self> {
        let runtime = Runtime::new()?;
        let join_handle = tokio::task::spawn(async move {
            loop {
                generate_metrics(&registry);
                sleep(Duration::from_secs(5)).await;
            }
        });
        Ok(Self { runtime, join_handle })
    }

    pub fn join(self) -> Result<(), anyhow::Error> {
        self.runtime.block_on(self.join_handle)?;
        Ok(())
    }
}

fn monitor_runtimes(
    metrics_push_runtime: MetricsPushRuntime,
    metrics_generation_runtime: MetricsGenerationRuntime,
    exit_listener: oneshot::Receiver<()>,
    cancel_token: CancellationToken,
) -> anyhow::Result<()> {
    let monitor_runtime = Runtime::new()?;
    monitor_runtime.block_on(async move {
        tokio::spawn(async move {
            let mut set = JoinSet::new();
            set.spawn_blocking({
                let mut metrics_push_runtime = metrics_push_runtime;
                move || metrics_push_runtime.join()
            });
            set.spawn_blocking({
                move || metrics_generation_runtime.join()
            });
            tokio::select! {
                _ = wait_until_terminated(exit_listener) => {
                    tracing::info!("received termination signal, shutting down...");
                }
                _ = set.join_next() => {
                    tracing::info!("runtime stopped successfully");
                }
            }
            cancel_token.cancel();
            tracing::info!("cancellation token triggered, waiting for tasks to shut down...");

            // Drain remaining runtimes
            while set.join_next().await.is_some() {}
            tracing::info!("all runtimes have shut down");
        })
        .await
    })?;
    Ok(())
}

/// Wait for SIGINT and SIGTERM (unix only).
#[tracing::instrument(skip_all)]
pub async fn wait_until_terminated(mut exit_listener: oneshot::Receiver<()>) {
    #[cfg(not(unix))]
    async fn wait_for_other_signals() {
        // Disables this branch in the select statement.
        std::future::pending().await
    }

    #[cfg(unix)]
    async fn wait_for_other_signals() {
        use tokio::signal::unix;

        unix::signal(unix::SignalKind::terminate())
            .expect("unable to register for SIGTERM signals")
            .recv()
            .await;
        tracing::info!("received SIGTERM")
    }

    tokio::select! {
        biased;
        _ = wait_for_other_signals() => (),
        _ = tokio::signal::ctrl_c() => tracing::info!("received SIGINT"),
        exit_or_dropped = &mut exit_listener => match exit_or_dropped {
            Err(_) => tracing::info!("exit notification sender was dropped"),
            Ok(_) => tracing::info!("exit notification received"),
        }
    }
}