// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use crate::config::{LabelActions, RemoteWriteConfig};
use crate::handlers::{extract_client_ip, publish_metrics};
use crate::histogram_relay::HistogramRelay;
use crate::middleware::{expect_content_length, expect_valid_bearer_token};
use crate::providers::BearerTokenProvider;
use crate::var;
use axum::{extract::DefaultBodyLimit, middleware, routing::post, Extension, Router};
use std::sync::Arc;
use tokio::signal;
use tower::ServiceBuilder;
use tower_http::{
    timeout::TimeoutLayer,
    trace::{DefaultOnFailure, DefaultOnResponse, TraceLayer},
    LatencyUnit,
};
use tracing::{info, Level};

/// Reqwest client holds the global client for remote_push api calls
/// it also holds the username and password.  The client has an underlying
/// connection pool.  See reqwest documentation for details
#[derive(Debug, Clone)]
pub struct ReqwestClient {
    /// client pool builder for connections to mimir
    pub client: reqwest::Client,
    /// settings for remote write connection
    pub settings: RemoteWriteConfig,
}

/// make a reqwest client to connect to mimir
pub fn make_reqwest_client(settings: RemoteWriteConfig, user_agent: &str) -> ReqwestClient {
    info!("making reqwest client with user agent: {:?}", user_agent);
    ReqwestClient {
        client: reqwest::Client::builder()
            .use_native_tls()
            .user_agent(user_agent)
            .pool_max_idle_per_host(settings.pool_max_idle_per_host)
            .timeout(Duration::from_secs(var!("MIMIR_CLIENT_TIMEOUT", 30)))
            .build()
            .expect("cannot create reqwest client"),
        settings,
    }
}

/// build our axum app
pub fn app(
    reqwest_client: ReqwestClient,
    allower: BearerTokenProvider,
    histogram_relay: HistogramRelay,
    label_actions: LabelActions,
) -> Router {
    // build our application with a route and our sender mpsc
    let mut router = Router::new()
        .route("/publish/metrics", post(publish_metrics))
        .route_layer(DefaultBodyLimit::max(var!(
            "MAX_BODY_SIZE",
            1024 * 1024 * 5
        )))
        .route_layer(middleware::from_fn(expect_content_length))
        .route_layer(middleware::from_fn(extract_client_ip));

    // if we have an allower, add the middleware and extension
    tracing::info!("adding bearer token middleware");
    router = router
        .route_layer(middleware::from_fn(expect_valid_bearer_token))
        .layer(Extension(Arc::new(allower)));

    router
        // Enforce on all routes.
        // If the request does not complete within the specified timeout it will be aborted
        // and a 408 Request Timeout response will be sent.
        .layer(TimeoutLayer::new(Duration::from_secs(var!(
            "NODE_CLIENT_TIMEOUT",
            20
        ))))
        .layer(Extension(reqwest_client))
        .layer(Extension(histogram_relay))
        .layer(Extension(label_actions))
        .layer(
            ServiceBuilder::new().layer(
                TraceLayer::new_for_http()
                    .on_response(
                        DefaultOnResponse::new()
                            .level(Level::INFO)
                            .latency_unit(LatencyUnit::Seconds),
                    )
                    .on_failure(
                        DefaultOnFailure::new()
                            .level(Level::ERROR)
                            .latency_unit(LatencyUnit::Seconds),
                    ),
            ),
        )
}

/// Server creates our http/https server
pub async fn server(listener: tokio::net::TcpListener, app: Router) -> std::io::Result<()> {
    // run the server
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
