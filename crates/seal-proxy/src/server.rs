// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use axum::{Extension, Router, extract::DefaultBodyLimit, middleware, routing::post};
use tokio::signal;
use tower::ServiceBuilder;
use tower_http::{
    LatencyUnit,
    timeout::TimeoutLayer,
    trace::{DefaultOnFailure, DefaultOnResponse, TraceLayer},
};
use tracing::Level;
use crate::handlers::relay_metrics_to_mimir;
use crate::handlers::ReqwestClient;
use crate::middleware::expect_valid_bearer_token;
use crate::var;
use crate::allowers::BearerTokenProvider;
use std::sync::Arc;

/// build our axum app
pub fn app(
    reqwest_client: ReqwestClient,
    allower: Option<BearerTokenProvider>,
) -> Router {
    // build our application with a route and our sender mpsc
    let mut router = Router::new()
        .route("/publish/metrics", post(relay_metrics_to_mimir))
        .layer(Extension(reqwest_client))
        .route_layer(DefaultBodyLimit::max(var!(
            "MAX_BODY_SIZE",
            1024 * 1024 * 5
        )));
    
    // if we have an allower, add the middleware and extension
    if let Some(allower) = allower {
        tracing::info!("adding bearer token middleware");
        router = router.route_layer(middleware::from_fn(expect_valid_bearer_token))
            .layer(Extension(Arc::new(allower)));
    } else {
        tracing::info!("no bearer token middleware");
    }
        
    router
        // Enforce on all routes.
        // If the request does not complete within the specified timeout it will be aborted
        // and a 408 Request Timeout response will be sent.
        .layer(TimeoutLayer::new(Duration::from_secs(var!(
            "NODE_CLIENT_TIMEOUT",
            20
        ))))
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
