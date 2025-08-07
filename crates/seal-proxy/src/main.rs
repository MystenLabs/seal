// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use clap::Parser;
use seal_proxy::metrics;
use seal_proxy::{
    admin::{app, make_reqwest_client, server},
    config::{load, ProxyConfig},
    histogram_relay::start_prometheus_server,
    providers::BearerTokenProvider,
};
use tracing::info;

// Define the `GIT_REVISION` and `VERSION` consts
seal_proxy::bin_version!();

/// user agent we use when posting to mimir
static APP_USER_AGENT: &str = const_str::concat!(env!("CARGO_BIN_NAME"), "/", VERSION);

#[derive(Parser, Debug)]
#[command(
    name = env!("CARGO_BIN_NAME"),
    version = VERSION,
    rename_all = "kebab-case"
)]
struct Args {
    #[arg(
        long,
        short,
        default_value = "./seal-proxy.yaml",
        help = "Specify the config file path to use"
    )]
    config: String,
    #[arg(long, short, help = "Specify the bearer tokens file path to use")]
    bearer_tokens_path: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let _registry_guard = metrics::seal_proxy_prom_registry();
    let args = Args::parse();

    let config: ProxyConfig = load(&args.config)?;
    info!(
        "listen on {:?} send to {:?}",
        config.listen_address, config.remote_write.url
    );

    let listener = tokio::net::TcpListener::bind(config.listen_address).await?;
    let histogram_listener = std::net::TcpListener::bind(config.histogram_address)?;
    let metrics_listener = std::net::TcpListener::bind(config.metrics_address)?;

    let remote_write_client = make_reqwest_client(config.remote_write, APP_USER_AGENT);
    let histogram_relay = start_prometheus_server(histogram_listener);
    metrics::start_prometheus_server(metrics_listener);

    // if bearer tokens path is not provided, don't create a bearer token provider
    // if the bearer tokens path is provided but the file is not found or is invalid, return an error
    let bearer_token_provider = match BearerTokenProvider::new(args.bearer_tokens_path) {
        Ok(bearer_token_provider) => bearer_token_provider,
        Err(e) => {
            tracing::error!("error creating bearer token provider: {}", e);
            return Err(e);
        }
    };

    // Build our application with a route
    let app = app(
        remote_write_client,
        bearer_token_provider,
        histogram_relay,
        config.label_actions,
    );

    server(listener, app).await?;

    Ok(())
}
