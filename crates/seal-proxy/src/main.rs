use anyhow::Result;
use clap::Parser;
use seal_proxy::metrics;
use seal_proxy::{
    allowers::BearerTokenProvider,
    config::{load, ProxyConfig},
    handlers::make_reqwest_client,
    server::app,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Serialize, Deserialize)]
struct Metrics {
    // Add your metrics fields here based on Alloy's format
    #[serde(flatten)]
    data: serde_json::Value,
}

// Define the `GIT_REVISION` and `VERSION` consts
seal_proxy::bin_version!();

/// user agent we use when posting to mimir
static APP_USER_AGENT: &str = const_str::concat!(
    env!("CARGO_BIN_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "/",
    VERSION
);

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
    bearer_tokens_path: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let _registry_guard = metrics::seal_proxy_prom_registry();

    let args = Args::parse();
    let config: Arc<ProxyConfig> = Arc::new(load(&args.config)?);
    let reqwest_client = make_reqwest_client(config.clone(), APP_USER_AGENT);

    // if bearer tokens path is not provided, don't create a bearer token provider
    // if the bearer tokens path is provided but the file is not found or is invalid, return an error
    let allower = match BearerTokenProvider::new(args.bearer_tokens_path) {
        Ok(allower) => allower,
        Err(e) => {
            tracing::error!("error creating bearer token provider: {}", e);
            return Err(e);
        }
    };

    // Build our application with a route
    let app = app(reqwest_client, allower);

    // Run it
    let addr = config.listen_address.parse::<SocketAddr>()?;
    tracing::info!("listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
