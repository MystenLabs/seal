// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use key_server::master_keys::MasterKeys;
use key_server::{app, get_server_options_from_env};
use mysten_service::serve;
use sui_sdk::SuiClient;
use tracing::error;

#[tokio::main]
async fn main() -> Result<()> {
    let _guard = mysten_service::logging::init();

    let options = get_server_options_from_env()?;
    let master_keys = MasterKeys::load_from_env(&options.server_mode)?;

    let (monitor_handle, app) = app::<SuiClient>(options, master_keys).await?;

    tokio::select! {
        server_result = serve(app) => {
            error!("Server stopped with status {:?}", server_result);
            std::process::exit(1);
        }
        monitor_result = monitor_handle => {
            error!("Background tasks stopped with error: {:?}", monitor_result);
            std::process::exit(1);
        }
    }
}
