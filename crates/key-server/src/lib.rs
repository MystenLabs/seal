// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared modules for key-server and aggregator server binaries.

// Alias the crate as `key_server` inside itself so key server and aggregator can both use.
extern crate self as key_server;

pub mod aggregator;
pub(crate) mod cache;
pub mod common;
pub mod errors;
pub mod metrics;
pub mod metrics_push;
pub mod sui_rpc_client;
pub mod valid_ptb;
