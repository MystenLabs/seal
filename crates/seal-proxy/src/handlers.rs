// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use axum::{
    extract::Request, http::{Method, HeaderMap}, Extension,
    body::to_bytes,
    http::StatusCode,
};
use reqwest::header::{HeaderMap as ReqwestHeaderMap, HeaderValue, HeaderName};

use std::time::Duration;
use crate::var;
use serde::{Deserialize, Serialize};
use fastcrypto::secp256r1::Secp256r1PublicKey;
use crate::config::ProxyConfig;
use std::sync::Arc;

pub type NetworkPublicKey = Secp256r1PublicKey;

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    /// name of the node, can be anything
    pub name: String,
    /// the dns or ip address of the node with port number
    pub network_address: String,
    /// the pubkey stored on chain
    pub network_public_key: NetworkPublicKey,
}

#[derive(Debug, Clone)]
pub struct ReqwestClient {
    pub client: reqwest::Client,
    pub mimir_url: String,
}

pub fn make_reqwest_client(config: Arc<ProxyConfig>, user_agent: &str) -> ReqwestClient {
    let client = reqwest::Client::builder()
        .user_agent(user_agent)
        .pool_max_idle_per_host(config.pool_max_idle_per_host)
        .timeout(Duration::from_secs(var!("MIMIR_CLIENT_TIMEOUT", 30)))
        .build()
        .expect("cannot create reqwest client");

    ReqwestClient { client, mimir_url: config.mimir_url.clone() }
}

/// relay handler which receives metrics from nodes.  Nodes will call us at
/// this endpoint and we relay them to the upstream tsdb.
pub async fn relay_metrics_to_mimir(
    Extension(reqwest_client): Extension<ReqwestClient>,
    req: Request,
) -> Result<String, StatusCode> {
    let (parts, body) = req.into_parts();

    let req_builder = reqwest_client.client.request(convert_axum_method_to_reqwest_method(parts.method), reqwest_client.mimir_url);
    // convert the axum body to bytes
    let body_bytes = to_bytes(body, usize::MAX).await.map_err(|e| {
        tracing::error!("Error converting axum body to bytes: {}", e);
        StatusCode::BAD_GATEWAY
    })?;
    let response = req_builder
        .headers(convert_headers(&parts.headers))
        .body(body_bytes)
        .send()
        .await.map_err(|e| {
            tracing::error!("Error sending request: {}", e);
            StatusCode::BAD_GATEWAY
        })?;

    Ok(response.text().await.map_err(|e| {
        tracing::error!("Error reading response text: {}", e);
        StatusCode::BAD_GATEWAY
    })?)
}

fn convert_axum_method_to_reqwest_method(method: Method) -> reqwest::Method {
    match method {
        Method::GET => reqwest::Method::GET,
        Method::POST => reqwest::Method::POST,
        Method::PUT => reqwest::Method::PUT,
        Method::DELETE => reqwest::Method::DELETE,
        Method::HEAD => reqwest::Method::HEAD,
        _ => panic!("Unsupported method: {}", method),
    }
}

fn convert_headers(axum_headers: &HeaderMap) -> ReqwestHeaderMap {
    let mut reqwest_headers = ReqwestHeaderMap::new();

    for (key, value) in axum_headers.iter() {
        tracing::info!("header: {} = {}", key, value.to_str().unwrap_or(""));
        if let Ok(header_name) = HeaderName::from_bytes(key.as_str().as_bytes()) {
            if let Ok(header_value) = HeaderValue::from_bytes(value.as_bytes()) {
                reqwest_headers.insert(header_name, header_value);
            }
        }
    }

    reqwest_headers
}