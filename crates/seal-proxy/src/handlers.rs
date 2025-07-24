// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use axum::{
    body::to_bytes,
    extract::Request,
    http::StatusCode,
    http::{HeaderMap, Method},
    Extension,
};
use reqwest::header::{HeaderMap as ReqwestHeaderMap, HeaderName, HeaderValue};

use crate::config::ProxyConfig;
use crate::var;
use std::sync::Arc;
use std::time::Duration;

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

    ReqwestClient {
        client,
        mimir_url: config.mimir_url.clone(),
    }
}

/// relay handler which receives metrics from nodes.  Nodes will call us at
/// this endpoint and we relay them to the upstream tsdb.
pub async fn relay_metrics_to_mimir(
    Extension(reqwest_client): Extension<ReqwestClient>,
    req: Request,
) -> Result<String, StatusCode> {
    let (parts, body) = req.into_parts();

    let req_builder = reqwest_client.client.request(
        convert_axum_method_to_reqwest_method(parts.method),
        reqwest_client.mimir_url,
    );
    // convert the axum body to bytes
    let body_bytes = to_bytes(body, usize::MAX).await.map_err(|e| {
        tracing::error!("Error converting axum body to bytes: {}", e);
        StatusCode::BAD_GATEWAY
    })?;
    let response = req_builder
        .headers(convert_headers(&parts.headers))
        .body(body_bytes)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Error sending request: {}", e);
            StatusCode::BAD_GATEWAY
        })?;

    response.text().await.map_err(|e| {
        tracing::error!("Error reading response text: {}", e);
        StatusCode::BAD_GATEWAY
    })
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
        if let Ok(header_name) = HeaderName::from_bytes(key.as_str().as_bytes()) {
            if let Ok(header_value) = HeaderValue::from_bytes(value.as_bytes()) {
                reqwest_headers.insert(header_name, header_value);
            }
        }
    }

    reqwest_headers
}
