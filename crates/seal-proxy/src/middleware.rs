// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::consumer::{Label, ProtobufDecoder};
use crate::providers::BearerTokenProvider;
use crate::register_metric;
use crate::with_label;
use crate::Allower;
use axum::http::header::CONTENT_ENCODING;
use axum::{
    body::Body, extract::FromRequest, extract::Request, http::StatusCode, middleware::Next,
    response::Response, Extension,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization, ContentLength},
    typed_header::TypedHeader,
};
use bytes::Buf;
use bytes::Bytes;
use once_cell::sync::Lazy;
use prometheus::proto::MetricFamily;
use prometheus::{CounterVec, Opts};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::error;

static MIDDLEWARE_OPS: Lazy<CounterVec> = Lazy::new(|| {
    register_metric!(CounterVec::new(
        Opts::new(
            "middleware_operations",
            "Operations counters and status for axum middleware.",
        ),
        &["operation", "status"]
    )
    .unwrap())
});

/// we expect that calling seal nodes have known bearer tokens
pub async fn expect_valid_bearer_token(
    TypedHeader(auth_header): TypedHeader<Authorization<Bearer>>,
    Extension(allower): Extension<Arc<BearerTokenProvider>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, &'static str)> {
    // Extract the Authorization header
    let (allowed, _owner_name) = allower.allowed(&auth_header.token().to_string());
    if allowed {
        Ok(next.run(req).await)
    } else {
        tracing::info!("invalid token, rejecting request");
        Err((StatusCode::UNAUTHORIZED, "Unauthorized"))
    }
}

/// we expect seal to send us an http header content-length encoding.
pub async fn expect_content_length(
    TypedHeader(_content_length): TypedHeader<ContentLength>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, &'static str)> {
    Ok(next.run(request).await)
}

/// MetricFamilyWithStaticLabels takes labels that were signaled to us from the node as well
/// as their metrics and creates an axum Extension type param that can be used in middleware
#[derive(Debug)]
pub struct MetricFamilyWithStaticLabels {
    /// static labels defined in config, eg host, network, etc
    pub labels: Option<Vec<Label>>,
    /// the metrics the node sent us, decoded from protobufs
    pub metric_families: Vec<MetricFamily>,
}

/// LenDelimProtobuf is an axum extractor that will consume protobuf content by
/// decompressing it and decoding it into protobuf metrics. the body payload is
/// a json payload that is snappy compressed.  it has a structure seen in
/// MetricPayload.  The buf field is protobuf encoded `Vec<MetricFamily>`
#[derive(Debug)]
pub struct LenDelimProtobuf(pub MetricFamilyWithStaticLabels);

impl<S> FromRequest<S> for LenDelimProtobuf
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request(
        req: Request<axum::body::Body>,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        req.headers()
            .get(CONTENT_ENCODING)
            .map(|v| v.as_bytes() == b"snappy")
            .unwrap_or(false)
            .then_some(())
            .ok_or((
                StatusCode::BAD_REQUEST,
                "snappy compression is required".into(),
            ))?;

        let body = Bytes::from_request(req, state).await.map_err(|e| {
            let msg = format!("error extracting bytes; {e}");
            error!(msg);
            with_label!(
                MIDDLEWARE_OPS,
                "LenDelimProtobuf_from_request",
                "unable-to-extract-bytes"
            )
            .inc();
            (e.status(), msg)
        })?;

        let mut s = snap::raw::Decoder::new();
        let decompressed = s.decompress_vec(&body).map_err(|e| {
            let msg = format!("unable to decode snappy encoded protobufs; {e}");
            error!(msg);
            with_label!(
                MIDDLEWARE_OPS,
                "LenDelimProtobuf_decompress_vec",
                "unable-to-decode-snappy"
            )
            .inc();
            (StatusCode::BAD_REQUEST, msg)
        })?;

        #[derive(Deserialize)]
        struct Payload {
            labels: Option<HashMap<String, String>>,
            buf: Vec<u8>,
        }
        let metric_payload: Payload = serde_json::from_slice(&decompressed).map_err(|error| {
            let msg = "unable to deserialize MetricPayload";
            error!(?error, msg);
            (StatusCode::BAD_REQUEST, msg.into())
        })?;

        let mut decoder = ProtobufDecoder::new(Bytes::from(metric_payload.buf).reader());
        let metric_families = decoder.parse::<MetricFamily>().map_err(|e| {
            let msg = format!("unable to decode len delimited protobufs; {e}");
            error!(msg);
            with_label!(
                MIDDLEWARE_OPS,
                "LenDelimProtobuf_from_request",
                "unable-to-decode-protobufs"
            )
            .inc();
            (StatusCode::BAD_REQUEST, msg)
        })?;

        let labels: Option<Vec<Label>> = metric_payload.labels.map(|map| {
            map.into_iter()
                .map(|(k, v)| Label { name: k, value: v })
                .collect()
        });
        Ok(Self(MetricFamilyWithStaticLabels {
            labels,
            metric_families,
        }))
    }
}
