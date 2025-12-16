// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

/// Shared error response format used by key-server and aggregator-server.
/// This matches the JSON format returned by key servers.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        let status = match self.error.as_str() {
            "InvalidPTB"
            | "InvalidPackage"
            | "NoAccess"
            | "InvalidCertificate"
            | "InvalidSignature"
            | "InvalidSessionSignature"
            | "InvalidParameter"
            | "InvalidMVRName" => StatusCode::FORBIDDEN,
            "InvalidSDKVersion"
            | "InvalidServiceId"
            | "UnsupportedPackageId"
            | "MissingRequiredHeader" => StatusCode::BAD_REQUEST,
            "DeprecatedSDKVersion" => StatusCode::UPGRADE_REQUIRED,
            _ => StatusCode::SERVICE_UNAVAILABLE, // Default for "Failure" and unknown errors
        };

        (status, Json(self)).into_response()
    }
}
