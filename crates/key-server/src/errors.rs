// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize, PartialEq)]
pub enum InternalError {
    InvalidPTB,
    InvalidPackage,
    NoAccess,
    OldPackageVersion,
    InvalidSignature,
    InvalidSessionSignature,
    InvalidCertificate,
    InvalidSDKVersion,
    DeprecatedSDKVersion,
    Failure, // Internal error, try again later
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    error: InternalError,
    message: String,
}

impl IntoResponse for InternalError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            InternalError::InvalidPTB => (StatusCode::FORBIDDEN, "Invalid PTB"),
            InternalError::InvalidPackage => (StatusCode::FORBIDDEN, "Invalid package ID"),
            InternalError::NoAccess => (StatusCode::FORBIDDEN, "Access denied"),
            InternalError::InvalidCertificate => {
                (StatusCode::FORBIDDEN, "Invalid certificate time or ttl")
            }
            InternalError::OldPackageVersion => (
                StatusCode::FORBIDDEN,
                "Package has been upgraded, please use the latest version",
            ),
            InternalError::InvalidSignature => (StatusCode::FORBIDDEN, "Invalid user signature"),
            InternalError::InvalidSessionSignature => {
                (StatusCode::FORBIDDEN, "Invalid session key signature")
            }
            InternalError::InvalidSDKVersion => (StatusCode::FORBIDDEN, "Invalid SDK version"),
            InternalError::DeprecatedSDKVersion => {
                (StatusCode::FORBIDDEN, "Deprecated SDK version")
            }
            InternalError::Failure => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Internal server error, please try again later",
            ),
        };

        let error_response = ErrorResponse {
            error: self,
            message: message.to_string(),
        };

        (status, Json(error_response)).into_response()
    }
}

impl InternalError {
    pub fn as_str(&self) -> &'static str {
        match self {
            InternalError::InvalidPTB => "InvalidPTB",
            InternalError::InvalidPackage => "InvalidPackage",
            InternalError::NoAccess => "NoAccess",
            InternalError::InvalidCertificate => "InvalidCertificate",
            InternalError::OldPackageVersion => "OldPackageVersion",
            InternalError::InvalidSignature => "InvalidSignature",
            InternalError::InvalidSessionSignature => "InvalidSessionSignature",
            InternalError::InvalidSDKVersion => "InvalidSDKVersion",
            InternalError::DeprecatedSDKVersion => "DeprecatedSDKVersion",
            InternalError::Failure => "Failure",
        }
    }
}
