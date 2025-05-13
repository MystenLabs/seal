// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize, PartialEq)]
pub enum InternalError {
    InvalidPTB(String),
    InvalidPackage,
    NoAccess,
    OldPackageVersion,
    InvalidSignature,
    InvalidSessionSignature,
    InvalidCertificate,
    InvalidSDKVersion,
    DeprecatedSDKVersion,
    MissingRequiredHeader(String),
    InvalidParameter,
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
            InternalError::InvalidPTB(ref inner) => {
                (StatusCode::FORBIDDEN, format!("Invalid PTB: {}", inner))
            }
            InternalError::InvalidPackage => {
                (StatusCode::FORBIDDEN, "Invalid package ID".to_string())
            }
            InternalError::NoAccess => (StatusCode::FORBIDDEN, "Access denied".to_string()),
            InternalError::InvalidCertificate => (
                StatusCode::FORBIDDEN,
                "Invalid certificate time or ttl".to_string(),
            ),
            InternalError::OldPackageVersion => (
                StatusCode::FORBIDDEN,
                "Package has been upgraded, please use the latest version".to_string(),
            ),
            InternalError::InvalidSignature => {
                (StatusCode::FORBIDDEN, "Invalid user signature".to_string())
            }
            InternalError::InvalidSDKVersion => {
                (StatusCode::BAD_REQUEST, "Invalid SDK version".to_string())
            }
            InternalError::DeprecatedSDKVersion => (
                StatusCode::UPGRADE_REQUIRED,
                "Deprecated SDK version".to_string(),
            ),
            InternalError::MissingRequiredHeader(ref inner) => (
                StatusCode::BAD_REQUEST,
                format!("Missing required header: {}", inner).to_string(),
            ),
            InternalError::InvalidSessionSignature => (
                StatusCode::FORBIDDEN,
                "Invalid session key signature".to_string(),
            ),
            InternalError::InvalidParameter => (
                StatusCode::FORBIDDEN,
                "Invalid parameter. If the object was just created, try again later.".to_string(),
            ),
            InternalError::Failure => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Internal server error, please try again later".to_string(),
            ),
        };

        let error_response = ErrorResponse {
            error: self,
            message,
        };

        (status, Json(error_response)).into_response()
    }
}

impl InternalError {
    pub fn as_str(&self) -> &'static str {
        match self {
            InternalError::InvalidPTB(_) => "InvalidPTB",
            InternalError::InvalidPackage => "InvalidPackage",
            InternalError::NoAccess => "NoAccess",
            InternalError::InvalidCertificate => "InvalidCertificate",
            InternalError::OldPackageVersion => "OldPackageVersion",
            InternalError::InvalidSignature => "InvalidSignature",
            InternalError::InvalidSessionSignature => "InvalidSessionSignature",
            InternalError::InvalidSDKVersion => "InvalidSDKVersion",
            InternalError::DeprecatedSDKVersion => "DeprecatedSDKVersion",
            InternalError::MissingRequiredHeader(_) => "MissingRequiredHeader",
            InternalError::InvalidParameter => "InvalidParameter",
            InternalError::Failure => "Failure",
        }
    }
}

#[macro_export]
macro_rules! return_err {
    ($err:expr, $msg:expr $(, $arg:expr)*) => {{
        debug!($msg $(, $arg)*);
        return Err($err);
    }};
}
