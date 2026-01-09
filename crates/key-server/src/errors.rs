// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, PartialEq, Clone)]
pub enum InternalError {
    InvalidPTB(String),
    InvalidPackage,
    NoAccess(String),
    InvalidSignature,
    InvalidSessionSignature,
    InvalidCertificate,
    InvalidSDKVersion,
    DeprecatedSDKVersion,
    MissingRequiredHeader(String),
    InvalidParameter(String),
    InvalidMVRName,
    InvalidServiceId,
    UnsupportedPackageId,
    Failure(String), // Internal error, try again later. Debug message is for logging only.
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

impl IntoResponse for InternalError {
    fn into_response(self) -> Response {
        ErrorResponse::from(self).into_response()
    }
}

impl InternalError {
    pub fn as_str(&self) -> &'static str {
        match self {
            InternalError::InvalidPTB(_) => "InvalidPTB",
            InternalError::InvalidPackage => "InvalidPackage",
            InternalError::NoAccess(_) => "NoAccess",
            InternalError::InvalidCertificate => "InvalidCertificate",
            InternalError::InvalidSignature => "InvalidSignature",
            InternalError::InvalidSessionSignature => "InvalidSessionSignature",
            InternalError::InvalidSDKVersion => "InvalidSDKVersion",
            InternalError::DeprecatedSDKVersion => "DeprecatedSDKVersion",
            InternalError::MissingRequiredHeader(_) => "MissingRequiredHeader",
            InternalError::InvalidParameter(_) => "InvalidParameter",
            InternalError::InvalidMVRName => "InvalidMVRName",
            InternalError::InvalidServiceId => "InvalidServiceId",
            InternalError::UnsupportedPackageId => "UnsupportedPackageId",
            InternalError::Failure(_) => "Failure",
        }
    }
}

impl From<InternalError> for ErrorResponse {
    fn from(err: InternalError) -> ErrorResponse {
        let message = match err {
            InternalError::InvalidPTB(ref inner) => format!("Invalid PTB: {inner}"),
            InternalError::InvalidPackage => "Invalid package ID".to_string(),
            InternalError::NoAccess(ref inner) => format!("Access denied: {inner}"),
            InternalError::InvalidCertificate => "Invalid certificate time or ttl".to_string(),
            InternalError::InvalidSignature => "Invalid user signature".to_string(),
            InternalError::InvalidSDKVersion => "Invalid SDK version".to_string(),
            InternalError::DeprecatedSDKVersion => "Deprecated SDK version".to_string(),
            InternalError::MissingRequiredHeader(ref inner) => {
                format!("Missing required header: {inner}")
            }
            InternalError::InvalidSessionSignature => "Invalid session key signature".to_string(),
            InternalError::InvalidParameter(ref inner) => {
                format!("Invalid parameter to PTB: {inner}")
            }
            InternalError::InvalidMVRName => "Invalid MVR name".to_string(),
            InternalError::InvalidServiceId => "Invalid service ID".to_string(),
            InternalError::UnsupportedPackageId => "Unsupported package ID".to_string(),
            InternalError::Failure(_) => {
                "Internal server error, please try again later".to_string()
            }
        };

        ErrorResponse {
            error: err.as_str().to_string(),
            message,
        }
    }
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

#[macro_export]
macro_rules! return_err {
    ($err:expr, $msg:expr $(, $arg:expr)*) => {{
        debug!($msg $(, $arg)*);
        return Err($err);
    }};
}
