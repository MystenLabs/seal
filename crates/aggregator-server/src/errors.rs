// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use axum::http::StatusCode;
use seal_committee::ErrorResponse;

#[derive(Debug)]
pub enum InternalError {
    RequestFailed(String),               // Network request to member failed
    HttpError(StatusCode),               // HTTP error from member
    ParseFailed(String),                 // Failed to parse response
    VerificationFailed(String),          // Decryption key verification failed
    InsufficientResponses(usize, usize), // (got, need)
    AggregationFailed(String),           // Aggregation error
}

impl From<InternalError> for ErrorResponse {
    fn from(err: InternalError) -> ErrorResponse {
        let message = match err {
            InternalError::RequestFailed(ref e) => format!("Request failed: {e}"),
            InternalError::HttpError(status) => format!("HTTP {status}"),
            InternalError::ParseFailed(ref e) => format!("Parse failed: {e}"),
            InternalError::VerificationFailed(ref e) => format!("Verification failed: {e}"),
            InternalError::InsufficientResponses(got, need) => {
                format!("Insufficient responses: got {got}, need {need}")
            }
            InternalError::AggregationFailed(ref e) => format!("Aggregation failed: {e}"),
        };

        ErrorResponse {
            error: "Aggregator failure".to_string(),
            message,
        }
    }
}
