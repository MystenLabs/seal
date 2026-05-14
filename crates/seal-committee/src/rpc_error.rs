// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Result type for Sui gRPC operations.
pub type RpcResult<T> = Result<T, RpcError>;

/// Error type for Sui gRPC operations.
///
/// `code` is populated only for errors returned by tonic. Local post-processing
/// failures (missing BCS, decode errors, unexpected object shape) are
/// deterministic and keep `code` empty.
#[derive(Debug)]
pub struct RpcError {
    pub message: String,
    pub code: Option<tonic::Code>,
}

impl RpcError {
    /// Build from a gRPC status; produces `code: Some(...)`.
    pub fn from_grpc(status: tonic::Status) -> Self {
        Self {
            message: status.message().to_string(),
            code: Some(status.code()),
        }
    }

    /// Build a local post-processing failure; produces `code: None`.
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
            code: None,
        }
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.code {
            Some(code) => write!(f, "gRPC {code}: {}", self.message),
            None => write!(f, "{}", self.message),
        }
    }
}

impl std::error::Error for RpcError {}
