use axum::{
    extract::Request,
    http::{header},
    Extension,
    body::Body,
    response::Response,
    http::StatusCode,
    middleware::Next,
};
use std::sync::Arc;
use crate::allowers::BearerTokenProvider;
use crate::Allower;

/// we expect that calling seal nodes have known bearer tokens
pub async fn expect_valid_bearer_token(
    Extension(allower): Extension<Arc<BearerTokenProvider>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, &'static str)> {
    // tracing::info!("in fn expect_valid_bearer_token");
    // Extract the Authorization header
    if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
        tracing::info!("auth_header: {:?}", auth_header);
        if let Ok(auth_str) = auth_header.to_str() {
            // Check if it's a Bearer token
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                // Validate the token
                if allower.allowed(&token.to_string()) {
                    return Ok(next.run(req).await);
                } else {
                    tracing::info!("invalid token, rejecting request");
                    return Err((StatusCode::UNAUTHORIZED, "Unauthorized"));
                }
            }
        }
    }

    tracing::info!("no auth header found, rejecting request");
    // Reject the request if no valid token
    Err((StatusCode::UNAUTHORIZED, "Unauthorized"))
}