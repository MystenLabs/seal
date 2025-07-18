use crate::{BearerToken, Allower};
use std::collections::HashMap;
use crate::config::{load, BearerTokenConfig};
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct BearerTokenProvider {
    bearer_tokens: HashMap<BearerToken, String>,
}

impl BearerTokenProvider {
    pub fn new(bearer_token_config_path: Option<String>) -> Result<Option<Self>> {
        if bearer_token_config_path.is_none() {
            return Ok(None);
        }

        let bearer_token_config: BearerTokenConfig = load(bearer_token_config_path.unwrap())?;
        Ok(Some(Self { bearer_tokens: bearer_token_config.iter().map(|item| {
            tracing::info!("bearer token loaded for: {:?}", item.name);
            (item.token.clone(), item.name.clone())
        }).collect() }))
    }
}

impl Allower<BearerToken> for BearerTokenProvider {
    fn allowed(&self, token: &BearerToken) -> bool {
        if let Some(name) = self.bearer_tokens.get(token) {
            tracing::info!("Accepted Request from: {:?}", name);
            true
        } else {
            tracing::info!("Rejected Bearer Token: {:?}", token);
            false
        }
    }
}