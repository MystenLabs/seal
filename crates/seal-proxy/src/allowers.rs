use crate::{BearerToken, Allower};
use std::collections::HashSet;
use crate::config::{load, BearerTokenConfig};
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct BearerTokenProvider {
    bearer_tokens: HashSet<BearerToken>,
}

impl BearerTokenProvider {
    pub fn new(bearer_token_config_path: Option<String>) -> Result<Option<Self>> {
        if bearer_token_config_path.is_none() {
            return Ok(None);
        }

        let bearer_token_config: BearerTokenConfig = load(bearer_token_config_path.unwrap())?;
        Ok(Some(Self { bearer_tokens: bearer_token_config.items.iter().map(|item| item.bearer_token.clone()).collect() }))
    }
}

impl Allower<BearerToken> for BearerTokenProvider {
    fn allowed(&self, key: &BearerToken) -> bool {
        self.bearer_tokens.contains(key)
    }
}