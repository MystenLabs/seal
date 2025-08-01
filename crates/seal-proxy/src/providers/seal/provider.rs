// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::config::{load, BearerTokenConfig};
use crate::{Allower, BearerToken};
use anyhow::Result;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct BearerTokenProvider {
    bearer_tokens: HashMap<BearerToken, String>,
}

impl BearerTokenProvider {
    pub fn new(bearer_token_config_path: String) -> Result<Self> {
        let bearer_token_config: BearerTokenConfig = load(bearer_token_config_path)?;
        Ok(Self {
            bearer_tokens: bearer_token_config
                .iter()
                .map(|item| {
                    tracing::info!("bearer token loaded for: {:?}", item.name);
                    (item.token.clone(), item.name.clone())
                })
                .collect(),
        })
    }

    pub fn get_bearer_token_owner_name(&self, token: &str) -> Option<String> {
        self.bearer_tokens.get(token).cloned()
    }
}

impl Allower<BearerToken> for BearerTokenProvider {
    fn allowed(&self, token: &String) -> (bool, String) {
        if let Some(name) = self.bearer_tokens.get(token) {
            tracing::info!("Accepted Request from: {:?}", name);
            (true, name.clone())
        } else {
            tracing::info!("Rejected Bearer Token: {:?}", token);
            (false, "".to_string())
        }
    }
}
