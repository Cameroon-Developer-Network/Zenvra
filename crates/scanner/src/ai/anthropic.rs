//! Anthropic (Claude) AI provider.
//!
//! Uses the Anthropic Messages API to generate explanations and fixes.

use super::{build_explain_prompt, build_fix_prompt, AiProvider};
use crate::finding::RawFinding;
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Anthropic API provider using the Messages endpoint.
pub struct AnthropicProvider {
    api_key: String,
    model: String,
    endpoint: String,
    client: reqwest::Client,
}

impl AnthropicProvider {
    /// Create a new Anthropic provider.
    pub fn new(api_key: String, model: String, endpoint: String) -> Self {
        Self {
            api_key,
            model,
            endpoint,
            client: reqwest::Client::new(),
        }
    }
}

#[derive(Serialize)]
struct MessagesRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<Message>,
}

#[derive(Serialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct MessagesResponse {
    content: Vec<ContentBlock>,
}

#[derive(Deserialize)]
struct ContentBlock {
    text: Option<String>,
}

impl AnthropicProvider {
    /// Call the Anthropic Messages API.
    async fn call(&self, prompt: &str) -> Result<String> {
        let body = MessagesRequest {
            model: self.model.clone(),
            max_tokens: 1024,
            messages: vec![Message {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
        };

        let response = self
            .client
            .post(format!("{}/v1/messages", self.endpoint))
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Failed to call Anthropic API")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Anthropic API returned {status}: {text}");
        }

        let resp: MessagesResponse = response
            .json()
            .await
            .context("Failed to parse Anthropic response")?;

        resp.content
            .first()
            .and_then(|block| block.text.clone())
            .ok_or_else(|| anyhow::anyhow!("Anthropic returned empty response"))
    }
}

#[async_trait]
impl AiProvider for AnthropicProvider {
    async fn explain(&self, finding: &RawFinding) -> Result<String> {
        let prompt = build_explain_prompt(finding);
        self.call(&prompt).await
    }

    async fn generate_fix(&self, finding: &RawFinding) -> Result<String> {
        let prompt = build_fix_prompt(finding);
        self.call(&prompt).await
    }
}
