//! Custom AI provider — user-configured endpoint.
//!
//! Assumes an OpenAI-compatible API format, which is the most common
//! protocol for self-hosted models (Ollama, vLLM, LiteLLM, etc.).

use super::{AiProvider, build_explain_prompt, build_fix_prompt};
use crate::finding::RawFinding;
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Custom AI provider for user-configured endpoints.
///
/// Sends requests in OpenAI Chat Completions format to whatever
/// endpoint the user specifies. Works with Ollama, vLLM, LiteLLM,
/// and any OpenAI-compatible API.
pub struct CustomProvider {
    api_key: String,
    model: String,
    endpoint: String,
    client: reqwest::Client,
}

impl CustomProvider {
    /// Create a new custom provider.
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
struct ChatCompletionRequest {
    model: String,
    messages: Vec<ChatMessage>,
    max_tokens: u32,
}

#[derive(Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Deserialize)]
struct ResponseMessage {
    content: Option<String>,
}

impl CustomProvider {
    /// Call the custom OpenAI-compatible endpoint.
    async fn call(&self, prompt: &str) -> Result<String> {
        let body = ChatCompletionRequest {
            model: self.model.clone(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            max_tokens: 1024,
        };

        // The endpoint should be the base URL; we append /v1/chat/completions.
        // If the user already includes /v1/ in their endpoint, strip trailing slashes.
        let base = self.endpoint.trim_end_matches('/');
        let url = if base.ends_with("/v1") || base.ends_with("/v1/chat/completions") {
            // User already specified a complete path.
            if base.ends_with("/v1/chat/completions") {
                base.to_string()
            } else {
                format!("{base}/chat/completions")
            }
        } else {
            format!("{base}/v1/chat/completions")
        };

        let mut req = self
            .client
            .post(&url)
            .header("Content-Type", "application/json");

        // Only add auth header if api_key is non-empty.
        if !self.api_key.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", self.api_key));
        }

        let response = req
            .json(&body)
            .send()
            .await
            .context("Failed to call custom AI endpoint")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Custom AI endpoint returned {status}: {text}");
        }

        let resp: ChatCompletionResponse = response
            .json()
            .await
            .context("Failed to parse custom AI response")?;

        resp.choices
            .first()
            .and_then(|c| c.message.content.clone())
            .ok_or_else(|| anyhow::anyhow!("Custom AI endpoint returned empty response"))
    }
}

#[async_trait]
impl AiProvider for CustomProvider {
    async fn explain(&self, finding: &RawFinding) -> Result<String> {
        let prompt = build_explain_prompt(finding);
        self.call(&prompt).await
    }

    async fn generate_fix(&self, finding: &RawFinding) -> Result<String> {
        let prompt = build_fix_prompt(finding);
        self.call(&prompt).await
    }
}
