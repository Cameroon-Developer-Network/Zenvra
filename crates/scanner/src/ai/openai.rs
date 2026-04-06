//! OpenAI-compatible AI provider.
//!
//! Works with OpenAI, Groq, Together, and any OpenAI-compatible API.
//! Users can override the endpoint to point at alternative providers.

use super::{build_explain_prompt, build_fix_prompt, AiProvider};
use crate::finding::RawFinding;
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// OpenAI-compatible API provider.
///
/// Works with native OpenAI and any API that implements the
/// Chat Completions endpoint (Groq, Together, Fireworks, etc.).
pub struct OpenAiProvider {
    api_key: String,
    model: String,
    endpoint: String,
    client: reqwest::Client,
}

impl OpenAiProvider {
    /// Create a new OpenAI-compatible provider.
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

#[derive(Deserialize)]
struct ModelsResponse {
    data: Vec<ModelData>,
}

#[derive(Deserialize)]
struct ModelData {
    id: String,
}

/// List available models from an OpenAI-compatible API.
pub async fn list_models(api_key: &str, endpoint: Option<&str>) -> Result<Vec<String>> {
    let client = reqwest::Client::new();
    let ep = endpoint
        .unwrap_or("https://api.openai.com")
        .trim_end_matches('/');

    let url = if ep.ends_with("/v1") {
        format!("{}/models", ep)
    } else {
        format!("{}/v1/models", ep)
    };

    let response = client
        .get(url)
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .context("Failed to connect to OpenAI-compatible model list")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("OpenAI API returned {status}: {body}");
    }

    let resp: ModelsResponse = response
        .json()
        .await
        .context("Failed to parse model list")?;
    let mut models: Vec<String> = resp.data.into_iter().map(|m| m.id).collect();
    models.sort();
    Ok(models)
}

impl OpenAiProvider {
    /// Call the OpenAI-compatible Chat Completions API.
    async fn call(&self, prompt: &str) -> Result<String> {
        let body = ChatCompletionRequest {
            model: self.model.clone(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            max_tokens: 1024,
        };

        let ep = self.endpoint.trim_end_matches('/');
        let url = if ep.ends_with("/v1") {
            format!("{}/chat/completions", ep)
        } else {
            format!("{}/v1/chat/completions", ep)
        };

        let response = self
            .client
            .post(url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Failed to call OpenAI API")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("OpenAI API returned {status}: {text}");
        }

        let resp: ChatCompletionResponse = response
            .json()
            .await
            .context("Failed to parse OpenAI response")?;

        resp.choices
            .first()
            .and_then(|c| c.message.content.clone())
            .ok_or_else(|| anyhow::anyhow!("OpenAI returned empty response"))
    }
}

#[async_trait]
impl AiProvider for OpenAiProvider {
    async fn explain(&self, finding: &RawFinding) -> Result<String> {
        let prompt = build_explain_prompt(finding);
        self.call(&prompt).await
    }

    async fn generate_fix(&self, finding: &RawFinding) -> Result<String> {
        let prompt = build_fix_prompt(finding);
        self.call(&prompt).await
    }
}
