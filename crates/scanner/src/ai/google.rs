//! Google Gemini AI provider.
//!
//! Uses the Gemini `generateContent` API for vulnerability explanations and fixes.

use super::{AiProvider, build_explain_prompt, build_fix_prompt};
use crate::finding::RawFinding;
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Google Gemini API provider.
pub struct GoogleProvider {
    api_key: String,
    model: String,
    endpoint: String,
    client: reqwest::Client,
}

impl GoogleProvider {
    /// Create a new Google Gemini provider.
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
struct GenerateContentRequest {
    contents: Vec<Content>,
    #[serde(rename = "generationConfig")]
    generation_config: GenerationConfig,
}

#[derive(Serialize)]
struct Content {
    parts: Vec<Part>,
}

#[derive(Serialize)]
struct Part {
    text: String,
}

#[derive(Serialize)]
struct GenerationConfig {
    #[serde(rename = "maxOutputTokens")]
    max_output_tokens: u32,
}

#[derive(Deserialize)]
struct GenerateContentResponse {
    candidates: Option<Vec<Candidate>>,
}

#[derive(Deserialize)]
struct Candidate {
    content: CandidateContent,
}

#[derive(Deserialize)]
struct CandidateContent {
    parts: Vec<CandidatePart>,
}

#[derive(Deserialize)]
struct CandidatePart {
    text: Option<String>,
}

impl GoogleProvider {
    /// Call the Gemini generateContent API.
    async fn call(&self, prompt: &str) -> Result<String> {
        let body = GenerateContentRequest {
            contents: vec![Content {
                parts: vec![Part {
                    text: prompt.to_string(),
                }],
            }],
            generation_config: GenerationConfig {
                max_output_tokens: 1024,
            },
        };

        let url = format!(
            "{}/v1beta/models/{}:generateContent?key={}",
            self.endpoint, self.model, self.api_key
        );

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Failed to call Google Gemini API")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("Google Gemini API returned {status}: {text}");
        }

        let resp: GenerateContentResponse = response
            .json()
            .await
            .context("Failed to parse Google Gemini response")?;

        resp.candidates
            .and_then(|c| c.into_iter().next())
            .and_then(|c| c.content.parts.into_iter().next())
            .and_then(|p| p.text)
            .ok_or_else(|| anyhow::anyhow!("Google Gemini returned empty response"))
    }
}

#[async_trait]
impl AiProvider for GoogleProvider {
    async fn explain(&self, finding: &RawFinding) -> Result<String> {
        let prompt = build_explain_prompt(finding);
        self.call(&prompt).await
    }

    async fn generate_fix(&self, finding: &RawFinding) -> Result<String> {
        let prompt = build_fix_prompt(finding);
        self.call(&prompt).await
    }
}
