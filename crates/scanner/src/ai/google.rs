//! Google Gemini AI provider.
//!
//! Uses the Gemini `generateContent` API for vulnerability explanations and fixes.

use super::{build_explain_prompt, build_fix_prompt, AiProvider};
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

#[derive(Deserialize)]
struct ListModelsResponse {
    models: Vec<ModelInfo>,
}

#[derive(Deserialize)]
struct ModelInfo {
    name: String,
}

/// List available models from the Google Gemini API.
pub async fn list_models(api_key: &str, endpoint: Option<&str>) -> Result<Vec<String>> {
    let client = reqwest::Client::new();
    let ep = endpoint.unwrap_or("https://generativelanguage.googleapis.com");

    let url = format!("{}/v1beta/models?key={}", ep, api_key);

    let response = client
        .get(&url)
        .send()
        .await
        .context("Failed to connect to Google Gemini model list")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Google Gemini API returned {status}: {body}");
    }

    let resp: ListModelsResponse = response
        .json()
        .await
        .context("Failed to parse model list")?;

    // Google returns names as "models/gemini-1.5-pro". Strip the prefix.
    let mut models: Vec<String> = resp
        .models
        .into_iter()
        .map(|m| m.name.replace("models/", ""))
        .collect();
    models.sort();
    Ok(models)
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
