//! Multi-provider AI system for generating vulnerability explanations and fixes.
//!
//! Supports Anthropic, OpenAI, Google Gemini, and custom OpenAI-compatible endpoints.
//! Users can bring their own API keys.

pub mod anthropic;
pub mod custom;
pub mod google;
pub mod openai;

use crate::finding::RawFinding;
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Supported AI provider types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Anthropic,
    OpenAi,
    Google,
    Custom,
}

impl std::fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderKind::Anthropic => write!(f, "Anthropic"),
            ProviderKind::OpenAi => write!(f, "OpenAI"),
            ProviderKind::Google => write!(f, "Google"),
            ProviderKind::Custom => write!(f, "Custom"),
        }
    }
}

/// Configuration for an AI provider.
///
/// Supports bring-your-own-key: users pass their API key and optionally
/// a custom endpoint URL for self-hosted or alternative providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AiConfig {
    /// Which provider to use.
    pub provider: ProviderKind,

    /// API key for the provider.
    #[serde(alias = "apiKey")]
    pub api_key: String,

    /// Model identifier (e.g. "claude-sonnet-4-20250514", "gpt-4o", "gemini-2.0-flash").
    pub model: String,

    /// Custom endpoint URL. Required for `Custom` provider, optional for others
    /// (overrides default endpoint when set).
    pub endpoint: Option<String>,
}

/// Trait for AI providers that generate vulnerability explanations and fixes.
///
/// Each provider (Anthropic, OpenAI, Google, Custom) implements this trait.
/// The trait is object-safe so we can use `Box<dyn AiProvider>`.
#[async_trait]
pub trait AiProvider: Send + Sync {
    /// Generate a plain-English explanation of a vulnerability finding.
    async fn explain(&self, finding: &RawFinding) -> Result<String>;

    /// Generate corrected code that fixes the vulnerability.
    async fn generate_fix(&self, finding: &RawFinding) -> Result<String>;
}

/// Create an AI provider from configuration.
///
/// # Errors
/// Returns an error if the config is invalid (e.g. custom provider without endpoint).
pub fn create_provider(config: &AiConfig) -> Result<std::sync::Arc<dyn AiProvider>> {
    match config.provider {
        ProviderKind::Anthropic => {
            let endpoint = config
                .endpoint
                .clone()
                .unwrap_or_else(|| "https://api.anthropic.com".to_string());
            Ok(std::sync::Arc::new(anthropic::AnthropicProvider::new(
                config.api_key.clone(),
                config.model.clone(),
                endpoint,
            )))
        }
        ProviderKind::OpenAi => {
            let endpoint = config
                .endpoint
                .clone()
                .unwrap_or_else(|| "https://api.openai.com".to_string());
            Ok(std::sync::Arc::new(openai::OpenAiProvider::new(
                config.api_key.clone(),
                config.model.clone(),
                endpoint,
            )))
        }
        ProviderKind::Google => {
            let endpoint = config
                .endpoint
                .clone()
                .unwrap_or_else(|| "https://generativelanguage.googleapis.com".to_string());
            Ok(std::sync::Arc::new(google::GoogleProvider::new(
                config.api_key.clone(),
                config.model.clone(),
                endpoint,
            )))
        }
        ProviderKind::Custom => {
            let endpoint = config
                .endpoint
                .clone()
                .ok_or_else(|| anyhow::anyhow!("Custom provider requires an endpoint URL"))?;
            Ok(std::sync::Arc::new(custom::CustomProvider::new(
                config.api_key.clone(),
                config.model.clone(),
                endpoint,
            )))
        }
    }
}

/// List available models for a given provider and API key.
///
/// This provides the "sophisticated" dynamic loading requested by the user.
pub async fn list_models(
    provider: ProviderKind,
    api_key: &str,
    endpoint: Option<&str>,
) -> Result<Vec<String>> {
    match provider {
        ProviderKind::Anthropic => anthropic::list_models(api_key, endpoint).await,
        ProviderKind::OpenAi => openai::list_models(api_key, endpoint).await,
        ProviderKind::Google => google::list_models(api_key, endpoint).await,
        ProviderKind::Custom => {
            let ep =
                endpoint.ok_or_else(|| anyhow::anyhow!("Custom provider requires an endpoint"))?;
            openai::list_models(api_key, Some(ep)).await
        }
    }
}

/// Build the system prompt used across all AI providers.
pub(crate) fn build_explain_prompt(finding: &RawFinding) -> String {
    format!(
        "You are a security expert explaining vulnerabilities to developers who may not have security experience.\n\n\
         Analyze this security finding and explain it in plain English:\n\n\
         **Title:** {title}\n\
         **Severity:** {severity}\n\
         {cve}\
         {cwe}\
         **Vulnerable code:**\n```\n{code}\n```\n\n\
         Explain:\n\
         1. What the vulnerability is\n\
         2. Why it's dangerous (real-world impact)\n\
         3. How an attacker could exploit it\n\n\
         Keep it under 200 words. No jargon. Speak to a developer who built this with an AI tool and has no security background.",
        title = finding.title,
        severity = finding.severity,
        cve = finding
            .cve_id
            .as_ref()
            .map(|id| format!("**CVE:** {id}\n"))
            .unwrap_or_default(),
        cwe = finding
            .cwe_id
            .as_ref()
            .map(|id| format!("**CWE:** {id}\n"))
            .unwrap_or_default(),
        code = finding.vulnerable_code,
    )
}

/// Build the prompt for generating a fix.
pub(crate) fn build_fix_prompt(finding: &RawFinding) -> String {
    format!(
        "You are a security expert. Fix this vulnerable code.\n\n\
         **Title:** {title}\n\
         **Vulnerable code:**\n```\n{code}\n```\n\n\
         Return ONLY the corrected code. No explanation, no markdown fences, just the fixed code.",
        title = finding.title,
        code = finding.vulnerable_code,
    )
}
