//! Zenvra Scanner — core vulnerability detection engine.
//!
//! This crate exposes the primary scanning API used by the CLI, web API,
//! and VS Code extension. It orchestrates SAST, SCA, and secrets detection,
//! and supports multiple AI providers for generating explanations and fixes.

pub mod ai;
pub mod engine;
pub mod engines;
pub mod finding;
pub mod language;

pub use engine::Engine;
pub use finding::{Finding, RawFinding, Severity};
pub use language::Language;

use serde::{Deserialize, Serialize};

/// Configuration for a scan run.
///
/// Holds the source code, detected language, which engines to run,
/// and optional AI provider config for generating explanations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// The source code to scan.
    pub code: String,

    /// Programming language of the code.
    pub language: Language,

    /// Which scan engines to run (e.g. SAST, SCA, Secrets).
    pub engines: Vec<Engine>,

    /// Optional AI provider configuration for explanations and fixes.
    pub ai_config: Option<ai::AiConfig>,

    /// Optional file path for context in findings.
    pub file_path: Option<String>,
}

/// Run a full scan on the provided source code.
///
/// # Arguments
/// * `config` - The scan configuration including code, language, and engines.
///
/// # Returns
/// A list of [`Finding`]s, sorted by severity (critical first).
pub async fn scan(config: &ScanConfig) -> anyhow::Result<Vec<Finding>> {
    let raw_findings = engine::run(config).await?;

    // If AI config is provided, enrich findings with explanations and fixes.
    // Otherwise, return raw findings converted to Finding without AI enrichment.
    let findings = if let Some(ai_config) = &config.ai_config {
        let provider = ai::create_provider(ai_config)?;
        let mut enriched = Vec::with_capacity(raw_findings.len());
        for raw in raw_findings {
            let explanation = match provider.explain(&raw).await {
                Ok(exp) => exp,
                Err(e) => {
                    tracing::warn!("AI explain failed for {}: {}", raw.title, e);
                    String::from("AI explanation unavailable.")
                }
            };
            let fixed_code = match provider.generate_fix(&raw).await {
                Ok(fix) => fix,
                Err(e) => {
                    tracing::warn!("AI fix generation failed for {}: {}", raw.title, e);
                    String::new()
                }
            };
            enriched.push(raw.into_finding(explanation, fixed_code));
        }
        enriched
    } else {
        raw_findings
            .into_iter()
            .map(|r| r.into_finding(String::new(), String::new()))
            .collect()
    };

    Ok(findings)
}
