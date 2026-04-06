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
pub use finding::{Finding, RawFinding, ScanEvent, Severity};
pub use language::Language;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::UnboundedSender;

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

/// Run a full scan on the provided source code and stream results via a channel.
pub async fn scan_stream(config: ScanConfig, tx: UnboundedSender<ScanEvent>) -> anyhow::Result<()> {
    let raw_findings = match engine::run_stream(&config, tx.clone()).await {
        Ok(f) => f,
        Err(e) => {
            let _ = tx.send(ScanEvent::Error(e.to_string()));
            return Err(e);
        }
    };

    // If AI config is provided, enrich findings with explanations and fixes.
    if let Some(ai_config) = &config.ai_config {
        let provider = ai::create_provider(ai_config)?;
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
            let finding = raw.into_finding(explanation, fixed_code);
            let _ = tx.send(ScanEvent::Finding(Box::new(finding)));
        }
    } else {
        for raw in raw_findings {
            let finding = raw.into_finding(String::new(), String::new());
            let _ = tx.send(ScanEvent::Finding(Box::new(finding)));
        }
    }

    let _ = tx.send(ScanEvent::Complete);
    Ok(())
}

/// Run a full scan on the provided source code.
///
/// # Arguments
/// * `config` - The scan configuration including code, language, and engines.
///
/// # Returns
/// A list of [`Finding`]s, sorted by severity (critical first).
pub async fn scan(config: &ScanConfig) -> anyhow::Result<Vec<Finding>> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let config_clone = config.clone();

    // Run scan in background and collect findings
    tokio::spawn(async move {
        let _ = scan_stream(config_clone, tx).await;
    });

    let mut findings = Vec::new();
    while let Some(event) = rx.recv().await {
        match event {
            ScanEvent::Finding(f) => findings.push(*f),
            ScanEvent::Complete => break,
            ScanEvent::Error(e) => return Err(anyhow::anyhow!(e)),
            _ => {}
        }
    }

    Ok(findings)
}
