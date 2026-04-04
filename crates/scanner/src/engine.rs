use crate::{finding::{RawFinding, ScanEvent}, ScanConfig};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::UnboundedSender;

/// Scan engines available in Zenvra.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Engine {
    /// Static Application Security Testing — analyses source code patterns.
    Sast,
    /// Software Composition Analysis — checks dependency vulnerabilities.
    Sca,
    /// Detects hardcoded secrets, API keys, and credentials.
    Secrets,
    /// Patterns specific to AI/vibe-generated code.
    AiCode,
}

impl std::fmt::Display for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Engine::Sast => write!(f, "SAST"),
            Engine::Sca => write!(f, "SCA"),
            Engine::Secrets => write!(f, "Secrets"),
            Engine::AiCode => write!(f, "AI Code"),
        }
    }
}

/// Run all requested scan engines and stream results.
pub async fn run_stream(
    config: &ScanConfig,
    tx: UnboundedSender<ScanEvent>,
) -> anyhow::Result<Vec<RawFinding>> {
    let mut all_findings = Vec::new();
    let total_engines = config.engines.len();

    for (i, engine) in config.engines.iter().enumerate() {
        let progress = ((i as f32 / total_engines as f32) * 100.0) as u8;
        let _ = tx.send(ScanEvent::Progress {
            percentage: progress,
            message: format!("Running {} engine...", engine),
        });

        let mut results = match engine {
            Engine::Sast => crate::engines::sast::run(config).await?,
            Engine::Sca => crate::engines::sca::run(config).await?,
            Engine::Secrets => crate::engines::secrets::run(config).await?,
            Engine::AiCode => crate::engines::ai_code::run(config).await?,
        };

        all_findings.append(&mut results);
    }

    let _ = tx.send(ScanEvent::Progress {
        percentage: 100,
        message: "Scanning complete. Preparing results...".to_string(),
    });

    // Sort by severity descending (critical first).
    all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    Ok(all_findings)
}

/// Run all requested scan engines and merge results (synchronous wrapper).
pub async fn run(config: &ScanConfig) -> anyhow::Result<Vec<RawFinding>> {
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    run_stream(config, tx).await
}
