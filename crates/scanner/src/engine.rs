//! Scan engine orchestrator — runs all requested engines and merges results.

use crate::{ScanConfig, finding::RawFinding};
use serde::{Deserialize, Serialize};

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

/// Run all requested scan engines and merge results.
///
/// Engines run sequentially for now; will be parallelised with `tokio::join!`
/// once individual engines are mature enough.
pub async fn run(config: &ScanConfig) -> anyhow::Result<Vec<RawFinding>> {
    let mut findings = Vec::new();

    for engine in &config.engines {
        let mut results = match engine {
            Engine::Sast => crate::engines::sast::run(config).await?,
            Engine::Sca => crate::engines::sca::run(config).await?,
            Engine::Secrets => crate::engines::secrets::run(config).await?,
            Engine::AiCode => crate::engines::ai_code::run(config).await?,
        };
        findings.append(&mut results);
    }

    // Sort by severity descending (critical first).
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    Ok(findings)
}
