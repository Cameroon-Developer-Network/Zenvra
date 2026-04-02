//! Zenvra Scanner — core vulnerability detection engine.
//!
//! This crate exposes the primary scanning API used by the CLI, web API,
//! and VS Code extension. It orchestrates SAST, SCA, and secrets detection.

pub mod engine;
pub mod finding;
pub mod language;

pub use finding::{Finding, Severity};
pub use language::Language;

/// Run a full scan on the provided source code.
///
/// # Arguments
/// * `code` - The source code to scan
/// * `language` - Programming language of the code
/// * `engines` - Which scan engines to run
///
/// # Returns
/// A list of [`Finding`]s, sorted by severity (critical first).
pub async fn scan(
    code: &str,
    language: Language,
    engines: &[Engine],
) -> anyhow::Result<Vec<Finding>> {
    engine::run(code, language, engines).await
}

/// Scan engines available in Zenvra.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
