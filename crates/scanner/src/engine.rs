//! Scan engine orchestrator — runs all requested engines in parallel.

use crate::{Engine, finding::Finding, language::Language};

/// Run all requested scan engines concurrently and merge results.
pub async fn run(
    code: &str,
    language: Language,
    engines: &[Engine],
) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // TODO: Run engines concurrently with tokio::join! in future iterations.
    // For now, sequential to keep the skeleton simple and testable.
    for engine in engines {
        let mut results = match engine {
            Engine::Sast => sast::scan(code, &language).await?,
            Engine::Sca => sca::scan(code, &language).await?,
            Engine::Secrets => secrets::scan(code).await?,
            Engine::AiCode => ai_code::scan(code, &language).await?,
        };
        findings.append(&mut results);
    }

    // Sort by severity descending (critical first)
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    Ok(findings)
}

// Engine sub-modules — each will grow into its own file as we implement them.
mod sast {
    use crate::{finding::Finding, language::Language};

    pub async fn scan(_code: &str, _language: &Language) -> anyhow::Result<Vec<Finding>> {
        // TODO: Implement Semgrep subprocess call
        Ok(vec![])
    }
}

mod sca {
    use crate::{finding::Finding, language::Language};

    pub async fn scan(_code: &str, _language: &Language) -> anyhow::Result<Vec<Finding>> {
        // TODO: Parse dependency files and query OSV API
        Ok(vec![])
    }
}

mod secrets {
    use crate::finding::Finding;

    pub async fn scan(_code: &str) -> anyhow::Result<Vec<Finding>> {
        // TODO: Implement Gitleaks regex patterns
        Ok(vec![])
    }
}

mod ai_code {
    use crate::{finding::Finding, language::Language};

    pub async fn scan(_code: &str, _language: &Language) -> anyhow::Result<Vec<Finding>> {
        // TODO: AI-code specific pattern detection
        Ok(vec![])
    }
}
