//! Secrets scanner — detects API keys, tokens, and credentials in code.
//!
//! Uses compiled regex patterns inspired by Gitleaks to detect hardcoded
//! secrets across all languages. Each pattern maps to a severity and
//! descriptive name for clear reporting.

use crate::engine::Engine;
use crate::finding::{RawFinding, Severity};
use crate::ScanConfig;
use anyhow::Result;
use regex::Regex;

/// A pattern for detecting a specific type of secret.
struct SecretPattern {
    /// Human-friendly name (e.g. "AWS Access Key").
    name: &'static str,
    /// Compiled regex to match against each line.
    regex: Regex,
    /// Severity of this type of secret exposure.
    severity: Severity,
    /// CWE identifier for hardcoded credentials.
    cwe_id: &'static str,
}

/// Build the list of secret detection patterns.
///
/// Each pattern is a regex that matches a specific type of secret.
/// Patterns are ordered by severity (critical first) for consistency.
fn build_patterns() -> Vec<SecretPattern> {
    vec![
        // ── Critical: cloud provider keys ──────────────────────────────────
        SecretPattern {
            name: "AWS Access Key ID",
            regex: Regex::new(r"(?i)(AKIA[0-9A-Z]{16})").expect("valid regex"),
            severity: Severity::Critical,
            cwe_id: "CWE-798",
        },
        SecretPattern {
            name: "AWS Secret Access Key",
            regex: Regex::new(r#"(?i)aws_secret_access_key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#)
                .expect("valid regex"),
            severity: Severity::Critical,
            cwe_id: "CWE-798",
        },
        // ── Critical: private keys ─────────────────────────────────────────
        SecretPattern {
            name: "Private Key",
            regex: Regex::new(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").expect("valid regex"),
            severity: Severity::Critical,
            cwe_id: "CWE-321",
        },
        // ── High: API keys and tokens ──────────────────────────────────────
        SecretPattern {
            name: "GitHub Personal Access Token",
            regex: Regex::new(r"(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})")
                .expect("valid regex"),
            severity: Severity::High,
            cwe_id: "CWE-798",
        },
        SecretPattern {
            name: "GitHub OAuth Access Token",
            regex: Regex::new(r"gho_[a-zA-Z0-9]{36}").expect("valid regex"),
            severity: Severity::High,
            cwe_id: "CWE-798",
        },
        SecretPattern {
            name: "Anthropic API Key",
            regex: Regex::new(r"sk-ant-[a-zA-Z0-9_-]{40,}").expect("valid regex"),
            severity: Severity::High,
            cwe_id: "CWE-798",
        },
        SecretPattern {
            name: "OpenAI API Key",
            regex: Regex::new(r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}").expect("valid regex"),
            severity: Severity::High,
            cwe_id: "CWE-798",
        },
        SecretPattern {
            name: "Stripe Secret Key",
            regex: Regex::new(r"(?i)(sk_live_[a-zA-Z0-9]{24,}|sk_test_[a-zA-Z0-9]{24,})").expect("valid regex"),
            severity: Severity::High,
            cwe_id: "CWE-798",
        },
        SecretPattern {
            name: "Stripe Webhook Secret",
            regex: Regex::new(r"whsec_[a-zA-Z0-9]{24,}").expect("valid regex"),
            severity: Severity::High,
            cwe_id: "CWE-798",
        },
        SecretPattern {
            name: "Slack Webhook URL",
            regex: Regex::new(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9]{8,}/B[a-zA-Z0-9]{8,}/[a-zA-Z0-9]{24}")
                .expect("valid regex"),
            severity: Severity::High,
            cwe_id: "CWE-798",
        },
        SecretPattern {
            name: "Slack Bot Token",
            regex: Regex::new(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}").expect("valid regex"),
            severity: Severity::High,
            cwe_id: "CWE-798",
        },
        SecretPattern {
            name: "Google API Key",
            regex: Regex::new(r"AIza[0-9A-Za-z_-]{35}").expect("valid regex"),
            severity: Severity::High,
            cwe_id: "CWE-798",
        },
        SecretPattern {
            name: "Twilio API Key",
            regex: Regex::new(r"SK[a-f0-9]{32}").expect("valid regex"),
            severity: Severity::Medium,
            cwe_id: "CWE-798",
        },
        // ── Medium: database and connection strings ────────────────────────
        SecretPattern {
            name: "Database Connection String",
            regex: Regex::new(r#"(?i)(postgres|mysql|mongodb(\+srv)?|redis)://[^\s'"]+:[^\s'"]+@[^\s'"]+"#)
                .expect("valid regex"),
            severity: Severity::Medium,
            cwe_id: "CWE-798",
        },
        SecretPattern {
            name: "JWT Token",
            regex: Regex::new(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}")
                .expect("valid regex"),
            severity: Severity::Medium,
            cwe_id: "CWE-798",
        },
        // ── Medium: generic patterns ───────────────────────────────────────
        SecretPattern {
            name: "Generic API Key Assignment",
            regex: Regex::new(r#"(?i)(api_key|apikey|api_secret|secret_key|access_token)\s*[=:]\s*['"][a-zA-Z0-9_\-/.]{16,}['"]"#)
                .expect("valid regex"),
            severity: Severity::Medium,
            cwe_id: "CWE-798",
        },
        SecretPattern {
            name: "Generic Password Assignment",
            regex: Regex::new(r#"(?i)(password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]"#)
                .expect("valid regex"),
            severity: Severity::Medium,
            cwe_id: "CWE-798",
        },
    ]
}

/// Run the secrets scanner against the code in `config`.
///
/// Scans each line of code against all secret patterns and returns
/// a finding for each match.
pub async fn run(config: &ScanConfig) -> Result<Vec<RawFinding>> {
    let patterns = build_patterns();
    let mut findings = Vec::new();

    for (line_num, line) in config.code.lines().enumerate() {
        let line_number = (line_num + 1) as u32;

        // Skip comment-only lines (basic heuristic).
        let trimmed = line.trim();
        if trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
        {
            // Still scan — secrets in comments are still secrets.
            // But we could add an option to skip in the future.
        }

        for pattern in &patterns {
            if pattern.regex.is_match(line) {
                // Extract the matched secret (redacted for safety).
                let matched = pattern
                    .regex
                    .find(line)
                    .map(|m| m.as_str())
                    .unwrap_or("[match]");

                // Redact all but first 4 and last 4 characters.
                let redacted = redact_secret(matched);

                findings.push(RawFinding {
                    engine: Engine::Secrets,
                    cve_id: None,
                    cwe_id: Some(pattern.cwe_id.to_string()),
                    severity: pattern.severity.clone(),
                    title: format!("Hardcoded {} detected", pattern.name),
                    vulnerable_code: line.to_string(),
                    line_start: line_number,
                    line_end: line_number,
                    file_path: config.file_path.clone(),
                });

                tracing::debug!(
                    "Secret found: {} at line {} (redacted: {})",
                    pattern.name,
                    line_number,
                    redacted
                );

                // Only report the first pattern match per line to avoid duplicates.
                break;
            }
        }
    }

    Ok(findings)
}

/// Redact a secret value, showing only the first 4 and last 4 characters.
fn redact_secret(secret: &str) -> String {
    if secret.len() <= 12 {
        return "*".repeat(secret.len());
    }
    let prefix = &secret[..4];
    let suffix = &secret[secret.len() - 4..];
    format!("{prefix}{}…{suffix}", "*".repeat(secret.len() - 8))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::language::Language;

    async fn scan_code(code: &str) -> Vec<RawFinding> {
        let config = ScanConfig {
            code: code.to_string(),
            language: Language::Unknown,
            engines: vec![Engine::Secrets],
            ai_config: None,
            file_path: None,
        };
        run(&config).await.expect("scan should succeed")
    }

    #[tokio::test]
    async fn detects_aws_access_key() {
        let findings = scan_code("const key = \"AKIAIOSFODNN7EXAMPLE\";").await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("AWS Access Key"));
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[tokio::test]
    async fn detects_github_pat() {
        let findings = scan_code("token = \"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\"").await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("GitHub Personal Access Token"));
    }

    #[tokio::test]
    async fn detects_stripe_key() {
        let findings = scan_code("STRIPE_KEY = \"SK_LIVE_000000000000000000000000\"").await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Stripe Secret Key"));
    }

    #[tokio::test]
    async fn detects_private_key() {
        let findings = scan_code("-----BEGIN RSA PRIVATE KEY-----").await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Private Key"));
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[tokio::test]
    async fn detects_generic_password() {
        let findings = scan_code(r#"password = "my_super_secret_password""#).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Password"));
    }

    #[tokio::test]
    async fn detects_database_url() {
        let findings =
            scan_code("DATABASE_URL=postgres://admin:pass123@localhost:5432/mydb").await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Database Connection String"));
    }

    #[tokio::test]
    async fn clean_code_produces_no_findings() {
        let findings = scan_code(
            "fn main() {\n    println!(\"Hello, world!\");\n}",
        )
        .await;
        assert!(findings.is_empty());
    }

    #[test]
    fn redact_works() {
        assert_eq!(redact_secret("AKIAIOSFODNN7EXAMPLE"), "AKIA************…MPLE");
        assert_eq!(redact_secret("short"), "*****");
    }
}
