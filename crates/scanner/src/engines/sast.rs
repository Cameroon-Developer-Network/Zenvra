//! SAST scanner — detects common code vulnerabilities using pattern matching.
//!
//! This engine uses regex patterns to identify insecure coding practices
//! like SQL injection, XSS, insecure cryptography, and OS command injection.

use crate::engine::Engine;
use crate::finding::{RawFinding, Severity};
use crate::ScanConfig;
use anyhow::Result;
use regex::Regex;

/// A pattern for detecting a specific security vulnerability.
struct SastRule {
    name: &'static str,
    regex: Regex,
    severity: Severity,
    cwe_id: &'static str,
    description: &'static str,
}

/// Build the list of static analysis rules.
fn build_rules() -> Vec<SastRule> {
    vec![
        // ── Insecure Cryptography ──────────────────────────────────────────
        SastRule {
            name: "Insecure Hashing Algorithm (MD5)",
            regex: Regex::new(r#"(?i)\bmd5\b\(|hashlib\.md5\(|crypto\.createHash\(['"]md5['"]\)"#).expect("valid regex"),
            severity: Severity::Medium,
            cwe_id: "CWE-327",
            description: "MD5 is a cryptographically broken hashing algorithm. Use SHA-256 or Argon2 instead.",
        },
        SastRule {
            name: "Insecure Hashing Algorithm (SHA1)",
            regex: Regex::new(r#"(?i)\bsha1\b\(|hashlib\.sha1\(|crypto\.createHash\(['"]sha1['"]\)"#).expect("valid regex"),
            severity: Severity::Low,
            cwe_id: "CWE-327",
            description: "SHA-1 is no longer considered secure against well-funded attackers. Use SHA-256 or better.",
        },
        // ── Injection Vulnerabilities ──────────────────────────────────────
        SastRule {
            name: "Potential SQL Injection (String Concatenation)",
            regex: Regex::new(r#"(?i)(SELECT|INSERT|UPDATE|DELETE|FROM).*(\+|=.*f['"]|\.format\(|\$\{).*"#).expect("valid regex"),
            severity: Severity::High,
            cwe_id: "CWE-89",
            description: "Detected string concatenation in a SQL query. Use parameterized queries or an ORM to prevent SQL injection.",
        },
        SastRule {
            name: "Potential OS Command Injection",
            regex: Regex::new(r"(?i)\bos\.(system|popen)\(|subprocess\.(run|call|Popen)\(.*\bshell\s*=\s*True\b|child_process\.exec\(").expect("valid regex"),
            severity: Severity::High,
            cwe_id: "CWE-78",
            description: "Executing OS commands with unsanitized input or via a shell can lead to command injection.",
        },
        // ── Cross-Site Scripting (XSS) ──────────────────────────────────────
        SastRule {
            name: "Insecure HTML Rendering (innerHTML)",
            regex: Regex::new(r"(?i)\.innerHTML\s*=|dangerousSetInnerHTML|\$state\.raw\(.*<").expect("valid regex"),
            severity: Severity::Medium,
            cwe_id: "CWE-79",
            description: "Directly setting innerHTML or using dangerouslySetInnerHTML bypasses sanitization and can lead to XSS.",
        },
        // ── Insecure Defaults ──────────────────────────────────────────────
        SastRule {
            name: "Hardcoded Localhost Reference",
            regex: Regex::new(r"127\.0\.0\.1|localhost").expect("valid regex"),
            severity: Severity::Info,
            cwe_id: "CWE-1188",
            description: "Hardcoded localhost references can cause issues when deploying to production.",
        },
    ]
}

/// Run the SAST scanner against the code in `config`.
pub async fn run(config: &ScanConfig) -> Result<Vec<RawFinding>> {
    let rules = build_rules();
    let mut findings = Vec::new();

    for (line_num, line) in config.code.lines().enumerate() {
        let line_number = (line_num + 1) as u32;

        for rule in &rules {
            if rule.regex.is_match(line) {
                findings.push(RawFinding {
                    engine: Engine::Sast,
                    cve_id: None,
                    cwe_id: Some(rule.cwe_id.to_string()),
                    severity: rule.severity.clone(),
                    title: rule.name.to_string(),
                    vulnerable_code: line.trim().to_string(),
                    description: Some(rule.description.to_string()),
                    line_start: line_number,
                    line_end: line_number,
                    file_path: config.file_path.clone(),
                });
            }
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::language::Language;

    async fn scan_code(code: &str) -> Vec<RawFinding> {
        let config = ScanConfig {
            code: code.to_string(),
            language: Language::Unknown,
            engines: vec![Engine::Sast],
            ai_config: None,
            file_path: None,
        };
        run(&config).await.expect("scan should succeed")
    }

    #[tokio::test]
    async fn detects_md5() {
        let findings = scan_code("let hash = crypto.createHash('md5');").await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("MD5"));
    }

    #[tokio::test]
    async fn detects_sqli() {
        let findings = scan_code(
            "cursor.execute(\"SELECT * FROM users WHERE name = '\" + user_input + \"'\")",
        )
        .await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("SQL Injection"));
    }

    #[tokio::test]
    async fn detects_command_injection() {
        let findings = scan_code("os.system(\"rm -rf \" + path)").await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("OS Command Injection"));
    }
}
