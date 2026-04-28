//! AI code engine — patterns specific to AI/vibe-generated code.
//!
//! Detects common anti-patterns introduced by AI code generators such as
//! hardcoded numeric IDs, missing pagination, insecure defaults, missing
//! authentication guards, and dangerous dynamic evaluation.

use crate::engine::Engine;
use crate::finding::{RawFinding, Severity};
use crate::ScanConfig;
use anyhow::Result;
use regex::Regex;
use std::sync::OnceLock;

static HARDCODED_ID_REGEX: OnceLock<Regex> = OnceLock::new();
static MISSING_PAGINATION_REGEX: OnceLock<Regex> = OnceLock::new();
static DEBUG_TRUE_REGEX: OnceLock<Regex> = OnceLock::new();
static OPEN_CORS_REGEX: OnceLock<Regex> = OnceLock::new();
static VERIFY_FALSE_REGEX: OnceLock<Regex> = OnceLock::new();
static HARDCODED_PORT_REGEX: OnceLock<Regex> = OnceLock::new();
static EXEC_REGEX: OnceLock<Regex> = OnceLock::new();
static NO_AUTH_ROUTE_REGEX: OnceLock<Regex> = OnceLock::new();
static CONSOLE_LOG_SENSITIVE_REGEX: OnceLock<Regex> = OnceLock::new();
static TODOS_SECURITY_REGEX: OnceLock<Regex> = OnceLock::new();
static PLAIN_HTTP_REGEX: OnceLock<Regex> = OnceLock::new();
static ADMIN_DEFAULT_REGEX: OnceLock<Regex> = OnceLock::new();

/// A pattern for detecting AI-generated code anti-patterns.
struct AiCodeRule {
    name: &'static str,
    regex: Regex,
    severity: Severity,
    cwe_id: &'static str,
    description: &'static str,
}

/// Build the list of AI-code-specific detection rules.
fn build_rules() -> Vec<AiCodeRule> {
    vec![
        // ── Hardcoded values ───────────────────────────────────────────────
        AiCodeRule {
            name: "Hardcoded Numeric User/Object ID",
            regex: HARDCODED_ID_REGEX.get_or_init(|| {
                Regex::new(r"(?i)(user_id|userId|account_id|accountId|object_id|objectId)\s*[=:]\s*[0-9]+\b")
                    .unwrap()
            })
            .clone(),
            severity: Severity::Medium,
            cwe_id: "CWE-798",
            description: "AI generators often insert hardcoded numeric IDs as placeholders. \
                           These bypass access controls and expose arbitrary data.",
        },
        AiCodeRule {
            name: "Hardcoded Admin Credentials",
            regex: ADMIN_DEFAULT_REGEX.get_or_init(|| {
                Regex::new(r#"(?i)(username|user)\s*[=:]\s*['"]admin['"]"#).unwrap()
            })
            .clone(),
            severity: Severity::High,
            cwe_id: "CWE-798",
            description: "Default admin credentials are a top target for attackers. \
                           Credentials must come from environment variables or a secrets manager.",
        },
        // ── Insecure defaults ──────────────────────────────────────────────
        AiCodeRule {
            name: "Debug Mode Enabled",
            regex: DEBUG_TRUE_REGEX.get_or_init(|| {
                Regex::new(r#"(?i)\b(debug\s*=\s*True|debug:\s*true|NODE_ENV\s*=\s*['"]development['"])"#)
                    .unwrap()
            })
            .clone(),
            severity: Severity::Medium,
            cwe_id: "CWE-489",
            description: "Debug mode exposes stack traces, configuration, and internal state. \
                           Never enable it in production deployments.",
        },
        AiCodeRule {
            name: "TLS/SSL Verification Disabled",
            regex: VERIFY_FALSE_REGEX.get_or_init(|| {
                Regex::new(r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)")
                    .unwrap()
            })
            .clone(),
            severity: Severity::High,
            cwe_id: "CWE-295",
            description: "Disabling TLS verification allows man-in-the-middle attacks. \
                           This is a common AI-generated shortcut that must never reach production.",
        },
        AiCodeRule {
            name: "Overly Permissive CORS Policy",
            regex: OPEN_CORS_REGEX.get_or_init(|| {
                Regex::new(r#"(?i)(Access-Control-Allow-Origin:\s*\*|cors\(\)|allow_origins=\["\*"\]|allowedOrigins.*"\*")"#)
                    .unwrap()
            })
            .clone(),
            severity: Severity::Medium,
            cwe_id: "CWE-942",
            description: "A wildcard CORS policy allows any origin to make credentialed requests. \
                           Restrict to specific trusted domains in production.",
        },
        // ── Missing security controls ──────────────────────────────────────
        AiCodeRule {
            name: "Missing Pagination Limit (Potential DoS / Data Exposure)",
            regex: MISSING_PAGINATION_REGEX.get_or_init(|| {
                Regex::new(r"(?i)\.(findAll|find_all|list|fetchAll|fetch_all|getAll|get_all)\s*\((?:[^)]*\))").unwrap()
            })
            .clone(),
            severity: Severity::Low,
            cwe_id: "CWE-400",
            description: "Fetching all records without a limit can expose large amounts of data \
                           and cause denial-of-service through excessive database load.",
        },
        AiCodeRule {
            name: "Unauthenticated Route Handler",
            regex: NO_AUTH_ROUTE_REGEX.get_or_init(|| {
                // Simplified: detect the decorator. Manual filtering below.
                Regex::new(r"(?i)@(app|router)\.(delete|put|patch)\s*\(").unwrap()
            })
            .clone(),
            severity: Severity::Medium,
            cwe_id: "CWE-306",
            description: "AI-generated DELETE/PUT/PATCH route handlers often omit authentication \
                           dependencies. Ensure every mutation endpoint validates the caller's identity.",
        },
        // ── Dangerous evaluation ───────────────────────────────────────────
        AiCodeRule {
            name: "Dynamic Code Execution (exec/compile)",
            regex: EXEC_REGEX.get_or_init(|| {
                Regex::new(r"(?i)\b(exec|compile)\s*\(.*\binput\b|\b(exec|compile)\s*\(.*request\.")
                    .unwrap()
            })
            .clone(),
            severity: Severity::High,
            cwe_id: "CWE-95",
            description: "Passing user-controlled input to exec() or compile() enables remote \
                           code execution. This pattern is frequently generated by LLMs as a \
                           quick solution for dynamic calculations.",
        },
        // ── Information leakage ────────────────────────────────────────────
        AiCodeRule {
            name: "Logging Sensitive Data",
            regex: CONSOLE_LOG_SENSITIVE_REGEX.get_or_init(|| {
                Regex::new(r"(?i)(console\.(log|info|debug)|print|logger\.(info|debug|warn))\s*\(.*\b(password|token|secret|api_key|apikey|auth)\b")
                    .unwrap()
            })
            .clone(),
            severity: Severity::Medium,
            cwe_id: "CWE-532",
            description: "Logging credentials or tokens exposes them to anyone with log access. \
                           AI tools frequently add debug logs that include sensitive variables.",
        },
        AiCodeRule {
            name: "Plain HTTP Endpoint (No TLS)",
            regex: PLAIN_HTTP_REGEX.get_or_init(|| {
                // Simplified: detect http:// without localhost/127.0.0.1
                Regex::new(r#"(?i)(url\s*=\s*['"]http://|fetch\s*\(\s*['"]http://)"#).unwrap()
            })
            .clone(),
            severity: Severity::Medium,
            cwe_id: "CWE-319",
            description: "Transmitting data over plain HTTP exposes it to interception. \
                           Use HTTPS for all non-local endpoints.",
        },
        // ── Security TODO markers ──────────────────────────────────────────
        AiCodeRule {
            name: "Security TODO / FIXME Left by AI",
            regex: TODOS_SECURITY_REGEX.get_or_init(|| {
                Regex::new(r"(?i)(?://|#)\s*(TODO|FIXME|HACK|NOTSECURE|UNSAFE)[^:]*:?.*(auth|secur|password|token|permission|access|vulnerab|sanitiz|valid)")
                    .unwrap()
            })
            .clone(),
            severity: Severity::Info,
            cwe_id: "CWE-546",
            description: "AI generators often leave security-related TODO/FIXME comments indicating \
                           that critical security controls are not yet implemented.",
        },
        // ── Hardcoded port numbers ─────────────────────────────────────────
        AiCodeRule {
            name: "Hardcoded Development Port",
            regex: HARDCODED_PORT_REGEX.get_or_init(|| {
                Regex::new(r#"(?i)(port\s*[=:]\s*(3000|8080|8000|5000|4200|3001)\b|['"]:(3000|8080|8000|5000|4200|3001)['"])"#)
                    .unwrap()
            })
            .clone(),
            severity: Severity::Info,
            cwe_id: "CWE-1188",
            description: "Hardcoded development port numbers indicate configuration that may not \
                           match production requirements. Use environment variables for port config.",
        },
    ]
}

/// Run AI-code-specific pattern detection.
///
/// Returns a list of raw findings for AI-generated code anti-patterns.
pub async fn run(config: &ScanConfig) -> Result<Vec<RawFinding>> {
    let rules = build_rules();
    let mut findings = Vec::new();

    for (line_num, line) in config.code.lines().enumerate() {
        let line_number = (line_num + 1) as u32;

        for rule in &rules {
            if rule.regex.is_match(line) {
                // Manual filtering for rules that were simplified to avoid look-ahead panics
                if rule.name == "Unauthenticated Route Handler" {
                    let l = line.to_lowercase();
                    if l.contains("auth") || l.contains("depends") || l.contains("token") || l.contains("user") {
                        continue;
                    }
                }
                if rule.name == "Plain HTTP Endpoint (No TLS)" {
                    let l = line.to_lowercase();
                    if l.contains("localhost") || l.contains("127.0.0.1") {
                        continue;
                    }
                }

                findings.push(RawFinding {
                    engine: Engine::AiCode,
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
                // One finding per line — avoid duplicates for the same line.
                break;
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
            engines: vec![Engine::AiCode],
            ai_config: None,
            file_path: None,
        };
        run(&config).await.expect("scan should succeed")
    }

    #[tokio::test]
    async fn detects_hardcoded_user_id() {
        let findings = scan_code("user_id = 1").await;
        assert!(!findings.is_empty());
        assert!(findings[0].title.contains("Hardcoded Numeric"));
    }

    #[tokio::test]
    async fn detects_debug_true() {
        let findings = scan_code("DEBUG = True").await;
        assert!(!findings.is_empty());
        assert!(findings[0].title.contains("Debug Mode"));
    }

    #[tokio::test]
    async fn detects_verify_false() {
        let findings = scan_code("requests.get(url, verify=False)").await;
        assert!(!findings.is_empty());
        assert!(findings[0].title.contains("TLS"));
    }

    #[tokio::test]
    async fn detects_logging_password() {
        let findings = scan_code(r#"console.log("user password:", password)"#).await;
        assert!(!findings.is_empty());
        assert!(findings[0].title.contains("Logging Sensitive"));
    }

    #[tokio::test]
    async fn clean_code_no_findings() {
        let findings = scan_code("fn main() { println!(\"Hello\"); }").await;
        assert!(findings.is_empty());
    }
}
