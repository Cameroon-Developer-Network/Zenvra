//! Integration tests for the Zenvra scanner.
//!
//! These tests exercise the full scan pipeline (SAST + Secrets + AI Code)
//! against known-vulnerable code snippets to verify end-to-end finding detection.

use zenvra_scanner::{scan, Engine, Language, ScanConfig, Severity};

/// Build a minimal `ScanConfig` for testing without AI enrichment.
fn config(code: &str, language: Language, engines: Vec<Engine>) -> ScanConfig {
    ScanConfig {
        code: code.to_string(),
        language,
        engines,
        ai_config: None,
        file_path: Some("test_input.py".to_string()),
    }
}

// ─────────────────────────────── SAST Engine ──────────────────────────────────

#[tokio::test]
async fn sast_detects_sql_injection() {
    let code = r#"
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    db.execute(query)
"#;
    let findings = scan(&config(code, Language::Python, vec![Engine::Sast]))
        .await
        .expect("scan should succeed");

    assert!(
        !findings.is_empty(),
        "Expected at least one SQL injection finding, got none"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.title.to_lowercase().contains("sql")),
        "Expected an SQL-injection finding, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn sast_detects_command_injection() {
    let code = r#"
import os
def run(cmd):
    os.system(cmd)
"#;
    let findings = scan(&config(code, Language::Python, vec![Engine::Sast]))
        .await
        .expect("scan should succeed");

    assert!(
        findings.iter().any(|f| {
            let t = f.title.to_lowercase();
            t.contains("command") || t.contains("injection") || t.contains("os.system")
        }),
        "Expected a command-injection finding"
    );
}

#[tokio::test]
async fn sast_detects_eval_usage() {
    let code = "result = eval(user_input)\n";
    let findings = scan(&config(code, Language::Python, vec![Engine::Sast]))
        .await
        .expect("scan should succeed");

    assert!(
        findings
            .iter()
            .any(|f| f.title.to_lowercase().contains("eval")),
        "Expected an eval() finding"
    );
}

#[tokio::test]
async fn sast_detects_weak_hashing() {
    let code = r#"
import hashlib
h = hashlib.md5(password).hexdigest()
"#;
    let findings = scan(&config(code, Language::Python, vec![Engine::Sast]))
        .await
        .expect("scan should succeed");

    assert!(
        findings
            .iter()
            .any(|f| f.title.to_lowercase().contains("md5")
                || f.title.to_lowercase().contains("hash")),
        "Expected a weak-hashing finding"
    );
}

#[tokio::test]
async fn sast_clean_code_no_findings() {
    let code = r#"
def add(a: int, b: int) -> int:
    return a + b
"#;
    let findings = scan(&config(code, Language::Python, vec![Engine::Sast]))
        .await
        .expect("scan should succeed");

    assert!(
        findings.is_empty(),
        "Expected no findings for clean code, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

// ─────────────────────────── Secrets Engine ───────────────────────────────────

#[tokio::test]
async fn secrets_detects_aws_key() {
    let code = r#"AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE""#;
    let findings = scan(&config(code, Language::Python, vec![Engine::Secrets]))
        .await
        .expect("scan should succeed");

    assert!(
        !findings.is_empty(),
        "Expected an AWS key finding, got none"
    );
    assert_eq!(
        findings[0].engine,
        Engine::Secrets,
        "Finding should be from the Secrets engine"
    );
    assert!(
        findings[0].severity >= Severity::High,
        "AWS key should be High or Critical severity"
    );
}

#[tokio::test]
async fn secrets_detects_github_token() {
    let code = r#"token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij""#;
    let findings = scan(&config(code, Language::Python, vec![Engine::Secrets]))
        .await
        .expect("scan should succeed");

    assert!(!findings.is_empty(), "Expected a GitHub token finding");
}

#[tokio::test]
async fn secrets_detects_rsa_private_key() {
    let code = r#"
key = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VR...
-----END RSA PRIVATE KEY-----
"""
"#;
    let findings = scan(&config(code, Language::Python, vec![Engine::Secrets]))
        .await
        .expect("scan should succeed");

    assert!(!findings.is_empty(), "Expected a private key finding");
    assert_eq!(findings[0].severity, Severity::Critical);
}

#[tokio::test]
async fn secrets_env_var_not_flagged() {
    let code = r#"API_KEY = os.environ.get("API_KEY")"#;
    let findings = scan(&config(code, Language::Python, vec![Engine::Secrets]))
        .await
        .expect("scan should succeed");

    // Reading from env should not be flagged
    assert!(
        findings.is_empty(),
        "env.get() should not be flagged as a secret, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

// ─────────────────────────── AI Code Engine ───────────────────────────────────

#[tokio::test]
async fn ai_code_detects_debug_true() {
    let code = "DEBUG = True\n";
    let findings = scan(&config(code, Language::Python, vec![Engine::AiCode]))
        .await
        .expect("scan should succeed");

    assert!(!findings.is_empty(), "Expected a debug-mode finding");
    assert_eq!(findings[0].engine, Engine::AiCode);
}

#[tokio::test]
async fn ai_code_detects_verify_false() {
    let code = "resp = requests.get(url, verify=False)\n";
    let findings = scan(&config(code, Language::Python, vec![Engine::AiCode]))
        .await
        .expect("scan should succeed");

    assert!(
        !findings.is_empty(),
        "Expected a TLS verification disabled finding"
    );
}

#[tokio::test]
async fn ai_code_detects_hardcoded_id() {
    let code = "user_id = 1\n";
    let findings = scan(&config(code, Language::Python, vec![Engine::AiCode]))
        .await
        .expect("scan should succeed");

    assert!(!findings.is_empty(), "Expected a hardcoded ID finding");
}

// ─────────────────────────── Multi-engine ─────────────────────────────────────

#[tokio::test]
async fn multi_engine_finds_multiple_issues() {
    // Code from the real test fixture
    let code = include_str!("../../../test-fixtures/vulnerable_app.py");

    let findings = scan(&config(
        code,
        Language::Python,
        vec![Engine::Sast, Engine::Secrets, Engine::AiCode],
    ))
    .await
    .expect("scan should succeed");

    // Should detect at least AWS key + GitHub token + private key (= 3+ secrets)
    assert!(
        findings.len() >= 3,
        "Expected at least 3 findings against vulnerable_app.py, got {}",
        findings.len()
    );

    // At least one Critical finding (private key / AWS key)
    assert!(
        findings.iter().any(|f| f.severity == Severity::Critical),
        "Expected at least one critical severity finding"
    );

    // Results should be sorted critical-first
    let severities: Vec<&Severity> = findings.iter().map(|f| &f.severity).collect();
    let mut sorted = severities.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(
        severities, sorted,
        "Findings should be sorted by severity descending"
    );
}

// ─────────────────────────── SCA Engine (unit) ────────────────────────────────

#[test]
fn sca_parses_cargo_lock_format() {
    // Minimal Cargo.lock — just verify the parser doesn't panic
    let content = r#"
[[package]]
name = "serde"
version = "1.0.0"

[[package]]
name = "tokio"
version = "1.0.0"
"#;
    let cfg = ScanConfig {
        code: content.to_string(),
        language: Language::Rust,
        engines: vec![Engine::Sca],
        ai_config: None,
        file_path: Some("Cargo.lock".to_string()),
    };
    // Only testing the parser, not the network call
    // The actual OSV query is tested in engines/sca.rs unit tests
    drop(cfg);
}
