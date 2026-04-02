//! Core data types for scan findings.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single security finding from a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub engine: crate::Engine,

    /// CVE identifier if one exists (e.g. "CVE-2025-12345").
    pub cve_id: Option<String>,

    /// CWE identifier (e.g. "CWE-89" for SQL injection).
    pub cwe_id: Option<String>,

    pub severity: Severity,

    /// Short title of the vulnerability.
    pub title: String,

    /// AI-generated plain-English explanation for non-security-experts.
    pub explanation: String,

    /// The vulnerable code snippet.
    pub vulnerable_code: String,

    /// AI-generated corrected version of the code.
    pub fixed_code: String,

    pub line_start: u32,
    pub line_end: u32,
    pub file_path: Option<String>,
    pub detected_at: DateTime<Utc>,
}

/// Vulnerability severity aligned with CVSS categories.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}
