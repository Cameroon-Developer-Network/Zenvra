//! Core data types for scan findings.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A raw finding from a scan engine, before AI enrichment.
///
/// This is what engines produce. It gets converted to a [`Finding`]
/// after the AI provider generates an explanation and fix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawFinding {
    pub engine: crate::Engine,

    /// CVE identifier if one exists (e.g. "CVE-2025-12345").
    pub cve_id: Option<String>,

    /// CWE identifier (e.g. "CWE-89" for SQL injection).
    pub cwe_id: Option<String>,

    pub severity: Severity,

    /// Short title of the vulnerability.
    pub title: String,

    /// The vulnerable code snippet.
    pub vulnerable_code: String,
    pub description: Option<String>,
    pub line_start: u32,
    pub line_end: u32,
    pub file_path: Option<String>,
}

impl RawFinding {
    /// Convert a raw finding into a full [`Finding`] with AI-generated content.
    pub fn into_finding(self, explanation: String, fixed_code: String) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            engine: self.engine,
            cve_id: self.cve_id,
            cwe_id: self.cwe_id,
            severity: self.severity,
            title: self.title,
            explanation,
            vulnerable_code: self.vulnerable_code,
            fixed_code,
            description: self.description,
            line_start: self.line_start,
            line_end: self.line_end,
            file_path: self.file_path,
            detected_at: Utc::now(),
        }
    }
}

/// A fully enriched security finding from a scan.
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

    pub description: Option<String>,
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

/// Events emitted during a scan run to provide real-time updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ScanEvent {
    /// Scan progress update.
    Progress { percentage: u8, message: String },
    /// A new security finding has been detected and enriched.
    Finding(Box<Finding>),
    /// The scan has completed successfully.
    Complete,
    /// A critical error occurred during the scan.
    Error(String),
}
