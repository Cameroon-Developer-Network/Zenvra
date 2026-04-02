//! SAST engine — static application security testing.
//!
//! Wraps Semgrep and custom Zenvra rules.

use crate::{ScanConfig, finding::RawFinding};
use anyhow::Result;

/// Run SAST analysis against the code in `config`.
///
/// Returns a list of raw findings sorted by severity (highest first).
pub async fn run(_config: &ScanConfig) -> Result<Vec<RawFinding>> {
    // TODO: implement Semgrep subprocess integration
    tracing::info!("SAST engine: not yet implemented");
    Ok(vec![])
}
