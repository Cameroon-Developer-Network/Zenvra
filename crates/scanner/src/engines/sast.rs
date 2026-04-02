//! SAST engine — static application security testing.
//! Wraps Semgrep and custom Zenvra rules.
//! See issue #2 for implementation details.

use crate::{Finding, ScanConfig};
use anyhow::Result;

/// Run SAST analysis against the target in `config`.
/// Returns a list of findings sorted by severity (highest first).
pub async fn run(_config: &ScanConfig) -> Result<Vec<Finding>> {
    // TODO (#2): implement Semgrep subprocess integration
    tracing::info!("SAST engine: not yet implemented");
    Ok(vec![])
}
