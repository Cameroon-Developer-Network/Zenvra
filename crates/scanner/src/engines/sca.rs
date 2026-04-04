//! SCA engine — software composition analysis.
//!
//! Parses lockfiles and queries OSV/NVD for known CVEs.

use crate::{finding::RawFinding, ScanConfig};
use anyhow::Result;

/// Run SCA analysis — parse dependency files and check for known vulnerabilities.
///
/// Returns a list of raw findings for vulnerable dependencies.
pub async fn run(_config: &ScanConfig) -> Result<Vec<RawFinding>> {
    // TODO: parse lockfiles (Cargo.lock, package-lock.json, etc.) and query OSV API
    tracing::info!("SCA engine: not yet implemented");
    Ok(vec![])
}
