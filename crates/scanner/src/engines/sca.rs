//! SCA engine — software composition analysis.
//! Parses lockfiles and queries OSV/NVD for known CVEs.
//! See issue #4 for implementation details.

use crate::{Finding, ScanConfig};
use anyhow::Result;

pub async fn run(_config: &ScanConfig) -> Result<Vec<Finding>> {
    tracing::info!("SCA engine: not yet implemented");
    Ok(vec![])
}
