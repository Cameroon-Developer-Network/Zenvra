//! Secrets scanner — detects API keys, tokens, and credentials in code.
//! See issue #3 for implementation details.

use crate::{Finding, ScanConfig};
use anyhow::Result;

pub async fn run(_config: &ScanConfig) -> Result<Vec<Finding>> {
    tracing::info!("Secrets engine: not yet implemented");
    Ok(vec![])
}
