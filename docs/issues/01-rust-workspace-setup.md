# Issue #1 — Rust workspace setup + zenvra-scanner crate skeleton

**Labels:** `area: scanner` · `type: feature` · `priority: critical` · `good first issue`
**Milestone:** v0.1.0

---

## Summary

Set up the Rust workspace and create the foundational `zenvra-scanner` crate with all core types, module structure, and passing tests. This is the first issue to complete — everything else depends on it.

## Context

The scan engine lives in `crates/scanner/`. It is a library crate that the CLI, web API, and VS Code extension all call into. Getting the types right here is critical — they will not change often once established.

## What to build

### Workspace (`Cargo.toml` at root)
- `[workspace]` with members `crates/scanner` and `crates/cli`
- `[workspace.dependencies]` with shared dep versions for: `tokio`, `anyhow`, `thiserror`, `serde`, `serde_json`, `uuid`, `chrono`, `tracing`

### `crates/scanner/src/lib.rs` — public types
```rust
pub struct Finding { ... }      // id, kind, file, line, severity, cve_id, title, description, explanation, fix_code
pub enum FindingKind { Sast, Sca, Secret }
pub enum Severity { Info, Low, Medium, High, Critical }
pub struct ScanSummary { ... }  // total, critical, high, medium, low, info, files_scanned, duration_ms
pub struct ScanResult { ... }   // scan_id, target, findings, summary, scanned_at
pub struct ScanConfig { ... }   // target, enable_sast, enable_sca, enable_secrets, enable_ai_enrichment, min_severity
```

### Module stubs (compile but return empty results)
- `src/engines/sast.rs` — `pub async fn run(config: &ScanConfig) -> Result<Vec<Finding>>`
- `src/engines/sca.rs` — same signature
- `src/engines/secrets.rs` — same signature
- `src/cve/mod.rs` — `pub async fn lookup(cve_id: &str) -> Result<Option<serde_json::Value>>`
- `src/ai/mod.rs` — `pub async fn enrich(findings: &mut Vec<Finding>, api_key: &str) -> Result<()>`
- `src/api/mod.rs` — Axum router with `/health` route only
- `src/report/mod.rs` — `pub fn terminal(result: &ScanResult) -> Result<String>`

## Acceptance criteria

- [ ] `cargo build` passes with zero warnings
- [ ] `cargo clippy --all-targets -- -D warnings` passes
- [ ] `cargo fmt --check` passes
- [ ] `cargo test --all` passes with at least 5 unit tests covering:
  - `Finding::new()` creates with correct defaults
  - `Severity` ordering (Critical > High > Medium > Low > Info)
  - `ScanSummary::from_findings()` counts correctly
  - `FindingKind` serialises to snake_case JSON
  - `ScanConfig::default()` has all engines enabled

## Notes

- Use `uuid::Uuid::new_v4()` for finding IDs
- `Severity` must implement `PartialOrd + Ord` for filtering by min_severity
- All types must implement `Serialize + Deserialize` (needed for API and CLI JSON output)
- See `AGENTS.md` for the full type definitions and style rules
