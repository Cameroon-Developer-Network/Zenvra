# Issue #2 — SAST engine: Semgrep integration

**Labels:** `area: scanner` · `type: feature` · `priority: critical`
**Milestone:** v0.1.0
**Depends on:** #1

---

## Summary

Implement the SAST (static application security testing) engine in `crates/scanner/src/engines/sast.rs`. This engine calls Semgrep as a subprocess, parses its JSON output, and converts results into `Finding` structs.

## Context

Semgrep is the industry-standard open-source SAST engine. It supports 30+ languages and has a large rule registry. Rather than building our own AST-based analysis from scratch, we shell out to the `semgrep` binary and parse its structured JSON output. This is the same approach used by Snyk and Aikido Security internally.

## What to build

### `src/engines/sast.rs`

```rust
pub async fn run(config: &ScanConfig) -> Result<Vec<Finding>>
```

**Implementation steps:**

1. **Check Semgrep is installed** — run `semgrep --version` and return a clear error if not found (with install instructions in the error message)

2. **Build the Semgrep command**
   ```
   semgrep scan \
     --config p/owasp-top-ten \
     --config p/secrets \
     --json \
     --quiet \
     <target_path>
   ```

3. **Parse JSON output** — Semgrep returns:
   ```json
   {
     "results": [
       {
         "check_id": "python.django.security.injection.tainted-sql-string",
         "path": "src/db/users.py",
         "start": { "line": 42, "col": 5 },
         "extra": {
           "severity": "ERROR",
           "message": "Detected SQL injection...",
           "metadata": { "cve": "CVE-2025-1234" }
         }
       }
     ]
   }
   ```

4. **Convert to `Finding`** — map Semgrep fields to our types:
   - `check_id` → `rule_id`
   - `extra.severity` (`ERROR`/`WARNING`/`INFO`) → `Severity` (`High`/`Medium`/`Low`)
   - `extra.metadata.cve` → `cve_id` (if present)
   - `extra.message` → `description`

5. **Filter by `config.min_severity`**

6. **Return sorted by severity descending**

### Test fixtures

Add sample vulnerable files in `crates/scanner/tests/fixtures/`:
- `python_sqli.py` — SQL injection example
- `js_xss.js` — XSS example
- `node_path_traversal.js` — path traversal example

### Unit tests

- Test the Semgrep JSON parser with mocked output (do not require Semgrep to be installed for unit tests — use a fixture JSON file)
- Integration test (gated with `#[ignore]`) that actually runs Semgrep on the fixture files

## Acceptance criteria

- [ ] `sast::run()` returns `Vec<Finding>` for a directory containing vulnerable Python/JS files
- [ ] Graceful error if Semgrep is not installed (no panic)
- [ ] JSON output parsing is tested with fixture data
- [ ] Findings are sorted by severity (Critical first)
- [ ] `cargo test --all` passes (unit tests only, no Semgrep required)

## Notes

- Semgrep binary is NOT bundled — it must be installed by the user. Document this in the CLI help text.
- Default rules: `p/owasp-top-ten` covers the most important vulnerabilities for MVP
- Use `tokio::process::Command` for the subprocess (async)
- Capture stderr separately — Semgrep writes progress to stderr
