# Issue #3 — Secrets scanner: regex + entropy detection

**Labels:** `area: scanner` · `type: feature` · `priority: critical`
**Milestone:** v0.1.0 · **Depends on:** #1

## Summary

Implement `crates/scanner/src/engines/secrets.rs` — detect API keys, tokens, passwords, and credentials accidentally committed to code.

## What to build

Two detection strategies, run in parallel:

**1. Pattern matching** — regex rules for common secret formats:

| Secret type | Pattern example |
|---|---|
| AWS Access Key | `AKIA[0-9A-Z]{16}` |
| GitHub token | `ghp_[a-zA-Z0-9]{36}` |
| Anthropic API key | `sk-ant-[a-zA-Z0-9-]{95}` |
| Generic API key | `api[_-]?key\s*=\s*['"][a-zA-Z0-9]{20,}['"]` |
| Private key | `-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----` |
| JWT | `eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+` |
| Database URL with password | `(postgres|mysql|mongodb):\/\/[^:]+:[^@]+@` |

**2. Shannon entropy** — high-entropy strings (>4.5 bits/char) in variable assignments are likely secrets, even if they don't match a known pattern.

```rust
fn shannon_entropy(s: &str) -> f64 { ... }
```

**Output:** `Finding` with `kind: FindingKind::Secret`, severity always `High` or `Critical`, and a `description` that names the secret type (e.g. `"AWS Access Key detected"`).

## Acceptance criteria

- [ ] Detects at least 8 common secret types via regex
- [ ] Shannon entropy detects high-entropy strings ≥20 chars in variable assignments
- [ ] Ignores test fixture files and example files (`.env.example`, `test_`, `_test.`, `fixture`)
- [ ] Returns `file`, `line`, and which pattern matched
- [ ] Zero false positives on the Zenvra codebase itself
- [ ] Unit tests for each regex pattern and entropy function

---

# Issue #4 — SCA engine: dependency vulnerability scanning

**Labels:** `area: scanner` · `type: feature` · `priority: critical`
**Milestone:** v0.1.0 · **Depends on:** #1

## Summary

Implement `crates/scanner/src/engines/sca.rs` — parse lockfiles from major package ecosystems and query the OSV API to find known CVEs in dependencies.

## Supported lockfiles (MVP)

| Ecosystem | Lockfile |
|---|---|
| Node.js | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Python | `requirements.txt`, `Pipfile.lock`, `poetry.lock` |
| Rust | `Cargo.lock` |
| Go | `go.sum` |

## What to build

**Step 1 — Lockfile parser** for each format. Extract: `{ package_name, version, ecosystem }`.

**Step 2 — OSV API query**

```
POST https://api.osv.dev/v1/querybatch
{
  "queries": [
    { "package": { "name": "lodash", "ecosystem": "npm" }, "version": "4.17.15" }
  ]
}
```

Batch requests in groups of 100 (OSV limit). Cache responses in memory for the scan session.

**Step 3 — Map to `Finding`**

```rust
Finding {
    kind: FindingKind::Sca,
    file: PathBuf::from("package-lock.json"),
    line: None,
    cve_id: Some("CVE-2021-23337".to_string()),
    severity: map_cvss_to_severity(osv_response.severity),
    title: format!("{} {} — {}", package, version, vuln_id),
    description: osv_response.summary,
    ..
}
```

## Acceptance criteria

- [ ] Parses all listed lockfile formats correctly
- [ ] Queries OSV API in batches (not one request per package)
- [ ] Maps CVSS scores to Severity enum correctly (≥9.0 Critical, ≥7.0 High, ≥4.0 Medium, else Low)
- [ ] Gracefully handles OSV API errors (network timeout, rate limit)
- [ ] Unit tests with fixture lockfiles containing known-vulnerable packages

---

# Issue #5 — CVE enrichment: NVD local cache

**Labels:** `area: scanner` · `type: feature` · `priority: high`
**Milestone:** v0.1.0 · **Depends on:** #1, #4

## Summary

Implement `crates/scanner/src/cve/` — a local cache of CVE data from the National Vulnerability Database (NVD) that is queried to enrich findings with full CVE details before sending to the AI layer.

## What to build

**Database schema** (Postgres via sqlx):
```sql
CREATE TABLE cve_cache (
    cve_id TEXT PRIMARY KEY,
    data JSONB NOT NULL,          -- full NVD CVE record
    cached_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL  -- 24h TTL
);
```

**`cve::lookup(cve_id: &str) -> Result<Option<CveRecord>>`**
1. Check local DB — return cached record if not expired
2. On cache miss: fetch from `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}`
3. Parse and store in DB with 24h TTL
4. Return `CveRecord { id, description, cvss_score, cvss_vector, references, published_date }`

**Daily sync script** (`scripts/sync-nvd.sh`) — fetches the NVD data feed for bulk loading, avoiding per-CVE API calls during scans.

## Acceptance criteria

- [ ] CVE lookup works for any valid CVE ID
- [ ] Cache TTL of 24 hours respected
- [ ] Graceful fallback if NVD API is unavailable (return `None`, do not fail the scan)
- [ ] Unit tests with mocked HTTP responses

---

# Issue #6 — AI enrichment: Claude API integration

**Labels:** `area: scanner` · `type: feature` · `priority: critical`
**Milestone:** v0.1.0 · **Depends on:** #1, #5

## Summary

Implement `crates/scanner/src/ai/` — call the Anthropic Claude API to generate plain-English explanations and corrected code snippets for each finding.

## What to build

**`ai::enrich(findings: &mut Vec<Finding>, api_key: &str) -> Result<()>`**

For each finding (batch where possible):

1. Build a prompt:
```
You are a security expert explaining a code vulnerability to a developer.

Vulnerability: {title}
CVE: {cve_id or "no CVE"}
Severity: {severity}
File: {file}:{line}
Description: {description}

Vulnerable code:
```{language}
{code_snippet}
```

Respond with JSON only:
{
  "explanation": "Plain-English explanation under 120 words. No jargon without explaining it.",
  "fix_code": "The corrected code snippet only, same language, no prose."
}
```

2. Call `POST https://api.anthropic.com/v1/messages`
   - Model: `claude-sonnet-4-20250514`
   - Max tokens: 1024
   - Parse JSON response

3. **Cache by `(rule_id, sha256(code_snippet))`** — store in Postgres so identical findings across scans never call the API twice

4. Set `finding.explanation` and `finding.fix_code`

## Acceptance criteria

- [ ] All findings with severity ≥ Medium are enriched when `config.enable_ai_enrichment = true`
- [ ] Cache prevents duplicate API calls for identical code patterns
- [ ] Graceful fallback if API key is missing or API returns error (finding still returned, enrichment fields are `None`)
- [ ] API key read from `ANTHROPIC_API_KEY` environment variable
- [ ] Unit tests with mocked HTTP responses

---

# Issue #7 — CLI tool: `zenvra scan` command

**Labels:** `area: cli` · `type: feature` · `priority: critical`
**Milestone:** v0.1.0 · **Depends on:** #2, #3, #4, #5, #6

## Summary

Complete the `zenvra` CLI binary in `crates/cli/` so `zenvra scan ./src` runs a full scan and outputs results to the terminal.

## Commands

```
zenvra scan <path>
  --format         terminal (default) | json | html
  --min-severity   low (default) | medium | high | critical
  --no-ai          skip AI enrichment
  --no-sast        skip source code scanning
  --no-sca         skip dependency scanning
  --no-secrets     skip secrets scanning
  --fail-on        exit code 1 if findings at this severity or above exist

zenvra auth --token <TOKEN>    save API token to ~/.config/zenvra/config.toml
zenvra version                 print version and exit
```

## Terminal output format

```
Zenvra v0.1.0 — scanning ./my-app
─────────────────────────────────

CRITICAL  SQL Injection (CVE-2025-1234)
          src/db/users.py:42
          User input is concatenated directly into a SQL query...
          
          Fix:
          - query = f"SELECT * FROM users WHERE id = {user_id}"
          + query = "SELECT * FROM users WHERE id = ?"
          + cursor.execute(query, (user_id,))

─────────────────────────────────
  3 issues found in 47 files (1.2s)
  Critical: 1 · High: 1 · Medium: 1 · Low: 0
```

## Acceptance criteria

- [ ] `zenvra scan .` runs end-to-end and prints findings
- [ ] `--format json` outputs valid JSON matching `ScanResult` schema
- [ ] `--fail-on high` exits with code 1 when high/critical findings exist (useful for CI)
- [ ] `--no-ai` skips AI calls and runs significantly faster
- [ ] Install instructions work: `cargo install --path crates/cli`
- [ ] `zenvra --help` and `zenvra scan --help` output is clear and complete

---

# Issue #8 — Web UI: SvelteKit scanner interface

**Labels:** `area: web` · `type: feature` · `priority: critical`
**Milestone:** v0.1.0 · **Depends on:** #6

## Summary

Build the Zenvra web UI in `apps/web/` — a clean, fast interface where anyone can paste code and get a scan result in under 10 seconds. No login required for the basic scan.

## Pages to build

**`/` — homepage + scan interface**
- Hero: "Paste your code. Find the vulnerabilities."
- Large code paste area (syntax-highlighted, supports file drag & drop)
- Language selector (auto-detect by default)
- "Scan" button → calls `POST /api/scan` → shows results below
- Result card for each finding:
  - Severity badge (colour-coded)
  - CVE ID (linked to NVD)
  - Plain-English explanation
  - Before/after code diff showing the fix

**`/scan/[id]` — shareable scan result page**
- Full scan results with all findings
- "Share this scan" button — generates a public URL
- "Download report" button — JSON or PDF

**`/api/scan` — SvelteKit API route**
- `POST` with `{ code, language?, filename? }`
- Calls into the `zenvra-scanner` Rust API
- Returns `ScanResult` JSON

## Design requirements

- Mobile-friendly (many devs will share scan links on mobile)
- Fast — target <2s time to first byte
- Dark mode support
- No user account required to do a basic scan (free tier, 50 scans/month limit by IP)

## Acceptance criteria

- [ ] Paste code → click Scan → see results within 10 seconds
- [ ] Each finding shows: severity, title, CVE ID (if any), plain-English explanation, fix
- [ ] Shareable URL works (result persists for 30 days)
- [ ] Works on mobile
- [ ] `pnpm build` succeeds with no TypeScript errors

---

# Issue #9 — GitHub Action: PR annotations

**Labels:** `area: cli` · `type: feature` · `priority: high`
**Milestone:** v0.1.0 · **Depends on:** #7

## Summary

Create a GitHub Action that runs `zenvra scan` on every pull request and posts inline review comments on vulnerable lines.

## What to build

**`action.yml`** in repo root:
```yaml
name: Zenvra Security Scan
description: Scan code for vulnerabilities on every PR
inputs:
  token:
    description: GitHub token (use secrets.GITHUB_TOKEN)
    required: true
  fail-on:
    description: Fail the check if findings at this severity or above exist
    default: high
  min-severity:
    description: Minimum severity to report
    default: medium
runs:
  using: docker
  image: ghcr.io/cameroon-developer-network/zenvra:latest
```

**PR annotation logic:**
1. Run `zenvra scan . --format json`
2. For each finding with a `file` and `line`, post a GitHub Review comment on that exact line:
   ```
   🔴 CRITICAL — SQL Injection (CVE-2025-1234)
   
   User input is concatenated directly into a SQL query...
   
   Fix: [corrected code snippet]
   ```
3. Post a summary comment on the PR with total counts

**Usage (what contributors put in their `.github/workflows/zenvra.yml`):**
```yaml
- uses: Cameroon-Developer-Network/zenvra@v1
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    fail-on: high
```

## Acceptance criteria

- [ ] Action runs on `pull_request` events
- [ ] Inline review comments appear on the correct file + line
- [ ] Summary comment shows total finding count with breakdown by severity
- [ ] `fail-on: high` makes the check fail (red X) when high/critical findings found
- [ ] Action is published to GitHub Marketplace

---

# Issue #10 — Shareable scan badge (viral mechanic)

**Labels:** `area: web` · `type: feature` · `priority: high`
**Milestone:** v0.1.0 · **Depends on:** #8

## Summary

Build the shareable scan result card — the key viral growth mechanic. After every scan, users get a one-click shareable image card they can post to Twitter/X, Reddit, or LinkedIn.

## What to build

**`/api/badge/[scan_id]`** — generates an OG image (1200×630px) showing:

```
┌─────────────────────────────────────────────┐
│  ⚡ Zenvra                                   │
│                                             │
│  Scanned: my-saas-app                      │
│                                             │
│  🔴 2 Critical    🟠 1 High    🟡 3 Medium   │
│                                             │
│  Top finding: SQL Injection (CVE-2025-1234) │
│  Found in: src/db/users.py:42               │
│                                             │
│  Scanned in 1.2s · zenvra.dev              │
└─────────────────────────────────────────────┘
```

**Implementation:** Use `@vercel/og` (SvelteKit compatible) or `satori` to generate the image server-side from the scan result data.

**"Share" button** on every scan result page:
- Copies the `zenvra.dev/scan/[id]` URL to clipboard
- Pre-fills tweet text: `"Zenvra found {n} vulnerabilities in my code in {time}s — including {top_finding}. Free to scan yours: zenvra.dev"`

**README badge** (for open-source projects):
```markdown
[![Zenvra](https://zenvra.dev/badge/repo/github/user/repo.svg)](https://zenvra.dev)
```

## Acceptance criteria

- [ ] OG image generated correctly for any scan ID
- [ ] Share button copies URL + opens pre-filled tweet
- [ ] Badge SVG renders correctly in GitHub READMEs
- [ ] Image is generated server-side (not client-side canvas)

---

# Issue #11 — VS Code extension: inline diagnostics

**Labels:** `area: vscode` · `type: feature` · `priority: high`
**Milestone:** v0.2.0 · **Depends on:** #8

## Summary

Complete the VS Code extension in `extensions/vscode/` — shows vulnerability squiggles inline as developers type, with a quick-fix action that applies the AI-generated corrected code.

## What to build

**`src/scanner.ts`** — calls `POST /api/scan` with the current file content on save (debounced, 1s)

**`src/diagnostics.ts`** — converts `Finding[]` into `vscode.Diagnostic[]`:
- Red squiggle for Critical/High
- Yellow squiggle for Medium
- Blue squiggle for Low
- Hover tooltip shows: severity badge + CVE ID + plain-English explanation

**Quick Fix action** — when user clicks the lightbulb on a squiggly line:
- Shows "Fix with Zenvra: [title of fix]"
- Applies the `fix_code` as a text edit to the document

**Status bar item** — shows scan status: `Zenvra: 2 issues` or `Zenvra: scanning...`

## Acceptance criteria

- [ ] Squiggles appear within 2 seconds of saving a file
- [ ] Hover shows explanation and CVE link
- [ ] Quick Fix applies the corrected code
- [ ] Extension activates only for supported language files
- [ ] Published to VS Code Marketplace

---

# Issue #12 — Docker Compose dev environment

**Labels:** `area: scanner` · `type: dx` · `good first issue`
**Milestone:** v0.1.0

## Summary

Create a complete `docker-compose.yml` that spins up Postgres, Redis, and the Zenvra API so new contributors can be productive in under 5 minutes.

## What to build

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: zenvra
      POSTGRES_USER: zenvra
      POSTGRES_PASSWORD: zenvra
    ports: ["5432:5432"]
    volumes: [postgres_data:/var/lib/postgresql/data]

  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]

  # Optional: pgAdmin for DB inspection
  pgadmin:
    image: dpage/pgadmin4
    ports: ["5050:80"]
    profiles: [debug]
```

Also add `scripts/db-migrate.sh` that runs sqlx migrations.

## Acceptance criteria

- [ ] `docker compose up -d` starts all services successfully
- [ ] Postgres is accessible at `localhost:5432`
- [ ] Redis is accessible at `localhost:6379`
- [ ] `docker compose down -v` cleans up all volumes
- [ ] `.env.example` has all required variables pre-filled for Docker setup
- [ ] README setup instructions are correct

---

# Issue #13 — Database migrations: initial schema

**Labels:** `area: scanner` · `type: feature` · `priority: critical` · `good first issue`
**Milestone:** v0.1.0 · **Depends on:** #12

## Summary

Create the initial PostgreSQL schema using sqlx migrations.

## Tables to create

```sql
-- Users and API tokens
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE api_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  label TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ
);

-- Scan history
CREATE TABLE scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  target TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',  -- pending | running | complete | failed
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  summary JSONB
);

CREATE TABLE findings (
  id UUID PRIMARY KEY,
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  file TEXT,
  line INTEGER,
  severity TEXT NOT NULL,
  cve_id TEXT,
  rule_id TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  explanation TEXT,
  fix_code TEXT,
  detected_at TIMESTAMPTZ NOT NULL
);

-- CVE cache
CREATE TABLE cve_cache (
  cve_id TEXT PRIMARY KEY,
  data JSONB NOT NULL,
  cached_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);

-- AI explanation cache (keyed by rule+code hash)
CREATE TABLE ai_cache (
  cache_key TEXT PRIMARY KEY,  -- sha256(rule_id + code_snippet)
  explanation TEXT NOT NULL,
  fix_code TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX findings_scan_id ON findings(scan_id);
CREATE INDEX findings_severity ON findings(severity);
CREATE INDEX findings_cve_id ON findings(cve_id) WHERE cve_id IS NOT NULL;
```

## Acceptance criteria

- [ ] Migrations run with `sqlx migrate run`
- [ ] All tables created with correct types and constraints
- [ ] Indexes created for common query patterns
- [ ] `sqlx migrate revert` works cleanly
- [ ] Schema documented in `docs/schema.md`

---

# Issue #14 — Semgrep custom rules for AI-generated code patterns

**Labels:** `area: scanner` · `type: feature` · `priority: high` · `help wanted`
**Milestone:** v0.2.0 · **Depends on:** #2

## Summary

Write custom Semgrep YAML rules targeting vulnerability patterns that are uniquely common in AI-generated and vibe-coded applications. This is Zenvra's proprietary moat — no other scanner targets these patterns specifically.

## Background

Research shows AI coding tools consistently make the same security mistakes:
- Storing passwords in plaintext
- Putting all auth logic client-side
- Hardcoding credentials in environment setups
- Using `eval()` without sanitisation
- Exposing internal errors directly to users
- Missing row-level security on Supabase/Firebase queries

## Rules to write (minimum 10)

Each rule is a YAML file in `crates/scanner/rules/ai-patterns/`:

1. `plaintext-password-storage.yml` — detect `password = hash(password)` where hash is md5/sha1
2. `client-side-auth-only.yml` — detect auth checks only in frontend JS with no server validation
3. `hardcoded-supabase-key.yml` — detect Supabase anon key in client-side JS
4. `missing-rls-supabase.yml` — detect Supabase queries without RLS indication in comments/schema
5. `eval-user-input.yml` — detect `eval(userInput)` or `eval(req.body.*)`
6. `error-details-exposed.yml` — detect `res.json(error)` or `res.send(err.message)`
7. `sql-string-concat.yml` — broader than OWASP rule, catches f-string concat patterns
8. `missing-cors-validation.yml` — detect `app.use(cors())` with no origin validation
9. `jwt-no-expiry.yml` — detect JWT signing without `expiresIn` option
10. `debug-mode-production.yml` — detect `DEBUG=True` or `app.run(debug=True)` in non-test files

## Acceptance criteria

- [ ] At least 10 custom rules written and validated
- [ ] Each rule has a test case: a vulnerable file and a safe file
- [ ] Rules validated with `semgrep --test crates/scanner/rules/`
- [ ] False positive rate tested on 3 popular open-source projects
- [ ] Rules documented in `docs/rules.md`

---

# Issue #15 — CONTRIBUTING.md + development documentation

**Labels:** `type: dx` · `good first issue`
**Milestone:** v0.1.0

## Summary

Write the full `CONTRIBUTING.md` and populate the `docs/` folder with developer documentation so any contributor can get productive quickly.

## What to write

**`CONTRIBUTING.md`** (root):
- Code of conduct (link to standard)
- How to find issues to work on
- Development setup (step by step)
- Branch naming conventions
- Commit message format (Conventional Commits)
- PR process and what reviewers check
- How to run the full test suite
- How to add a new Semgrep rule

**`docs/architecture.md`**:
- System architecture diagram (ASCII or mermaid)
- How the scan pipeline works end-to-end
- Data flow between components
- Key design decisions and why

**`docs/api.md`**:
- All HTTP API endpoints with request/response examples
- Authentication (API token header)
- Rate limits
- Error format

**`docs/rules.md`**:
- How to write a custom Semgrep rule for Zenvra
- Rule structure and metadata fields
- Testing rules with `semgrep --test`

## Acceptance criteria

- [ ] A new contributor can set up their dev environment following CONTRIBUTING.md alone
- [ ] Architecture diagram is accurate and up to date
- [ ] All API endpoints documented
- [ ] Proof-read for clarity — no assumed knowledge

---

# Issue #16 — GitLab CI integration

**Labels:** `area: cli` · `type: feature` · `priority: medium`
**Milestone:** v0.2.0 · **Depends on:** #7

## Summary

Create a GitLab CI template that mirrors the GitHub Action (issue #9) — runs `zenvra scan` on merge requests and reports findings as pipeline job output.

## What to build

A reusable GitLab CI component in `.gitlab/` with:
- `zenvra-scan` job definition
- MR note posting via GitLab API
- Configurable `fail_on` and `min_severity` variables
- Published as a GitLab CI/CD Catalog component

## Acceptance criteria

- [ ] Works with `include: component: gitlab.com/...`
- [ ] Findings shown in pipeline job log with correct severity colours
- [ ] MR note posted with finding summary
- [ ] Documented in `docs/gitlab.md`
