<div align="center">

# Zenvra

**Ship fast. Ship safe.**

AI-powered code vulnerability scanner — finds security issues in your code, maps them to exact CVEs, and tells you in plain English exactly how to fix them.

Built for everyone: seasoned engineers, indie hackers, and the growing wave of developers building with AI tools (Cursor, Lovable, Bolt, Replit) who need a safety net before going to production.

[![CI](https://github.com/Cameroon-Developer-Network/zenvra/actions/workflows/ci.yml/badge.svg)](https://github.com/Cameroon-Developer-Network/zenvra/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Good First Issues](https://img.shields.io/github/issues/Cameroon-Developer-Network/zenvra/good%20first%20issue)](https://github.com/Cameroon-Developer-Network/zenvra/issues?q=label%3A%22good+first+issue%22)

</div>

---

## The problem Zenvra solves

AI coding tools (Copilot, Claude, Cursor, Lovable, Bolt) are producing millions of lines of code every day. The problem: **45% of AI-generated code contains security vulnerabilities** (Veracode 2025), and most of the people shipping that code have no idea.

Existing security tools (Snyk, SonarQube, CodeQL) were built for large DevSecOps teams. They require complex setup, speak in jargon, and cost money at scale. Nobody built a tool for the developer who just vibe-coded a SaaS product in a weekend and wants to know if it is safe to ship.

That is Zenvra.

---

## What Zenvra does

1. **Scans your code** — static analysis across 30+ languages (Python, JavaScript, TypeScript, Rust, Go, Java, and more)
2. **Scans your dependencies** — finds vulnerable packages and maps them to exact CVE IDs
3. **Finds secrets** — API keys, tokens, and credentials accidentally committed to code
4. **Explains every finding** — in plain English, no security jargon required
5. **Gives you the fix** — a corrected code snippet, not just a warning

```
$ zenvra scan ./my-app

Scanning 47 files...

CRITICAL — SQL Injection (CVE-2025-1234)
  src/db/users.py  line 42

  What happened:
  User input is concatenated directly into a SQL query. An attacker
  can manipulate this to read, modify, or delete your entire database.

  Fix:
  - query = f"SELECT * FROM users WHERE id = {user_id}"
  + query = "SELECT * FROM users WHERE id = ?"
  + cursor.execute(query, (user_id,))

Found 3 issues (1 critical · 1 high · 1 medium) in 1.2s
```

---

## How the scan pipeline works

```
1. File collection   Walk the target, respect .gitignore
         ↓
2. SAST              Semgrep rules → code vulnerabilities
         ↓
3. SCA               Parse lockfiles → OSV/NVD → known CVEs in dependencies
         ↓
4. Secrets           Regex + entropy → exposed credentials
         ↓
5. CVE enrichment    Fetch full CVE details from local cache
         ↓
6. AI enrichment     Claude API → plain-English explanation + corrected code
         ↓
7. Report            Terminal / JSON / HTML / PR comment
```

The `zenvra-scanner` Rust crate owns steps 1–7. The CLI, web API, and VS Code extension are thin wrappers that call into it — logic lives in one place.

---

## Repository structure

```
zenvra/
├── apps/
│   └── web/                    # SvelteKit frontend (dashboard + web scanner)
│       └── src/
│           ├── routes/         # Pages (+page.svelte, +layout.svelte)
│           ├── lib/            # API client, shared utilities
│           └── components/     # Reusable Svelte components
│
├── crates/
│   ├── scanner/                # Rust — core scan engine
│   │   └── src/
│   │       ├── lib.rs          # Public types: Finding, Severity, ScanResult
│   │       ├── engines/
│   │       │   ├── sast.rs     # SAST via Semgrep subprocess
│   │       │   ├── sca.rs      # Dependency scanning via OSV API
│   │       │   └── secrets.rs  # Regex + entropy secret detection
│   │       ├── cve/            # NVD/OSV/GHSA client + local cache
│   │       ├── ai/             # Claude API: explanations + fix generation
│   │       ├── api/            # Axum HTTP handlers
│   │       └── report/         # Output formatters (terminal, JSON, HTML)
│   │
│   └── cli/                    # Rust — `zenvra` binary
│       └── src/main.rs         # clap commands: scan, auth
│
├── extensions/
│   └── vscode/                 # VS Code extension (TypeScript)
│       └── src/
│           ├── extension.ts    # Activation entry point
│           ├── scanner.ts      # Calls the Zenvra API
│           └── diagnostics.ts  # Inline squiggles + quick-fix actions
│
├── docs/                       # Architecture docs, API reference, ADRs
├── scripts/                    # Dev helpers, DB seed scripts
├── AGENTS.md                   # AI assistant system prompt — read before coding
├── CONTRIBUTING.md             # Contribution guide
└── .github/
    ├── workflows/
    │   ├── ci.yml              # PR checks: Rust + frontend + extension
    │   └── release.yml         # Builds CLI binaries on git tag push
    └── ISSUE_TEMPLATE/         # Bug, feature, security report templates
```

---

## Tech stack

| Layer | Technology | Why |
|---|---|---|
| Core engine | Rust | Performance, memory safety, single-binary output |
| CLI | Rust + clap | Zero runtime deps, cross-platform |
| Frontend | SvelteKit + TypeScript | Smaller bundles, faster than Next.js, great DX |
| Styling | Tailwind CSS v4 | Consistent, utility-first |
| Database | PostgreSQL + sqlx | Compile-time checked async queries |
| Job queue | Redis | Async scan job processing |
| SAST engine | Semgrep | 30+ languages, extensible YAML rules |
| CVE data | NVD + OSV + GHSA | Comprehensive, updated daily |
| AI layer | Claude API (Anthropic) | Explanations + fix generation |
| VS Code ext | TypeScript | Native VS Code extension API |

---

## Getting started (development)

### Prerequisites

- **Rust** 1.78+ — `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **Node.js** 20+ and **pnpm** — `npm i -g pnpm`
- **Docker + Docker Compose** — for Postgres and Redis
- **Anthropic API key** — [console.anthropic.com](https://console.anthropic.com)

### Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Cameroon-Developer-Network/zenvra.git
   cd zenvra
   ```

2. **Start infrastructure (Postgres & Redis):**
   ```bash
   # Starts only the necessary databases
   docker compose up -d postgres redis
   ```

3. **Configure environment:**
   ```bash
   cp .env.example .env
   # Open .env and add your AI provider keys (Anthropic, OpenAI, or Google)
   # The default DATABASE_URL in .env.example works with the docker setup
   ```

4. **Start the Backend API:**
   ```bash
   cargo run -p zenvra-server
   ```

5. **Start the Dashboard (Frontend):**
   ```bash
   cd apps/web
   npm install  # or pnpm install
   npm run dev
   ```

### Quick Scan via CLI

```bash
cargo run -p zenvra-cli -- scan ./path/to/code
```

### Before every commit

```bash
# Rust
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test --all

# Frontend
cd apps/web && pnpm lint && pnpm check
```

---

## Contributing

Read [CONTRIBUTING.md](./CONTRIBUTING.md) and [AGENTS.md](./AGENTS.md) before opening a PR.

- `main` is protected — all changes go through pull requests
- PRs require: 1 approving review + all CI checks passing
- Browse [open issues](https://github.com/Cameroon-Developer-Network/zenvra/issues) to find something to work on
- Issues labelled **`good first issue`** are newcomer-friendly
- Issues labelled **`help wanted`** are actively needed

---

## Roadmap

| Milestone | Focus |
|---|---|
| **v0.1.0** | CLI tool, core scan engine, web paste UI, GitHub Action |
| **v0.2.0** | User accounts, scan history, VS Code extension, team workspaces |
| **v0.3.0** | Auto-fix PRs, SBOM generation, Slack/Jira alerts, compliance reports |
| **v1.0.0** | Proprietary AI-code vuln database, Zenvra Score, platform integrations |

---

## License

MIT — see [LICENSE](./LICENSE)

Built by the [Cameroon Developer Network](https://github.com/Cameroon-Developer-Network).
