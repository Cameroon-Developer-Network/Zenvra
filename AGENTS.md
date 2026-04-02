# Zenvra — AI Agent Context

> This file is the system prompt for any AI assistant (Claude, Cursor, Copilot, etc.) working on this repository.
> Read this entire file before writing any code, suggesting any change, or answering any question about Zenvra.

---

## What Zenvra Is

Zenvra (`zenvra.dev`) is an AI-powered code vulnerability scanner. It scans code for security vulnerabilities, maps findings to exact CVE identifiers, explains the risk in plain English, and generates corrected code — in seconds.

**Tagline:** Ship fast. Ship safe.

**Target users:** Solo developers, vibe coders (non-developers building with AI tools), startups, and enterprise security teams.

**Core problem we solve:** 45% of AI-generated code contains security vulnerabilities (Veracode 2025). The people generating this code — often non-developers — have no idea. Existing tools like Snyk and SonarQube are built for security engineers, not for someone who built a SaaS in a weekend with Lovable or Cursor. Zenvra bridges that gap.

---

## Repository Structure

```
zenvra/
├── apps/
│   └── web/              # Next.js 15 frontend — scanner UI, dashboard, auth, billing
├── crates/
│   ├── scanner/          # Rust core: SAST engine, SCA, secrets detection, CVE lookup
│   └── cli/              # Rust CLI: `zenvra scan`, `zenvra report`, `zenvra auth`
├── extensions/
│   └── vscode/           # VS Code extension: inline diagnostics, hover fixes
├── docs/                 # Markdown documentation
└── scripts/              # Shell scripts for dev setup and CI
```

---

## Tech Stack (Non-Negotiable Choices)

| Layer | Technology | Notes |
|-------|-----------|-------|
| Frontend | Next.js 15, TypeScript, Tailwind CSS | App Router. No Pages Router. |
| UI components | shadcn/ui | Installed in apps/web/components/ui |
| Backend API | Rust, Axum | REST + SSE for streaming scan results |
| Scan engine | Rust, Semgrep (via subprocess) | Custom rules in crates/scanner/rules/ |
| Secrets detection | Rust, Gitleaks patterns | Compiled regex patterns |
| AI explanations | Anthropic Claude API (claude-sonnet-4-20250514) | For CVE explanations and fix generation only |
| CVE database | NVD + OSV + GitHub Advisory DB | Synced daily via cron in scripts/sync-cve.sh |
| Database | PostgreSQL 16 | Diesel ORM in Rust, Prisma in Next.js |
| Cache / Queue | Redis 7 | Scan jobs via a simple queue pattern |
| Auth | NextAuth.js v5 | GitHub + Google OAuth + email magic link |
| Payments | Stripe | Subscription billing |
| CLI | Rust, Clap v4 | Produces single static binary |
| VS Code ext | TypeScript, VS Code Extension API | LSP-style diagnostics |

---

## Coding Rules — Always Follow These

### Rust
- All public functions MUST have doc comments (`///`)
- Use `thiserror` for error types — never `.unwrap()` in library code
- Use `anyhow` in binary crates (cli) for error propagation
- Run `cargo fmt` and `cargo clippy -- -D warnings` before finishing
- Async runtime: `tokio` with `#[tokio::main]`
- Tests in `#[cfg(test)]` modules at bottom of each file
- No `unsafe` without a comment explaining exactly why it's safe

### TypeScript / Next.js
- TypeScript strict mode is ON — no `any`, no `@ts-ignore`
- Named exports everywhere except Next.js page components
- Server Components by default; add `"use client"` only when needed
- API routes live in `apps/web/src/app/api/`
- No secrets or API keys ever in client-side code
- All fetch calls go through typed API client functions in `apps/web/src/lib/api.ts`
- Components max 200 lines — split into smaller ones if larger
- zod for all form and API input validation

### General
- Commit messages: Conventional Commits format (`feat:`, `fix:`, `chore:`, `docs:`, `test:`)
- Never commit `.env` files
- Every new user-facing feature needs at least one integration test
- Security is the product — be extra paranoid about input validation, especially in the scanner

---

## Scan Pipeline (How It Works)

```
User submits code (web / CLI / VS Code / GitHub Action)
    ↓
API validates input + queues scan job (Redis)
    ↓
Rust scanner worker picks up job:
    ├── SAST: run Semgrep with Zenvra ruleset
    ├── SCA: parse dependency files → query OSV/NVD API
    └── Secrets: scan with Gitleaks regex patterns
    ↓
Raw findings → CVE lookup (local DB + NVD fallback)
    ↓
Claude API: generate plain-English explanation + corrected code
    ↓
Results stored in PostgreSQL, streamed to client via SSE
    ↓
User sees: severity badge + CVE ID + explanation + fix + shareable card
```

---

## Key Domain Types (Rust)

```rust
pub struct ScanJob {
    pub id: Uuid,
    pub code: String,
    pub language: Language,
    pub engines: Vec<ScanEngine>, // Sast, Sca, Secrets
    pub created_at: DateTime<Utc>,
}

pub struct Finding {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub engine: ScanEngine,
    pub cve_id: Option<String>,      // e.g. "CVE-2025-12345"
    pub cwe_id: Option<String>,      // e.g. "CWE-89"
    pub severity: Severity,          // Critical, High, Medium, Low, Info
    pub title: String,
    pub explanation: String,         // AI-generated plain English
    pub vulnerable_code: String,
    pub fixed_code: String,          // AI-generated corrected version
    pub line_start: u32,
    pub line_end: u32,
    pub file_path: Option<String>,
}

pub enum Severity { Critical, High, Medium, Low, Info }
pub enum ScanEngine { Sast, Sca, Secrets, AiCode }
pub enum Language { Python, JavaScript, TypeScript, Rust, Go, Java, /* ... */ }
```

---

## Environment Variables

Required in `.env` (see `.env.example`):

```
# API
DATABASE_URL=postgresql://localhost:5432/zenvra
REDIS_URL=redis://localhost:6379

# AI
ANTHROPIC_API_KEY=sk-ant-...

# CVE feeds
NVD_API_KEY=...

# Auth (Next.js)
NEXTAUTH_SECRET=...
NEXTAUTH_URL=http://localhost:3000
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...

# Payments
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
```

---

## What NOT to Do

- Do NOT use `unwrap()` or `expect()` in library/API code
- Do NOT put business logic in React components — it goes in server actions or API routes
- Do NOT call the Claude API for anything other than explanation + fix generation (it's expensive)
- Do NOT store raw code in the database longer than needed — scan results only
- Do NOT add dependencies without discussion — keep the dependency tree lean
- Do NOT break the existing API contract without a migration plan
- Do NOT write a new Semgrep rule without a corresponding test case in `crates/scanner/tests/`

---

## Current Status

This repository is in **initial setup phase**. The structure, CI, and issue templates are being established. No production code exists yet. First milestone: working web paste scanner (MVP).

When in doubt about a decision, open a GitHub Discussion rather than assuming. We build deliberately.

---

*Last updated: April 2026 · Maintained by Cameroon Developer Network*
