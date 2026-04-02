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
│   └── web/              # SvelteKit 5 frontend — scanner UI, dashboard, auth, billing
├── crates/
│   ├── scanner/          # Rust core: SAST engine, SCA, secrets detection, CVE lookup, AI provider layer
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
| Frontend | SvelteKit 5, TypeScript, Tailwind CSS v4 | File-based routing. Svelte 5 runes syntax. |
| Backend API | Rust, Axum | REST + SSE for streaming scan results |
| Scan engine | Rust, Semgrep (via subprocess) | Custom rules in crates/scanner/rules/ |
| Secrets detection | Rust, compiled regex patterns | Gitleaks-inspired patterns |
| AI explanations | Multi-provider (Anthropic, OpenAI, Google, custom) | Bring-your-own-key supported. See AI Provider section. |
| CVE database | NVD + OSV + GitHub Advisory DB | Synced daily via cron in scripts/sync-cve.sh |
| Database | PostgreSQL 16, sqlx | Compile-time checked async queries |
| Cache / Queue | Redis 7 | Scan jobs via a simple queue pattern |
| Auth | TBD (SvelteKit-based) | GitHub + Google OAuth |
| Payments | Stripe | Subscription billing |
| CLI | Rust, Clap v4 | Produces single static binary |
| VS Code ext | TypeScript, VS Code Extension API | LSP-style diagnostics |

---

## AI Provider System

Zenvra supports multiple AI providers for generating vulnerability explanations and fix suggestions. Users can bring their own API key and even configure custom endpoints.

### Supported Providers

| Provider | Models | Notes |
|----------|--------|-------|
| Anthropic | claude-sonnet-4-20250514, etc. | Default provider |
| OpenAI | gpt-4o, gpt-4o-mini, etc. | Also works for OpenAI-compatible APIs (Groq, Together, etc.) |
| Google | gemini-2.0-flash, etc. | Gemini generateContent API |
| Custom | User-defined | Any endpoint with OpenAI-compatible API format |

### Configuration

```env
AI_PROVIDER=anthropic          # anthropic | openai | google | custom
AI_API_KEY=sk-ant-...          # API key for the chosen provider
AI_MODEL=claude-sonnet-4-20250514   # Model identifier
AI_ENDPOINT=                   # Only needed for custom provider or non-default endpoints
```

### Architecture

The `AiProvider` trait in `crates/scanner/src/ai/` defines the interface:

```rust
#[async_trait]
pub trait AiProvider: Send + Sync {
    async fn explain(&self, finding: &RawFinding) -> Result<String>;
    async fn generate_fix(&self, finding: &RawFinding) -> Result<String>;
}
```

Each provider (`AnthropicProvider`, `OpenAiProvider`, `GoogleProvider`, `CustomProvider`) implements this trait. Provider selection is config-driven via `AiConfig`.

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

### TypeScript / SvelteKit
- TypeScript strict mode is ON — no `any`, no `@ts-ignore`
- Named exports everywhere except SvelteKit page/layout components
- Use Svelte 5 runes syntax (`$state`, `$derived`, `$effect`, `$props`)
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
    └── Secrets: scan with compiled regex patterns
    ↓
Raw findings → CVE lookup (local DB + NVD fallback)
    ↓
AI Provider: generate plain-English explanation + corrected code
    ↓
Results stored in PostgreSQL, streamed to client via SSE
    ↓
User sees: severity badge + CVE ID + explanation + fix + shareable card
```

---

## Key Domain Types (Rust)

```rust
pub struct ScanConfig {
    pub code: String,
    pub language: Language,
    pub engines: Vec<Engine>,
    pub ai_config: Option<AiConfig>,
}

pub struct Finding {
    pub id: Uuid,
    pub engine: Engine,
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
pub enum Engine { Sast, Sca, Secrets, AiCode }
pub enum Language { Python, JavaScript, TypeScript, Rust, Go, Java, /* ... */ }
```

---

## Environment Variables

Required in `.env` (see `.env.example`):

```
# API
DATABASE_URL=postgresql://localhost:5432/zenvra
REDIS_URL=redis://localhost:6379

# AI Provider (multi-provider — see AI Provider System section)
AI_PROVIDER=anthropic
AI_API_KEY=sk-ant-...
AI_MODEL=claude-sonnet-4-20250514
AI_ENDPOINT=

# CVE feeds
NVD_API_KEY=...

# Auth (SvelteKit)
AUTH_SECRET=change-me-in-production
AUTH_URL=http://localhost:5173
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...

# Payments
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
```

---

## What NOT to Do

- Do NOT use `unwrap()` or `expect()` in library/API code
- Do NOT put business logic in Svelte components — it goes in server-side load functions or API routes
- Do NOT call the AI API for anything other than explanation + fix generation (it's expensive)
- Do NOT store raw code in the database longer than needed — scan results only
- Do NOT add dependencies without discussion — keep the dependency tree lean
- Do NOT break the existing API contract without a migration plan
- Do NOT write a new Semgrep rule without a corresponding test case in `crates/scanner/tests/`

---

## Current Status

This repository is in **active MVP development**. The scan engine foundation, multi-AI provider system, and secrets detection are being built. First milestone: working CLI scanner + web paste UI.

When in doubt about a decision, open a GitHub Discussion rather than assuming. We build deliberately.

---

*Last updated: April 2026 · Maintained by Cameroon Developer Network*
