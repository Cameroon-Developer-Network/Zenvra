# Zenvra — GitHub Issues Plan

This document lists every issue to create in the GitHub repo. Copy each one into GitHub Issues exactly as written.

---

## v0.1.0 — MVP (ship the core scanner)

| # | Title | Labels | Good first issue? |
|---|---|---|---|
| 1 | Rust workspace setup + zenvra-scanner crate skeleton | `area: scanner` `priority: critical` | ✅ Yes |
| 2 | SAST engine: Semgrep integration | `area: scanner` `priority: critical` | — |
| 3 | Secrets scanner: regex + entropy detection | `area: scanner` `priority: critical` | — |
| 4 | SCA engine: lockfile parsing + OSV API | `area: scanner` `priority: critical` | — |
| 5 | CVE enrichment: NVD local cache | `area: scanner` `priority: high` | — |
| 6 | AI enrichment: Claude API integration | `area: scanner` `priority: critical` | — |
| 7 | CLI tool: `zenvra scan` command | `area: cli` `priority: critical` | — |
| 8 | Web UI: SvelteKit scanner interface | `area: web` `priority: critical` | — |
| 9 | GitHub Action: PR annotations | `area: cli` `priority: high` | — |
| 10 | Shareable scan badge (viral mechanic) | `area: web` `priority: high` | — |
| 12 | Docker Compose dev environment | `area: scanner` `type: dx` | ✅ Yes |
| 13 | Database migrations: initial schema | `area: scanner` `priority: critical` | ✅ Yes |
| 15 | CONTRIBUTING.md + developer docs | `type: dx` | ✅ Yes |

## v0.2.0 — Platform

| # | Title | Labels | Notes |
|---|---|---|---|
| 11 | VS Code extension: inline diagnostics | `area: vscode` | Needs #8 |
| 14 | Semgrep custom rules for AI-generated code | `area: scanner` `help wanted` | Zenvra's moat |
| 16 | GitLab CI integration | `area: cli` | Mirrors #9 |
| 17 | User accounts + API token auth | `area: web` `area: scanner` | |
| 18 | Scan history dashboard | `area: web` | |
| 19 | Team workspaces | `area: web` | |

## Labels to create in GitHub

```
area: scanner    #7c3aed  (purple)
area: cli        #4f46e5  (indigo)
area: web        #0284c7  (blue)
area: vscode     #0891b2  (cyan)

type: bug        #dc2626  (red)
type: feature    #16a34a  (green)
type: security   #ea580c  (orange)
type: dx         #ca8a04  (yellow)

priority: critical   #991b1b
priority: high       #c2410c
priority: medium     #92400e

good first issue     #bbf7d0  (light green)
help wanted          #fef08a  (light yellow)
needs triage         #e2e8f0  (light gray)
```

## Issue dependencies (order to tackle)

```
#12 (Docker) → #13 (DB schema)
      ↓
#1 (Workspace) → #2 (SAST) ──┐
              → #3 (Secrets) ├──→ #7 (CLI) → #9 (GitHub Action)
              → #4 (SCA) ────┘
              → #5 (CVE) → #6 (AI) → #8 (Web UI) → #10 (Badge)
                                                   → #11 (VS Code)
#15 (Docs) — can be done any time
```
