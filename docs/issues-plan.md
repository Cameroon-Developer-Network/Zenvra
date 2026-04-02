# Zenvra — GitHub Issues Plan

This document tracks all planned GitHub issues by milestone.
Create these in order — each depends on the previous ones.

---

## Milestone 0 — Repository Setup (this week)

| # | Title | Labels | Description |
|---|-------|--------|-------------|
| 1 | chore: configure branch protection rules on main | chore, component:ci | Set main to require: 1 PR approval, all CI checks pass, no direct push |
| 2 | chore: sync GitHub labels from .github/labels.yml | chore, component:ci | Run github-label-sync to create all labels |
| 3 | chore: create GitHub team structure (core, rust, frontend, security) | chore | Create the four teams referenced in CODEOWNERS |
| 4 | docs: write environment setup guide | documentation | Expand docs/environment.md with full local dev walkthrough |

---

## Milestone 1 — MVP Scanner (weeks 1–8)

| # | Title | Labels | Description |
|---|-------|--------|-------------|
| 5 | feat: web scanner UI — code editor + language selector | enhancement, component:web, priority:high | Monaco/CodeMirror editor, language dropdown, "Scan" button |
| 6 | feat: Rust API server skeleton (Axum) | enhancement, component:scanner, priority:high | POST /api/scan endpoint, request validation, job queuing |
| 7 | feat: SAST engine — Semgrep integration | enhancement, component:scanner, priority:high | Subprocess call to Semgrep, parse SARIF output, map to Finding type |
| 8 | feat: secrets detection engine | enhancement, component:scanner, priority:high | Gitleaks regex patterns for API keys, AWS creds, JWT secrets |
| 9 | feat: CVE lookup — NVD + OSV API integration | enhancement, component:scanner, priority:high | Given a CWE/package finding, look up related CVEs |
| 10 | feat: Claude API integration for explanations + fixes | enhancement, component:scanner, priority:high | Call Claude to generate plain-English explanation and fixed code |
| 11 | feat: scan results UI — finding cards | enhancement, component:web, priority:high | Severity badge, CVE ID, explanation, diff view, fix button |
| 12 | feat: SSE streaming — stream results as they arrive | enhancement, component:web, priority:medium | Don't wait for full scan; stream findings card by card |
| 13 | feat: shareable scan badge card | enhancement, component:web, priority:medium | Generate OG image card: "Zenvra found X CVEs in 4s" — shareable on socials |
| 14 | feat: CLI scan command implementation | enhancement, component:cli, priority:medium | Wire up `zenvra scan` to call the API, display colored terminal output |
| 15 | feat: GitHub Action — scan on PR | enhancement, component:ci, priority:medium | Action that runs zenvra scan and posts inline PR review comments |

---

## Milestone 2 — Auth + Accounts (weeks 9–12)

| # | Title | Labels | Description |
|---|-------|--------|-------------|
| 16 | feat: NextAuth.js setup — GitHub + Google OAuth | enhancement, component:web | Auth provider configuration, session management |
| 17 | feat: user dashboard — scan history | enhancement, component:web | List of past scans, click to view full report |
| 18 | feat: API token management | enhancement, component:web | Generate, rotate, revoke CLI tokens in settings page |
| 19 | feat: free tier limits (50 scans/month) | enhancement, component:scanner | Rate limiting per user/IP, gate private repo scanning |

---

## Milestone 3 — VS Code Extension (weeks 13–16)

| # | Title | Labels | Description |
|---|-------|--------|-------------|
| 20 | feat: VS Code extension — scan on save | enhancement, component:vscode | Call Zenvra API on file save, show inline diagnostics |
| 21 | feat: VS Code extension — hover card | enhancement, component:vscode | Hover over underlined code to see CVE, severity, explanation |
| 22 | feat: VS Code extension — quick fix | enhancement, component:vscode | Apply AI-generated fix with one click from the lightbulb menu |
| 23 | feat: VS Code extension — marketplace publish | enhancement, component:vscode | Package and publish to VS Code Marketplace |

---

## Standing issues (always open)

| Title | Labels |
|-------|--------|
| Add Semgrep rule: [vulnerability type] | enhancement, component:scanner, good-first-issue |
| Improve CVE explanation for [CVE ID] | enhancement, good-first-issue |
| Add language support: [language] | enhancement, component:scanner |
