# Contributing to Zenvra

Thank you for helping make code safer for everyone. This guide covers everything you need to contribute effectively.

---

## Branch Strategy

```
main          ← production-only. Protected. No direct pushes ever.
develop       ← integration branch. All PRs merge here first.
feature/*     ← new features (e.g. feature/vscode-inline-fix)
fix/*         ← bug fixes (e.g. fix/sca-false-positive-npm)
chore/*       ← maintenance (e.g. chore/update-nvd-feed)
docs/*        ← documentation only
```

**Golden rule:** Open your PR against `develop`. The `develop → main` merge only happens on releases.

---

## Workflow

1. **Pick an issue** — check the [Issues tab](https://github.com/Cameroon-Developer-Network/zenvra/issues) and comment to claim it
2. **Branch off `develop`**
   ```bash
   git checkout develop && git pull
   git checkout -b feature/your-feature-name
   ```
3. **Write code** — follow the style guide below
4. **Test locally** — all CI checks must pass
5. **Open a PR** — fill out the PR template completely
6. **Get reviewed** — at least 1 approval required before merge
7. **Squash merge** into `develop`

---

## Code Style

### Rust (crates/)
- Run `cargo fmt` before committing
- Run `cargo clippy -- -D warnings` — no clippy warnings allowed
- Write doc comments on all public functions
- Tests go in a `#[cfg(test)]` module at the bottom of each file

### TypeScript (apps/web/, extensions/vscode/)
- Run `pnpm lint` and `pnpm typecheck` before committing
- Use named exports — no default exports except page components
- Keep components under 200 lines; split if larger

### General
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
  `feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`
- Never commit secrets, `.env` files, or API keys
- Every new feature needs at least one test

---

## Running Tests

```bash
# Rust
cargo test --workspace

# Frontend
cd apps/web && pnpm test

# VS Code extension
cd extensions/vscode && pnpm test
```

---

## Reporting Security Issues in Zenvra Itself

If you find a vulnerability **in Zenvra**, do not open a public issue.
Use the [Security Report template](.github/ISSUE_TEMPLATE/security_report.yml) or email **security@zenvra.dev**.

---

## Code of Conduct

Be kind. Be constructive. We're building something together.
