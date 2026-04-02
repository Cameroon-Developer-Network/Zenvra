# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-mvp] - 2026-04-02

### Added
- **API Server (`crates/server`)**: A new Axum-based REST API to bridge the scanner with the web.
- **SvelteKit 5 Frontend (`apps/web`)**: A premium, dark-mode dashboard with glassmorphism aesthetics.
- **Multi-AI Provider UI**: Support for switching AI providers (Anthropic, OpenAI, Google, Custom) directly from the scan interface.
- **Interactive Scan Workbench**: A code editor area for real-time vulnerability analysis.
- **Secrets Detection Engine**: Integrated 17+ regex patterns for cloud/API secrets with redaction.
- **Expanded SAST Rules**: Initial rules for SQL Injection and OS Command Injection.
- **Automated Release Workflow**: GitHub Actions to build and release the CLI binary on tag.

### Fixed
- **Vite 6 / Svelte 5 SSR**: Resolved CSS compilation and SSR "css is not a function" errors by optimizing Tailwind v4 usage and disabling SSR in dev mode.
- **Security**: Sanitized dummy secrets in test fixtures to comply with GitHub Push Protection.
- **Project Structure**: Consolidated workspace members and synchronized dependency versions.
