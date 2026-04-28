---
name: Feature Request
about: Implement CVE synchronization and finalize API configuration
title: 'feat: Implement CVE synchronization and NVD/OSV data integration'
labels: enhancement, needs-triage
assignees: ''
---

### Which area does this relate to?
- API
- CVE explanations / AI layer

### What problem does this solve?
Currently, the scanner relies on pattern matching but does not have a local, searchable database of real-world CVEs. To provide "next-level" security reporting, we need to sync data from authoritative sources so we can map local findings to exact CVE identifiers, CVSS scores, and official advisories.

### Describe the solution you'd like
1. **CVE Sync Script**: Implement or finalize `scripts/sync-cve.sh` to pull data from:
   - **NVD (NVD API v2)**: Priority for core system vulnerabilities.
   - **OSV**: Priority for package-level (SCA) findings.
2. **Database Schema**: Ensure the PostgreSQL schema in `crates/server` is optimized for fast search/lookup by CWE and file patterns.
3. **API Integration**: Connect the scanner's SCA engine to this local database to provide real-time vulnerability mapping.
4. **Environment Polish**: Ensure `.env` is fully utilized for all API keys and secondary configuration.

### Any alternatives you've considered?
We could call external APIs (like NVD) on every scan, but this would be too slow and would quickly hit rate limits. A local cache/db is essential for performance and reliability.

### How important is this to you?
Important - This is the core "extra value" of Zenvra over a basic linter.

### Before submitting
- [x] I searched existing issues and this has not been requested before
