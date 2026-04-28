//! SCA engine — software composition analysis.
//!
//! Parses lockfiles (`Cargo.lock`, `package-lock.json`, `requirements.txt`,
//! `go.sum`, `pom.xml`) and queries the [OSV.dev batch API](https://osv.dev/docs/)
//! for known CVEs.  Returns `RawFinding`s with `Engine::Sca` and real CVE IDs
//! wherever available.

use crate::{
    finding::{RawFinding, Severity},
    Engine, ScanConfig,
};
use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};

// ── OSV API types ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct OsvBatchRequest {
    queries: Vec<OsvQuery>,
}

#[derive(Debug, Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

#[derive(Debug, Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvQueryResult>,
}

#[derive(Debug, Deserialize)]
struct OsvQueryResult {
    vulns: Option<Vec<OsvVuln>>,
}

#[derive(Debug, Deserialize, Clone)]
struct OsvVuln {
    id: String,
    summary: Option<String>,
    severity: Option<Vec<OsvSeverity>>,
    aliases: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
struct OsvSeverity {
    r#type: String,
    score: String,
}

// ── Parsed dependency ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Dependency {
    name: String,
    version: String,
    ecosystem: String,
}

// ── Lockfile parsers ──────────────────────────────────────────────────────────

/// Detect the lockfile type from the file path and content, then parse dependencies.
fn parse_dependencies(config: &ScanConfig) -> Vec<Dependency> {
    let path = config.file_path.as_deref().unwrap_or("");
    let lower = path.to_lowercase();
    let code = &config.code;

    if lower.ends_with("cargo.lock") || code.contains("[[package]]") {
        parse_cargo_lock(code)
    } else if lower.ends_with("package-lock.json") || lower.ends_with("package.json") {
        parse_package_lock(code)
    } else if lower.ends_with("requirements.txt")
        || lower.ends_with("requirements.in")
        || (lower.ends_with(".txt") && code.contains("=="))
    {
        parse_requirements_txt(code)
    } else if lower.ends_with("go.sum") {
        parse_go_sum(code)
    } else if lower.ends_with("pom.xml") || (lower.ends_with(".xml") && code.contains("<groupId>"))
    {
        parse_pom_xml(code)
    } else {
        // Try heuristic detection
        if code.contains("[[package]]") {
            parse_cargo_lock(code)
        } else if code.trim_start().starts_with('{') && code.contains("\"dependencies\"") {
            parse_package_lock(code)
        } else if code.contains("<groupId>") {
            parse_pom_xml(code)
        } else {
            // Fall back to requirements.txt style
            parse_requirements_txt(code)
        }
    }
}

/// Parse `Cargo.lock` — extracts `[[package]]` blocks.
fn parse_cargo_lock(content: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            // Flush previous
            if let (Some(name), Some(version)) = (current_name.take(), current_version.take()) {
                deps.push(Dependency {
                    name,
                    version,
                    ecosystem: "crates.io".to_string(),
                });
            }
        } else if let Some(rest) = line.strip_prefix("name = ") {
            current_name = Some(rest.trim_matches('"').to_string());
        } else if let Some(rest) = line.strip_prefix("version = ") {
            current_version = Some(rest.trim_matches('"').to_string());
        }
    }
    // Flush last
    if let (Some(name), Some(version)) = (current_name, current_version) {
        deps.push(Dependency {
            name,
            version,
            ecosystem: "crates.io".to_string(),
        });
    }
    deps
}

/// Parse `package-lock.json` v2/v3 — extracts `"node_modules/…"` entries.
fn parse_package_lock(content: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    // Regex for simple "version": "x.y.z" inside node_modules entries
    let Ok(re) = Regex::new(r#""node_modules/([^"]+)"[^}]*?"version":\s*"([^"]+)""#) else {
        return deps;
    };
    for cap in re.captures_iter(content) {
        deps.push(Dependency {
            name: cap[1].to_string(),
            version: cap[2].to_string(),
            ecosystem: "npm".to_string(),
        });
    }
    deps
}

/// Parse `requirements.txt` — handles `pkg==1.2.3` and `pkg>=1.2.3` lines.
fn parse_requirements_txt(content: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let Ok(re) = Regex::new(r"^([A-Za-z0-9_.\-]+)\s*[><=!~]+\s*([^\s;#]+)") else {
        return deps;
    };
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(cap) = re.captures(line) {
            deps.push(Dependency {
                name: cap[1].to_string(),
                version: cap[2].to_string(),
                ecosystem: "PyPI".to_string(),
            });
        }
    }
    deps
}

/// Parse `go.sum` — extracts `module@version` pairs (deduplicates by module@version).
fn parse_go_sum(content: &str) -> Vec<Dependency> {
    let mut seen = std::collections::HashSet::new();
    let mut deps = Vec::new();
    let Ok(re) = Regex::new(r"^([^\s]+)@v([^\s/]+)") else {
        return deps;
    };
    for line in content.lines() {
        if let Some(cap) = re.captures(line.trim()) {
            let key = format!("{}@{}", &cap[1], &cap[2]);
            if seen.insert(key) {
                deps.push(Dependency {
                    name: cap[1].to_string(),
                    version: cap[2].to_string(),
                    ecosystem: "Go".to_string(),
                });
            }
        }
    }
    deps
}

/// Parse `pom.xml` — extracts `<artifactId>` / `<version>` pairs.
fn parse_pom_xml(content: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let Ok(dep_re) = Regex::new(
        r"<dependency>\s*(?:<groupId>[^<]*</groupId>)?\s*<artifactId>([^<]+)</artifactId>\s*(?:<version>([^<]+)</version>)?",
    ) else {
        return deps;
    };
    for cap in dep_re.captures_iter(content) {
        let name = cap[1].trim().to_string();
        let version = cap
            .get(2)
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        deps.push(Dependency {
            name,
            version,
            ecosystem: "Maven".to_string(),
        });
    }
    deps
}

// ── OSV severity mapping ──────────────────────────────────────────────────────

/// Map an OSV severity score string (CVSS 0–10) to a `Severity`.
fn map_cvss_severity(score_str: &str) -> Severity {
    // CVSS score may be like "7.5" or just "CVSS:3.1/AV:N/AC:L/..."
    let score: f32 = score_str
        .split('/')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5.0);
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// Extract a CVE alias from the vuln's alias list, or fall back to the OSV ID.
fn extract_cve_id(vuln: &OsvVuln) -> Option<String> {
    if let Some(aliases) = &vuln.aliases {
        if let Some(cve) = aliases.iter().find(|a| a.starts_with("CVE-")) {
            return Some(cve.clone());
        }
    }
    if vuln.id.starts_with("CVE-") {
        return Some(vuln.id.clone());
    }
    None
}

// ── OSV batch query ───────────────────────────────────────────────────────────

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
/// Maximum number of queries per OSV batch request.
const BATCH_SIZE: usize = 100;

/// Query the OSV batch API for a list of dependencies.
async fn query_osv(deps: &[Dependency]) -> Result<Vec<(Dependency, Vec<OsvVuln>)>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let mut results = Vec::new();

    for chunk in deps.chunks(BATCH_SIZE) {
        let queries: Vec<OsvQuery> = chunk
            .iter()
            .map(|d| OsvQuery {
                package: OsvPackage {
                    name: d.name.clone(),
                    ecosystem: d.ecosystem.clone(),
                },
                version: d.version.clone(),
            })
            .collect();

        let body = OsvBatchRequest { queries };

        let response = client.post(OSV_BATCH_URL).json(&body).send().await;

        let response = match response {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("OSV API request failed: {}", e);
                // Return empty results for this chunk rather than aborting
                for dep in chunk {
                    results.push((dep.clone(), vec![]));
                }
                continue;
            }
        };

        if !response.status().is_success() {
            tracing::warn!("OSV API returned status {}", response.status());
            for dep in chunk {
                results.push((dep.clone(), vec![]));
            }
            continue;
        }

        match response.json::<OsvBatchResponse>().await {
            Ok(batch_resp) => {
                for (dep, query_result) in chunk.iter().zip(batch_resp.results.iter()) {
                    let vulns = query_result.vulns.clone().unwrap_or_default();
                    results.push((dep.clone(), vulns));
                }
            }
            Err(e) => {
                tracing::warn!("Failed to parse OSV response: {}", e);
                for dep in chunk {
                    results.push((dep.clone(), vec![]));
                }
            }
        }
    }

    Ok(results)
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Run SCA analysis — parse dependency files and check for known vulnerabilities.
///
/// Supports `Cargo.lock`, `package-lock.json`, `requirements.txt`,
/// `go.sum`, and `pom.xml`.  Queries the OSV.dev batch API and returns
/// a `RawFinding` for every vulnerable dependency.
pub async fn run(config: &ScanConfig) -> Result<Vec<RawFinding>> {
    let deps = parse_dependencies(config);

    if deps.is_empty() {
        tracing::debug!("SCA: no dependencies found in input");
        return Ok(vec![]);
    }

    tracing::info!("SCA: checking {} dependencies against OSV", deps.len());

    let results = query_osv(&deps).await?;
    let mut findings = Vec::new();

    for (dep, vulns) in results {
        for vuln in vulns {
            let cve_id = extract_cve_id(&vuln);
            let severity = vuln
                .severity
                .as_deref()
                .and_then(|sev_list| sev_list.iter().find(|s| s.r#type.contains("CVSS")))
                .map(|s| map_cvss_severity(&s.score))
                .unwrap_or(Severity::Medium);

            let title = vuln
                .summary
                .clone()
                .unwrap_or_else(|| format!("Vulnerability in {}@{}", dep.name, dep.version));

            findings.push(RawFinding {
                engine: Engine::Sca,
                cve_id,
                cwe_id: None,
                severity,
                title: format!(
                    "Vulnerable dependency: {} v{} — {}",
                    dep.name, dep.version, title
                ),
                vulnerable_code: format!("{}@{} ({})", dep.name, dep.version, dep.ecosystem),
                description: Some(format!(
                    "{} (ID: {})",
                    vuln.summary.unwrap_or_default(),
                    vuln.id
                )),
                line_start: 0,
                line_end: 0,
                file_path: config.file_path.clone(),
            });
        }
    }

    tracing::info!("SCA: found {} vulnerable dependencies", findings.len());
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cargo_lock() {
        let content = r#"
[[package]]
name = "anyhow"
version = "1.0.70"

[[package]]
name = "tokio"
version = "1.28.0"
"#;
        let deps = parse_cargo_lock(content);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "anyhow");
        assert_eq!(deps[0].version, "1.0.70");
        assert_eq!(deps[0].ecosystem, "crates.io");
        assert_eq!(deps[1].name, "tokio");
    }

    #[test]
    fn parses_requirements_txt() {
        let content = "requests==2.28.0\nflask>=2.0.0\n# comment\nDjango==3.2.0\n";
        let deps = parse_requirements_txt(content);
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].version, "2.28.0");
        assert_eq!(deps[0].ecosystem, "PyPI");
    }

    #[test]
    fn parses_go_sum_deduplicates() {
        let content = "golang.org/x/text v0.3.7 h1:abc\ngolang.org/x/text v0.3.7/go.mod h1:def\n";
        let deps = parse_go_sum(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "golang.org/x/text");
        assert_eq!(deps[0].version, "0.3.7");
        assert_eq!(deps[0].ecosystem, "Go");
    }

    #[test]
    fn maps_cvss_severity() {
        assert_eq!(map_cvss_severity("9.8"), Severity::Critical);
        assert_eq!(map_cvss_severity("7.5"), Severity::High);
        assert_eq!(map_cvss_severity("5.4"), Severity::Medium);
        assert_eq!(map_cvss_severity("2.1"), Severity::Low);
    }
}
