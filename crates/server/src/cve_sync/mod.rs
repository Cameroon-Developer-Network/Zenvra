use reqwest::Client;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use std::env;
use tracing::{error, info, warn};

// ── NVD API types ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct NvdResponse {
    #[serde(rename = "vulnerabilities")]
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnerability {
    cve: CveData,
}

#[derive(Debug, Deserialize)]
struct CveData {
    id: String,
    descriptions: Vec<Description>,
    metrics: Option<Metrics>,
}

#[derive(Debug, Deserialize)]
struct Description {
    value: String,
}

#[derive(Debug, Deserialize)]
struct Metrics {
    #[serde(rename = "cvssMetricV31")]
    cvss_v31: Option<Vec<CvssMetricV31>>,
}

#[derive(Debug, Deserialize)]
struct CvssMetricV31 {
    #[serde(rename = "cvssData")]
    cvss_data: CvssData,
}

#[derive(Debug, Deserialize)]
struct CvssData {
    #[serde(rename = "baseSeverity")]
    base_severity: String,
}

// ── OSV API types ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct OsvQueryRequest {
    package: OsvPackageRef,
}

#[derive(Debug, Serialize)]
struct OsvPackageRef {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvQueryResponse {
    vulns: Option<Vec<OsvVuln>>,
}

#[derive(Debug, Deserialize)]
struct OsvVuln {
    id: String,
    summary: Option<String>,
    aliases: Option<Vec<String>>,
    severity: Option<Vec<OsvSeverity>>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    r#type: String,
    score: String,
}

// ── Well-known vulnerable packages used to seed the local DB ─────────────────

/// Pairs of (ecosystem, package_name) to query on each sync.
/// Covers commonly vulnerable packages across major ecosystems.
const SEED_PACKAGES: &[(&str, &str)] = &[
    // npm
    ("npm", "lodash"),
    ("npm", "minimist"),
    ("npm", "node-fetch"),
    ("npm", "axios"),
    ("npm", "express"),
    ("npm", "json5"),
    ("npm", "qs"),
    ("npm", "semver"),
    ("npm", "path-to-regexp"),
    ("npm", "ws"),
    // PyPI
    ("PyPI", "Django"),
    ("PyPI", "Flask"),
    ("PyPI", "Pillow"),
    ("PyPI", "cryptography"),
    ("PyPI", "requests"),
    ("PyPI", "PyYAML"),
    ("PyPI", "paramiko"),
    ("PyPI", "sqlalchemy"),
    ("PyPI", "urllib3"),
    ("PyPI", "certifi"),
    // Go
    ("Go", "github.com/gin-gonic/gin"),
    ("Go", "golang.org/x/crypto"),
    ("Go", "golang.org/x/net"),
    ("Go", "github.com/golang-jwt/jwt"),
    ("Go", "gopkg.in/yaml.v3"),
    // crates.io
    ("crates.io", "openssl"),
    ("crates.io", "rustls"),
    ("crates.io", "hyper"),
    ("crates.io", "tokio"),
    ("crates.io", "serde"),
    // Maven
    ("Maven", "log4j-core"),
    ("Maven", "spring-core"),
    ("Maven", "commons-collections"),
    ("Maven", "jackson-databind"),
];

/// Sync all vulnerability data sources.
pub async fn sync_all(pool: &Pool<Postgres>) -> anyhow::Result<()> {
    info!("Starting full CVE synchronization...");

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("Zenvra-Scanner/0.1.0")
        .build()?;

    sync_nvd(pool, &client).await?;
    sync_osv(pool, &client).await?;

    info!("CVE synchronization completed successfully.");
    Ok(())
}

// ── NVD sync ─────────────────────────────────────────────────────────────────

async fn sync_nvd(pool: &Pool<Postgres>, client: &Client) -> anyhow::Result<()> {
    let api_key = env::var("NVD_API_KEY").ok();
    if api_key.is_none() {
        info!("NVD_API_KEY not set. Running in rate-limited mode.");
    }

    let params = vec![("resultsPerPage", "100".to_string())];
    let url = reqwest::Url::parse_with_params(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        &params,
    )?;

    info!("Calling NVD API: {}", url);

    let mut request = client.get(url).header("User-Agent", "Zenvra-Scanner/0.1.0");

    if let Some(key) = api_key {
        request = request.header("apiKey", key);
    }

    let response: reqwest::Response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "Empty body".to_string());
        error!("NVD API error (Status: {}): {}", status, body);
        anyhow::bail!("NVD API returned error status: {}", status);
    }

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !content_type.contains("application/json") {
        let body = response.text().await.unwrap_or_default();
        error!("NVD API returned non-JSON response: {}", body);
        anyhow::bail!("NVD API returned non-JSON response");
    }

    let nvd_data = response.json::<NvdResponse>().await?;
    let mut upserted = 0usize;

    for item in nvd_data.vulnerabilities {
        let cve = item.cve;
        let id = cve.id;
        let description = cve
            .descriptions
            .first()
            .map(|d| d.value.clone())
            .unwrap_or_default();
        let severity = cve
            .metrics
            .and_then(|m| m.cvss_v31)
            .and_then(|v: Vec<CvssMetricV31>| {
                v.first().map(|c| c.cvss_data.base_severity.to_lowercase())
            })
            .unwrap_or_else(|| "medium".to_string());

        sqlx::query(
            r#"
            INSERT INTO vulnerabilities (cve_id, title, description, severity, data_source)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (cve_id) DO UPDATE SET
                description = EXCLUDED.description,
                severity = EXCLUDED.severity,
                updated_at = CURRENT_TIMESTAMP
            "#,
        )
        .bind(&id)
        .bind(format!("Vulnerability {}", id))
        .bind(&description)
        .bind(&severity)
        .bind("nvd")
        .execute(pool)
        .await?;

        upserted += 1;
    }

    info!("NVD sync completed. Upserted {} CVEs.", upserted);
    Ok(())
}

// ── OSV sync ──────────────────────────────────────────────────────────────────

async fn sync_osv(pool: &Pool<Postgres>, client: &Client) -> anyhow::Result<()> {
    info!(
        "Starting OSV synchronization for {} seed packages...",
        SEED_PACKAGES.len()
    );

    let mut total = 0usize;

    for (ecosystem, package_name) in SEED_PACKAGES {
        match fetch_osv_vulns(client, ecosystem, package_name).await {
            Ok(vulns) => {
                for vuln in vulns {
                    // Extract a CVE alias if available, otherwise use OSV ID.
                    let cve_id = vuln
                        .aliases
                        .as_ref()
                        .and_then(|aliases| aliases.iter().find(|a| a.starts_with("CVE-")))
                        .cloned()
                        .unwrap_or_else(|| vuln.id.clone());

                    let severity = vuln
                        .severity
                        .as_deref()
                        .and_then(|s| s.iter().find(|e| e.r#type.contains("CVSS")))
                        .map(|s| cvss_score_to_severity(&s.score))
                        .unwrap_or("medium");

                    let description = vuln
                        .summary
                        .clone()
                        .unwrap_or_else(|| format!("Vulnerability in {}", package_name));

                    let result = sqlx::query(
                        r#"
                        INSERT INTO vulnerabilities
                            (cve_id, title, description, severity, data_source, ecosystem, package_name)
                        VALUES ($1, $2, $3, $4, $5, $6, $7)
                        ON CONFLICT (cve_id) DO UPDATE SET
                            description   = EXCLUDED.description,
                            severity      = EXCLUDED.severity,
                            ecosystem     = EXCLUDED.ecosystem,
                            package_name  = EXCLUDED.package_name,
                            updated_at    = CURRENT_TIMESTAMP
                        "#,
                    )
                    .bind(&cve_id)
                    .bind(format!("{} ({}@{})", vuln.id, package_name, ecosystem))
                    .bind(&description)
                    .bind(severity)
                    .bind("osv")
                    .bind(ecosystem)
                    .bind(package_name)
                    .execute(pool)
                    .await;

                    match result {
                        Ok(_) => total += 1,
                        Err(e) => warn!("Failed to upsert OSV vuln {}: {}", cve_id, e),
                    }
                }
            }
            Err(e) => {
                warn!("OSV fetch failed for {}/{}: {}", ecosystem, package_name, e);
            }
        }
    }

    info!("OSV sync completed. Upserted {} advisories.", total);
    Ok(())
}

/// Query the OSV `/v1/query` endpoint for a specific package.
async fn fetch_osv_vulns(
    client: &Client,
    ecosystem: &str,
    package_name: &str,
) -> anyhow::Result<Vec<OsvVuln>> {
    let body = OsvQueryRequest {
        package: OsvPackageRef {
            name: package_name.to_string(),
            ecosystem: ecosystem.to_string(),
        },
    };

    let response = client
        .post("https://api.osv.dev/v1/query")
        .json(&body)
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("OSV API returned {}", response.status());
    }

    let result: OsvQueryResponse = response.json().await?;
    Ok(result.vulns.unwrap_or_default())
}

/// Convert a CVSS score string like "7.5" to a severity label.
fn cvss_score_to_severity(score: &str) -> &'static str {
    let n: f32 = score.split('/').next().and_then(|s| s.parse().ok()).unwrap_or(5.0);
    if n >= 9.0 {
        "critical"
    } else if n >= 7.0 {
        "high"
    } else if n >= 4.0 {
        "medium"
    } else {
        "low"
    }
}
