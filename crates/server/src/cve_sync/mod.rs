use reqwest::Client;
use serde::Deserialize;
use sqlx::{Pool, Postgres};
use std::env;
use tracing::{error, info};

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

/// Sync all vulnerability data sources.
pub async fn sync_all(pool: &Pool<Postgres>) -> anyhow::Result<()> {
    info!("Starting full CVE synchronization...");

    let client = Client::new();
    sync_nvd(pool, &client).await?;
    sync_osv(pool, &client).await?;

    info!("CVE synchronization completed successfully.");
    Ok(())
}

async fn sync_nvd(pool: &Pool<Postgres>, client: &Client) -> anyhow::Result<()> {
    let api_key = env::var("NVD_API_KEY").ok();
    if api_key.is_none() {
        info!("NVD_API_KEY not set. Running in rate-limited mode.");
    }

    let params = vec![("resultsPerPage", "100".to_string())];
    let url = reqwest::Url::parse_with_params("https://services.nvd.nist.gov/rest/json/cves/2.0", &params)?;
    
    info!("Calling NVD API: {}", url);

    let mut request = client
        .get(url)
        .header("User-Agent", "Zenvra-Scanner/0.1.0");
    
    if let Some(key) = api_key {
        request = request.header("apiKey", key);
    }

    let response: reqwest::Response = request.send().await?;
    
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_else(|_| "Empty body".to_string());
        error!("NVD API error (Status: {}): {}", status, body);
        anyhow::bail!("NVD API returned error status: {}", status);
    }

    let nvd_data = response.json::<NvdResponse>().await?;

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
                v.first()
                    .map(|c| c.cvss_data.base_severity.to_lowercase())
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
            "#
        )
        .bind(&id)
        .bind(format!("Vulnerability {}", id))
        .bind(&description)
        .bind(&severity)
        .bind("nvd")
        .execute(pool)
        .await?;
    }

    info!("NVD sync completed.");
    Ok(())
}

async fn sync_osv(_pool: &Pool<Postgres>, _client: &Client) -> anyhow::Result<()> {
    info!("OSV sync pending implementation.");
    Ok(())
}
