mod cve_sync;

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use zenvra_scanner::{Finding, Language, ScanConfig};

#[derive(Parser)]
#[command(name = "zenvra-server")]
#[command(about = "Zenvra API Server", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the API server (default)
    Serve,
    /// Synchronize CVE data from NVD/OSV
    Sync,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScanRequest {
    code: String,
    language: String,
    engines: Vec<String>,
    ai_config: Option<zenvra_scanner::ai::AiConfig>,
}

struct AppState {
    db: sqlx::PgPool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("zenvra_server=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    // Database connection
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(20) // Expanded for concurrency
        .connect(&db_url)
        .await?;

    // Run migrations
    tracing::info!("Running database migrations...");
    sqlx::migrate!("../../migrations").run(&pool).await?;

    match cli.command {
        Some(Commands::Sync) => {
            tracing::info!("Starting manual CVE synchronization...");
            cve_sync::sync_all(&pool).await?;
            return Ok(());
        }
        _ => {
            // Default to serve
            start_server(pool).await?;
        }
    }

    Ok(())
}

async fn start_server(pool: sqlx::PgPool) -> anyhow::Result<()> {
    let state = Arc::new(AppState { db: pool });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/scan", post(run_scan))
        .route("/api/v1/history", get(get_history))
        .route("/api/v1/sync", post(trigger_sync))
        .route("/api/v1/ai/models", post(fetch_ai_models))
        .with_state(state)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    tracing::info!("Zenvra API listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}

async fn run_scan(
    State(_state): State<Arc<AppState>>,
    Json(payload): Json<ScanRequest>,
) -> Result<Json<Vec<Finding>>, (StatusCode, String)> {
    tracing::info!("Received scan request for language: {}", payload.language);

    let engines = payload
        .engines
        .iter()
        .filter_map(|e| match e.as_str() {
            "sast" => Some(zenvra_scanner::Engine::Sast),
            "sca" => Some(zenvra_scanner::Engine::Sca),
            "secrets" => Some(zenvra_scanner::Engine::Secrets),
            "ai_code" => Some(zenvra_scanner::Engine::AiCode),
            _ => None,
        })
        .collect();

    let config = ScanConfig {
        code: payload.code,
        language: payload.language.parse().unwrap_or(Language::Unknown),
        engines,
        ai_config: payload.ai_config,
        file_path: None,
    };

    let mut findings = match zenvra_scanner::scan(&config).await {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("Scan failed: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Scan failed internally: {}", e),
            ));
        }
    };

    // Enrich findings with local CVE metadata
    let mut severity_counts = std::collections::HashMap::new();

    for finding in &mut findings {
        let sev_str = finding.severity.to_string().to_lowercase();
        *severity_counts.entry(sev_str).or_insert(0) += 1;

        if let Some(cve_id) = &finding.cve_id {
            let db_finding = sqlx::query(
                "SELECT title, description, severity FROM vulnerabilities WHERE cve_id = $1"
            )
            .bind(cve_id)
            .fetch_optional(&_state.db)
            .await;

            if let Ok(Some(row)) = db_finding {
                use sqlx::Row;
                finding.title = row.get("title");
                finding.description = Some(row.get("description"));
                let severity: String = row.get("severity");
                finding.severity = match severity.to_lowercase().as_str() {
                    "critical" => zenvra_scanner::Severity::Critical,
                    "high" => zenvra_scanner::Severity::High,
                    "medium" => zenvra_scanner::Severity::Medium,
                    "low" => zenvra_scanner::Severity::Low,
                    _ => zenvra_scanner::Severity::Info,
                };
            }
        }
    }

    // Persist scan history
    tracing::info!("Starting scan persistence (Findings: {})...", findings.len());
    let scan_id = match sqlx::query(
        "INSERT INTO scans (language, target_name, findings_count, severity_counts) 
         VALUES ($1, $2, $3, $4) RETURNING id"
    )
    .bind(payload.language)
    .bind("Manual Scan")
    .bind(findings.len() as i32)
    .bind(serde_json::to_value(&severity_counts).unwrap_or_default())
    .fetch_one(&_state.db)
    .await {
        Ok(row) => {
            use sqlx::Row;
            let id = row.get::<uuid::Uuid, _>("id");
            tracing::info!("Scan record created successfully (ID: {})", id);
            id
        },
        Err(e) => {
            tracing::error!("Failed to save scan history: {}", e);
            uuid::Uuid::new_v4()
        }
    };

    // Save individual results
    for finding in &findings {
        let _ = sqlx::query(
            "INSERT INTO scan_results (scan_id, engine, cve_id, cwe_id, severity, title, description, vulnerable_code, fixed_code, line_start, line_end, file_path)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"
        )
        .bind(scan_id)
        .bind(format!("{:?}", finding.engine))
        .bind(&finding.cve_id)
        .bind(&finding.cwe_id)
        .bind(finding.severity.to_string())
        .bind(&finding.title)
        .bind(&finding.description)
        .bind(&finding.vulnerable_code)
        .bind(&finding.fixed_code)
        .bind(finding.line_start as i32)
        .bind(finding.line_end as i32)
        .bind(&finding.file_path)
        .execute(&_state.db)
        .await;
    }
    tracing::info!("Scan persistence complete.");

    Ok(Json(findings))
}

async fn get_history(
    State(state): State<Arc<AppState>>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let scans = sqlx::query("SELECT * FROM scans ORDER BY created_at DESC LIMIT 50")
        .fetch_all(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut results = Vec::new();
    for row in scans {
        use sqlx::Row;
        results.push(serde_json::json!({
            "id": row.get::<uuid::Uuid, _>("id"),
            "language": row.get::<String, _>("language"),
            "target_name": row.get::<Option<String>, _>("target_name"),
            "findings_count": row.get::<i32, _>("findings_count"),
            "severity_counts": row.get::<serde_json::Value, _>("severity_counts"),
            "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
        }));
    }

    use axum::response::IntoResponse;
    let mut response = Json(serde_json::Value::Array(results)).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    );

    Ok(response)
}

async fn trigger_sync(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match cve_sync::sync_all(&state.db).await {
        Ok(_) => Ok(Json(serde_json::json!({"status": "success", "message": "Synchronization completed"}))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Sync failed: {}", e))),
    }
}

#[derive(Deserialize)]
struct ModelsRequest {
    provider: String,
    api_key: String,
    endpoint: Option<String>,
}

async fn fetch_ai_models(
    State(_state): State<Arc<AppState>>,
    Json(payload): Json<ModelsRequest>,
) -> Result<Json<Vec<String>>, (StatusCode, String)> {
    tracing::info!("Attempting to fetch AI models for provider: {}", payload.provider);
    
    let provider = match payload.provider.as_str() {
        "anthropic" => zenvra_scanner::ai::ProviderKind::Anthropic,
        "openai" => zenvra_scanner::ai::ProviderKind::OpenAi,
        "google" => zenvra_scanner::ai::ProviderKind::Google,
        "custom" => zenvra_scanner::ai::ProviderKind::Custom,
        _ => {
            tracing::warn!("Invalid AI provider requested: {}", payload.provider);
            return Err((StatusCode::BAD_REQUEST, "Invalid provider".to_string()));
        }
    };

    match zenvra_scanner::ai::list_models(provider, &payload.api_key, payload.endpoint.as_deref()).await {
        Ok(models) => {
            tracing::info!("Successfully fetched {} models for {}", models.len(), payload.provider);
            Ok(Json(models))
        },
        Err(e) => {
            tracing::error!("Failed to fetch models for {}: {}", payload.provider, e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        },
    }
}
