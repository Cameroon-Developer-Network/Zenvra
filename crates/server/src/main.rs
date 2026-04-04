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
        .max_connections(5)
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
    for finding in &mut findings {
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
                // Map severity string to enum (simplified for now)
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

    Ok(Json(findings))
}
