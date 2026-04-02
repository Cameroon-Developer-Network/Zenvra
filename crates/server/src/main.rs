//! Zenvra API Server — provides REST + SSE endpoints for the web frontend.

use axum::{
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use zenvra_scanner::{Finding, ScanConfig};

#[derive(Debug, Serialize, Deserialize)]
struct ScanRequest {
    code: String,
    language: String,
    engines: Vec<String>,
    ai_config: Option<zenvra_scanner::ai::AiConfig>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("zenvra_server=info".parse()?),
        )
        .init();

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/scan", post(run_scan))
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    tracing::info!("Zenvra API listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}

/// Run a scan and return the results immediately (REST version).
/// In the future, this will be replaced by SSE for real-time updates.
async fn run_scan(Json(payload): Json<ScanRequest>) -> Json<Vec<Finding>> {
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
        language: zenvra_scanner::Language::Unknown, // TODO: Map language string
        engines,
        ai_config: payload.ai_config,
        file_path: None,
    };

    match zenvra_scanner::scan(&config).await {
        Ok(findings) => Json(findings),
        Err(e) => {
            tracing::error!("Scan failed: {}", e);
            Json(vec![])
        }
    }
}
