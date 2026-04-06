mod cve_sync;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::sse::{Event, Sse},
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, Subcommand};
use dashmap::DashMap;
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;
use zenvra_scanner::{Language, ScanConfig, ScanEvent};

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
    /// Live broadcast channels for in-progress scans
    scans: DashMap<Uuid, broadcast::Sender<ScanEvent>>,
    /// Cached events for completed scans (replayed to late subscribers)
    results: DashMap<Uuid, Vec<ScanEvent>>,
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
    let db_url = std::env::var("DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("DATABASE_URL environment variable must be set"))?;
    
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&db_url)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to PostgreSQL at {}: {}", db_url, e))?;

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
            start_server(pool).await?;
        }
    }

    Ok(())
}

async fn start_server(pool: sqlx::PgPool) -> anyhow::Result<()> {
    let state = Arc::new(AppState { 
        db: pool,
        scans: DashMap::new(),
        results: DashMap::new(),
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/scan", post(run_scan))
        .route("/api/v1/scan/:id/events", get(subscribe_to_scan))
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

#[derive(serde::Serialize)]
struct ScanResponse {
    scan_id: Uuid,
}

async fn run_scan(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, (StatusCode, String)> {
    let scan_id = Uuid::new_v4();
    tracing::info!("Starting async scan for {}, ID: {}", payload.language, scan_id);

    let (tx, _rx) = broadcast::channel(100);
    state.scans.insert(scan_id, tx.clone());

    let engines = payload
        .engines
        .iter()
        .filter_map(|e: &String| match e.as_str() {
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

    let state_task = Arc::clone(&state);
    let payload_lang = payload.language.clone();
    
    // Spawn scan task
    tokio::spawn(async move {
        let (scan_tx, mut scan_rx) = tokio::sync::mpsc::unbounded_channel();
        let config_task = config.clone();
        
        tokio::spawn(async move {
            let _ = zenvra_scanner::scan_stream(config_task, scan_tx).await;
        });

        let mut findings = Vec::new();
        let mut severity_counts = std::collections::HashMap::new();
        let mut all_events: Vec<ScanEvent> = Vec::new();

        while let Some(event) = scan_rx.recv().await {
            // Cache event for late subscribers
            all_events.push(event.clone());

            // Broadcast to any connected SSE subscribers
            let _ = tx.send(event.clone());

            // Process specific events for DB persistence
            match event {
                ScanEvent::Finding(mut finding) => {
                    let sev_str = finding.severity.to_string().to_lowercase();
                    *severity_counts.entry(sev_str).or_insert(0) += 1;

                    // Enrich from local DB
                    if let Some(cve_id) = &finding.cve_id {
                        if let Ok(Some(row)) = sqlx::query("SELECT title, description FROM vulnerabilities WHERE cve_id = $1")
                            .bind(cve_id)
                            .fetch_optional(&state_task.db)
                            .await 
                        {
                            use sqlx::Row;
                            finding.title = row.get("title");
                        }
                    }
                    
                    // Persist individual finding
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
                    .execute(&state_task.db)
                    .await;
                    
                    findings.push(*finding);
                }
                ScanEvent::Complete => {
                    // Finalize scan record
                    let _ = sqlx::query(
                        "INSERT INTO scans (id, language, target_name, findings_count, severity_counts) 
                         VALUES ($1, $2, $3, $4, $5) 
                         ON CONFLICT (id) DO UPDATE SET findings_count = $4, severity_counts = $5"
                    )
                    .bind(scan_id)
                    .bind(payload_lang)
                    .bind("Manual Scan")
                    .bind(findings.len() as i32)
                    .bind(serde_json::to_value(&severity_counts).unwrap_or(serde_json::Value::Object(Default::default())))
                    .execute(&state_task.db)
                    .await;
                    
                    tracing::info!("Scan completed and persisted: {}", scan_id);
                    break;
                }
                ScanEvent::Error(e) => {
                    tracing::error!("Scan ID {} failed: {}", scan_id, e);
                    break;
                }
                _ => {}
            }
        }

        // Move results to cache so late SSE subscribers can replay them
        state_task.scans.remove(&scan_id);
        state_task.results.insert(scan_id, all_events);

        // Clean up results cache after 5 minutes
        tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
        state_task.results.remove(&scan_id);
    });

    Ok(Json(ScanResponse { scan_id }))
}

async fn subscribe_to_scan(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, (StatusCode, String)> {
    use futures::stream;

    type BoxedStream = std::pin::Pin<Box<dyn Stream<Item = Result<Event, Infallible>> + Send>>;

    // Case 1: Scan already completed — replay cached events immediately
    let stream: BoxedStream = if let Some(cached) = state.results.get(&id) {
        let events: Vec<ScanEvent> = cached.clone();
        Box::pin(
            stream::iter(events)
                .map(move |event| -> Result<Event, Infallible> {
                    Ok(Event::default()
                        .json_data(&event)
                        .unwrap_or_else(|_| Event::default()))
                })
        )
    } else {
        // Case 2: Scan is still in progress — subscribe to live broadcast
        let tx = state.scans.get(&id)
            .ok_or((StatusCode::NOT_FOUND, "Scan not found".to_string()))?
            .clone();

        let rx = tx.subscribe();
        Box::pin(
            tokio_stream::wrappers::BroadcastStream::new(rx)
                .filter_map(|msg: Result<ScanEvent, _>| msg.ok())
                .map(|event: ScanEvent| -> Result<Event, Infallible> {
                    Ok(Event::default()
                        .json_data(event)
                        .unwrap_or_else(|_| Event::default()))
                })
        )
    };

    Ok(Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default()))
}

use std::convert::Infallible;

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

#[derive(Debug, Serialize, Deserialize)]
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
