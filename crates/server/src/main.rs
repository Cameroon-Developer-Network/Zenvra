mod cve_sync;

use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, State},
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
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tower_http::cors::{AllowOrigin, CorsLayer};
use uuid::Uuid;
use zenvra_scanner::{Language, ScanConfig, ScanEvent};

/// Maximum allowed scan request body size (512 KiB).
const MAX_SCAN_BODY_BYTES: usize = 512 * 1024;

/// Rate-limit window duration.
const RATE_WINDOW: Duration = Duration::from_secs(60);
/// Maximum scan requests per IP per window.
const RATE_LIMIT: u32 = 10;

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

#[derive(Debug, Serialize, Deserialize)]
struct WorkspaceScanRequest {
    files: Vec<WorkspaceFile>,
    engines: Vec<String>,
    ai_config: Option<zenvra_scanner::ai::AiConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WorkspaceFile {
    path: String,
    code: String,
    language: String,
}

/// Per-IP rate-limit state.
struct RateEntry {
    count: u32,
    window_start: Instant,
}

struct AppState {
    db: sqlx::PgPool,
    /// Live broadcast channels for in-progress scans.
    scans: DashMap<Uuid, broadcast::Sender<ScanEvent>>,
    /// Cached events for completed scans (replayed to late subscribers).
    results: DashMap<Uuid, Vec<ScanEvent>>,
    /// Per-IP request counters for rate limiting.
    rate_limits: DashMap<String, RateEntry>,
}

impl AppState {
    /// Check if `ip` has exceeded the rate limit.
    /// Returns `true` if the request is allowed, `false` if it should be rejected.
    fn check_rate_limit(&self, ip: &str) -> bool {
        let now = Instant::now();
        let mut entry = self.rate_limits.entry(ip.to_string()).or_insert_with(|| RateEntry {
            count: 0,
            window_start: now,
        });

        if now.duration_since(entry.window_start) >= RATE_WINDOW {
            // Reset window
            entry.count = 1;
            entry.window_start = now;
            true
        } else if entry.count < RATE_LIMIT {
            entry.count += 1;
            true
        } else {
            false
        }
    }
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
        rate_limits: DashMap::new(),
    });

    // ── CORS ────────────────────────────────────────────────────────────────
    // In production, restrict to the app's own origin via `ALLOWED_ORIGIN`.
    // Falls back to allow-any for local development.
    let cors = build_cors_layer();

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/scan", post(run_scan))
        .route("/api/v1/scan/workspace", post(run_workspace_scan))
        .route("/api/v1/scan/:id/events", get(subscribe_to_scan))
        .route("/api/v1/scan/:id/results", get(get_scan_results))
        .route("/api/v1/history", get(get_history))
        .route("/api/v1/sync", post(trigger_sync))
        .route("/api/v1/ai/models", post(fetch_ai_models))
        .with_state(state)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    tracing::info!("Zenvra API listening on {}", listener.local_addr()?);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Build the CORS layer, honouring the `ALLOWED_ORIGIN` environment variable.
fn build_cors_layer() -> CorsLayer {
    use axum::http::{HeaderValue, Method};
    use tower_http::cors::Any;

    let methods = [
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::OPTIONS,
    ];

    match std::env::var("ALLOWED_ORIGIN") {
        Ok(origin) if !origin.is_empty() => {
            tracing::info!("CORS: restricting to origin '{}'", origin);
            let origin_value: HeaderValue = origin
                .parse()
                .expect("ALLOWED_ORIGIN must be a valid HTTP header value");
            CorsLayer::new()
                .allow_origin(AllowOrigin::exact(origin_value))
                .allow_methods(methods)
                .allow_headers(Any)
        }
        _ => {
            tracing::warn!("CORS: ALLOWED_ORIGIN not set — allowing any origin (development mode)");
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(methods)
                .allow_headers(Any)
        }
    }
}

async fn health_check() -> &'static str {
    "OK"
}

#[derive(serde::Serialize)]
struct ScanResponse {
    scan_id: Uuid,
}

/// Parse raw request bytes into a `ScanRequest`, enforcing the body size cap.
fn parse_scan_request(body: Bytes) -> Result<ScanRequest, (StatusCode, String)> {
    if body.len() > MAX_SCAN_BODY_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "Request body exceeds the {} KiB limit",
                MAX_SCAN_BODY_BYTES / 1024
            ),
        ));
    }
    serde_json::from_slice(&body).map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))
}

/// Extract a human-readable client IP from the connection info.
fn client_ip(addr: Option<ConnectInfo<SocketAddr>>) -> String {
    addr.map(|a| a.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

async fn run_scan(
    State(state): State<Arc<AppState>>,
    addr: Option<ConnectInfo<SocketAddr>>,
    body: Bytes,
) -> Result<Json<ScanResponse>, (StatusCode, String)> {
    // Rate limiting
    let ip = client_ip(addr);
    if !state.check_rate_limit(&ip) {
        tracing::warn!("Rate limit exceeded for IP: {}", ip);
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded. Maximum 10 scans per minute per IP.".to_string(),
        ));
    }

    // Parse and validate body size
    let payload = parse_scan_request(body)?;

    let scan_id = Uuid::new_v4();
    tracing::info!(
        "Starting async scan for {}, ID: {}",
        payload.language,
        scan_id
    );

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
            if let Err(e) = zenvra_scanner::scan_stream(config_task, scan_tx).await {
                tracing::error!("Scanner stream error: {}", e);
            }
        });

        let mut findings = Vec::new();
        let mut severity_counts = std::collections::HashMap::new();
        let mut all_events: Vec<ScanEvent> = Vec::new();

        while let Some(event) = scan_rx.recv().await {
            // Cache event for late subscribers
            all_events.push(event.clone());

            // Broadcast to any connected SSE subscribers
            if let Err(e) = tx.send(event.clone()) {
                tracing::debug!("SSE broadcast error (no active subscribers?): {}", e);
            }

            // Process specific events for DB persistence
            match event {
                ScanEvent::Finding(mut finding) => {
                    let sev_str = finding.severity.to_string().to_lowercase();
                    *severity_counts.entry(sev_str).or_insert(0) += 1;

                    // Enrich from local DB
                    if let Some(cve_id) = &finding.cve_id {
                        if let Ok(Some(row)) = sqlx::query(
                            "SELECT title, description FROM vulnerabilities WHERE cve_id = $1",
                        )
                        .bind(cve_id)
                        .fetch_optional(&state_task.db)
                        .await
                        {
                            use sqlx::Row;
                            finding.title = row.get("title");
                        }
                    }

                    // Persist individual finding
                    if let Err(e) = sqlx::query(
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
                    .await {
                        tracing::error!("Failed to persist finding for scan {}: {}", scan_id, e);
                    }

                    findings.push(*finding);
                }
                ScanEvent::Complete => {
                    // Finalize scan record
                    if let Err(e) = sqlx::query(
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
                    .await {
                        tracing::error!("Failed to finalize scan {}: {}", scan_id, e);
                    }

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

async fn run_workspace_scan(
    State(state): State<Arc<AppState>>,
    addr: Option<ConnectInfo<SocketAddr>>,
    body: Bytes,
) -> Result<Json<ScanResponse>, (StatusCode, String)> {
    // Rate limiting
    let ip = client_ip(addr);
    if !state.check_rate_limit(&ip) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded. Maximum 10 scans per minute per IP.".to_string(),
        ));
    }

    // Body size check for workspace (allow up to 5× single-file limit)
    if body.len() > MAX_SCAN_BODY_BYTES * 5 {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "Workspace request body exceeds the {} MiB limit",
                (MAX_SCAN_BODY_BYTES * 5) / (1024 * 1024)
            ),
        ));
    }

    let payload: WorkspaceScanRequest =
        serde_json::from_slice(&body).map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;

    let scan_id = Uuid::new_v4();
    tracing::info!(
        "Starting async workspace scan for {} files, ID: {}",
        payload.files.len(),
        scan_id
    );

    let (tx, _rx) = broadcast::channel(100);
    state.scans.insert(scan_id, tx.clone());

    let engines: Vec<zenvra_scanner::Engine> = payload
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

    let config = zenvra_scanner::WorkspaceScanConfig {
        files: payload
            .files
            .into_iter()
            .map(|f| zenvra_scanner::WorkspaceFile {
                path: f.path,
                code: f.code,
                language: zenvra_scanner::Language::from_extension(&f.language),
            })
            .collect(),
        engines,
        ai_config: payload.ai_config,
    };

    let tx_task = tx.clone();
    let state_task = state.clone();

    // Spawn scan task
    tokio::spawn(async move {
        let (scan_tx, mut scan_rx) = tokio::sync::mpsc::unbounded_channel();
        let config_task = config.clone();

        tokio::spawn(async move {
            if let Err(e) = zenvra_scanner::scan_workspace_stream(config_task, scan_tx).await {
                tracing::error!("Scanner stream error: {}", e);
            }
        });

        let mut findings = Vec::new();
        let mut severity_counts = std::collections::HashMap::new();

        while let Some(event) = scan_rx.recv().await {
            let _ = tx_task.send(event.clone());

            if let ScanEvent::Finding(finding) = event {
                let sev_str = finding.severity.to_string().to_lowercase();
                *severity_counts.entry(sev_str).or_insert(0) += 1;

                // Persist individual finding
                if let Err(e) = sqlx::query(
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
                .await {
                    tracing::error!("Failed to persist workspace finding: {}", e);
                }
                findings.push(*finding);
            } else if matches!(event, ScanEvent::Complete) {
                // Finalize scan record
                if let Err(e) = sqlx::query(
                    "INSERT INTO scans (id, language, target_name, findings_count, severity_counts) 
                     VALUES ($1, $2, $3, $4, $5)"
                )
                .bind(scan_id)
                .bind("Workspace") // Multi-file
                .bind("Workspace Scan")
                .bind(findings.len() as i32)
                .bind(serde_json::to_value(&severity_counts).unwrap_or(serde_json::Value::Object(Default::default())))
                .execute(&state_task.db)
                .await {
                    tracing::error!("Failed to finalize workspace scan: {}", e);
                }
                break;
            }
        }
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
            stream::iter(events).map(move |event| -> Result<Event, Infallible> {
                Ok(Event::default()
                    .json_data(&event)
                    .unwrap_or_else(|_| Event::default()))
            }),
        )
    } else {
        // Case 2: Scan is still in progress — subscribe to live broadcast
        let tx = state
            .scans
            .get(&id)
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
                }),
        )
    };

    Ok(Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default()))
}

use std::convert::Infallible;

/// Return persisted findings for a completed scan.
async fn get_scan_results(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let rows = sqlx::query(
        "SELECT id, engine, cve_id, cwe_id, severity, title, description, \
                vulnerable_code, fixed_code, line_start, line_end, file_path, created_at \
         FROM scan_results WHERE scan_id = $1 ORDER BY created_at ASC",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut results = Vec::new();
    for row in rows {
        use sqlx::Row;
        results.push(serde_json::json!({
            "id":              row.get::<uuid::Uuid, _>("id"),
            "engine":          row.get::<String, _>("engine"),
            "cve_id":          row.get::<Option<String>, _>("cve_id"),
            "cwe_id":          row.get::<Option<String>, _>("cwe_id"),
            "severity":        row.get::<String, _>("severity"),
            "title":           row.get::<String, _>("title"),
            "description":     row.get::<Option<String>, _>("description"),
            "explanation":     "",   // AI explanation not stored; shown during live stream
            "vulnerable_code": row.get::<String, _>("vulnerable_code"),
            "fixed_code":      row.get::<Option<String>, _>("fixed_code").unwrap_or_default(),
            "line_start":      row.get::<i32, _>("line_start"),
            "line_end":        row.get::<i32, _>("line_end"),
            "file_path":       row.get::<Option<String>, _>("file_path"),
            "detected_at":     row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
        }));
    }

    use axum::response::IntoResponse;
    Ok(Json(serde_json::Value::Array(results)).into_response())
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
        Ok(_) => Ok(Json(
            serde_json::json!({"status": "success", "message": "Synchronization completed"}),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Sync failed: {}", e),
        )),
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
    tracing::info!(
        "Attempting to fetch AI models for provider: {}",
        payload.provider
    );

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

    match zenvra_scanner::ai::list_models(provider, &payload.api_key, payload.endpoint.as_deref())
        .await
    {
        Ok(models) => {
            tracing::info!(
                "Successfully fetched {} models for {}",
                models.len(),
                payload.provider
            );
            Ok(Json(models))
        }
        Err(e) => {
            tracing::error!("Failed to fetch models for {}: {}", payload.provider, e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}
