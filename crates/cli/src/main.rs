//! Zenvra CLI — `zenvra scan`, `zenvra report`, and more.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "zenvra",
    about = "Ship fast. Ship safe. — AI-powered code vulnerability scanner",
    version,
    author
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a file or directory for security vulnerabilities
    Scan {
        /// Path to the file or directory to scan
        path: PathBuf,

        /// Output format: text (default), json
        #[arg(short, long, default_value = "text")]
        output: String,

        /// Minimum severity to report: info, low, medium, high, critical
        #[arg(short, long, default_value = "low")]
        severity: String,

        /// Disable specific engines (comma-separated: sast,sca,secrets,ai_code)
        #[arg(long)]
        disable: Option<String>,

        /// AI provider: anthropic, openai, google, custom
        #[arg(long)]
        ai_provider: Option<String>,

        /// AI API key (or set AI_API_KEY env var)
        #[arg(long)]
        ai_key: Option<String>,

        /// AI model name (e.g. claude-sonnet-4-20250514, gpt-4o, gemini-2.0-flash)
        #[arg(long)]
        ai_model: Option<String>,

        /// AI endpoint URL (required for custom provider, optional for others)
        #[arg(long)]
        ai_endpoint: Option<String>,
    },

    /// Authenticate with zenvra.dev (required for private repos and unlimited scans)
    Auth {
        /// API token from zenvra.dev/settings
        #[arg(long)]
        token: Option<String>,
    },

    /// Show the last scan report
    Report {
        /// Scan ID to retrieve
        id: Option<String>,
    },

    /// Configure Zenvra CLI settings (API keys, providers, etc.)
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Set a configuration value (e.g. ai_key, ai_provider)
    Set {
        /// Configuration key
        key: String,
        /// Configuration value
        value: String,
    },
    /// Show current configuration
    Show,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("zenvra=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            output,
            severity,
            disable,
            ai_provider,
            ai_key,
            ai_model,
            ai_endpoint,
        } => {
            cmd_scan(
                path,
                output,
                severity,
                disable,
                ai_provider,
                ai_key,
                ai_model,
                ai_endpoint,
            )
            .await
        }
        Commands::Auth { token } => cmd_auth(token).await,
        Commands::Report { id } => cmd_report(id).await,
        Commands::Config { action } => cmd_config(action).await,
    }
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Default)]
struct ZenvraConfig {
    ai_provider: Option<String>,
    ai_api_key: Option<String>,
    ai_model: Option<String>,
    ai_endpoint: Option<String>,
}

impl ZenvraConfig {
    fn load() -> Self {
        let config_path = Self::get_path();
        if let Ok(content) = std::fs::read_to_string(config_path) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            Self::default()
        }
    }

    fn save(&self) -> Result<()> {
        let config_path = Self::get_path();
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(config_path, content)?;
        Ok(())
    }

    fn get_path() -> std::path::PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        std::path::PathBuf::from(home).join(".config/zenvra/config.json")
    }
}

async fn cmd_config(action: ConfigAction) -> Result<()> {
    let mut config = ZenvraConfig::load();
    match action {
        ConfigAction::Set { key, value } => {
            match key.to_lowercase().as_str() {
                "ai_provider" => config.ai_provider = Some(value.clone()),
                "ai_key" | "ai_api_key" => config.ai_api_key = Some(value.clone()),
                "ai_model" => config.ai_model = Some(value.clone()),
                "ai_endpoint" => config.ai_endpoint = Some(value.clone()),
                _ => anyhow::bail!(
                    "Unknown config key: {}. Valid: ai_provider, ai_key, ai_model, ai_endpoint",
                    key
                ),
            }
            config.save()?;
            println!("✅ Config updated: {} set to {}", key, value);
        }
        ConfigAction::Show => {
            use colored::Colorize;
            println!("{}", "Zenvra CLI Configuration:".bold());
            println!(
                "   Path: {}",
                ZenvraConfig::get_path().display().to_string().dimmed()
            );
            println!();
            let json = serde_json::to_string_pretty(&config)?;
            println!("{}", json);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_scan(
    path: PathBuf,
    output: String,
    min_severity: String,
    disable: Option<String>,
    ai_provider: Option<String>,
    ai_key: Option<String>,
    ai_model: Option<String>,
    ai_endpoint: Option<String>,
) -> Result<()> {
    use colored::Colorize;
    use indicatif::{ProgressBar, ProgressStyle};
    use zenvra_scanner::{Engine, Finding, Language, ScanConfig, Severity};

    println!("{}", "⚡ Zenvra — scanning for vulnerabilities".bold());
    println!("   Path: {}", path.display());
    println!();

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .expect("valid template"),
    );
    pb.set_message("Reading files...");
    pb.enable_steady_tick(std::time::Duration::from_millis(80));

    // Determine which engines to run.
    let disabled: Vec<String> = disable
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    let mut engines = Vec::new();
    if !disabled.contains(&"sast".to_string()) {
        engines.push(Engine::Sast);
    }
    if !disabled.contains(&"sca".to_string()) {
        engines.push(Engine::Sca);
    }
    if !disabled.contains(&"secrets".to_string()) {
        engines.push(Engine::Secrets);
    }
    if !disabled.contains(&"ai_code".to_string()) {
        engines.push(Engine::AiCode);
    }

    // Parse minimum severity.
    let min_sev = match min_severity.to_lowercase().as_str() {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Low,
    };

    // Build AI config if provider is specified.
    let ai_config = build_ai_config(ai_provider, ai_key, ai_model, ai_endpoint)?;

    // Collect files to scan.
    let files = collect_files(&path)?;
    pb.set_message(format!("Scanning {} file(s)...", files.len()));

    // Run scan on each file.
    let mut all_findings: Vec<Finding> = Vec::new();

    for (file_path, content) in &files {
        let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let language = Language::from_extension(ext);

        let config = ScanConfig {
            code: content.clone(),
            language,
            engines: engines.clone(),
            ai_config: ai_config.clone(),
            file_path: Some(file_path.display().to_string()),
        };

        match zenvra_scanner::scan(&config).await {
            Ok(mut findings) => all_findings.append(&mut findings),
            Err(e) => {
                tracing::warn!("Error scanning {}: {}", file_path.display(), e);
            }
        }
    }

    // Filter by minimum severity.
    all_findings.retain(|f| f.severity >= min_sev);

    // Sort by severity descending.
    all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    pb.finish_and_clear();

    // Output results.
    match output.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&all_findings)
                .context("Failed to serialize findings")?;
            println!("{json}");
        }
        _ => {
            print_findings(&all_findings, files.len());
        }
    }

    Ok(())
}

/// Build AI config from CLI flags and environment variables.
fn build_ai_config(
    provider: Option<String>,
    key: Option<String>,
    model: Option<String>,
    endpoint: Option<String>,
) -> Result<Option<zenvra_scanner::ai::AiConfig>> {
    use zenvra_scanner::ai::{AiConfig, ProviderKind};

    let local_config = ZenvraConfig::load();

    // Priority: CLI Flag > Local Config > Env Var
    let provider_str = provider
        .or_else(|| local_config.ai_provider.clone())
        .or_else(|| std::env::var("AI_PROVIDER").ok());
    let api_key = key
        .or_else(|| local_config.ai_api_key.clone())
        .or_else(|| std::env::var("AI_API_KEY").ok());

    let Some(provider_str) = provider_str else {
        return Ok(None);
    };
    let Some(api_key) = api_key else {
        return Ok(None);
    };

    let provider_kind = match provider_str.to_lowercase().as_str() {
        "anthropic" => ProviderKind::Anthropic,
        "openai" => ProviderKind::OpenAi,
        "google" => ProviderKind::Google,
        "custom" => ProviderKind::Custom,
        other => {
            anyhow::bail!("Unknown AI provider: {other}. Use: anthropic, openai, google, custom")
        }
    };

    let model_name = model
        .or_else(|| local_config.ai_model.clone())
        .or_else(|| std::env::var("AI_MODEL").ok())
        .unwrap_or_else(|| match provider_kind {
            ProviderKind::Anthropic => "claude-3-5-sonnet-20240620".to_string(),
            ProviderKind::OpenAi => "gpt-4o".to_string(),
            ProviderKind::Google => "gemini-2.0-flash".to_string(),
            ProviderKind::Custom => "default".to_string(),
        });

    let endpoint_url = endpoint
        .or_else(|| local_config.ai_endpoint.clone())
        .or_else(|| std::env::var("AI_ENDPOINT").ok());

    Ok(Some(AiConfig {
        provider: provider_kind,
        api_key,
        model: model_name,
        endpoint: endpoint_url,
    }))
}

/// Collect all files from a path (file or directory), respecting common ignores.
fn collect_files(path: &PathBuf) -> Result<Vec<(PathBuf, String)>> {
    let mut files = Vec::new();

    if path.is_file() {
        let content =
            std::fs::read_to_string(path).context(format!("Failed to read {}", path.display()))?;
        files.push((path.clone(), content));
    } else if path.is_dir() {
        for entry in walkdir::WalkDir::new(path).into_iter().filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            // Skip common non-source directories.
            !matches!(
                name.as_ref(),
                ".git" | "node_modules" | "target" | ".venv" | "__pycache__" | "dist" | "build"
            )
        }) {
            let entry = entry?;
            if entry.file_type().is_file() {
                // Only scan text-like files by extension.
                let ext = entry
                    .path()
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("");

                if is_scannable_extension(ext) {
                    match std::fs::read_to_string(entry.path()) {
                        Ok(content) => files.push((entry.path().to_path_buf(), content)),
                        Err(_) => {
                            // Skip binary files silently.
                        }
                    }
                }
            }
        }
    } else {
        anyhow::bail!("Path does not exist: {}", path.display());
    }

    Ok(files)
}

/// Check if a file extension is one we should scan.
fn is_scannable_extension(ext: &str) -> bool {
    matches!(
        ext.to_lowercase().as_str(),
        "py" | "js"
            | "mjs"
            | "cjs"
            | "ts"
            | "tsx"
            | "jsx"
            | "rs"
            | "go"
            | "java"
            | "cs"
            | "cpp"
            | "cc"
            | "c"
            | "h"
            | "rb"
            | "php"
            | "swift"
            | "kt"
            | "kts"
            | "yaml"
            | "yml"
            | "toml"
            | "json"
            | "xml"
            | "env"
            | "sh"
            | "bash"
            | "zsh"
            | "cfg"
            | "ini"
            | "conf"
            | "properties"
            | "tf"
            | "hcl"
            | "dockerfile"
            | "svelte"
            | "vue"
    )
}

/// Pretty-print findings to the terminal.
fn print_findings(findings: &[zenvra_scanner::Finding], files_scanned: usize) {
    use colored::Colorize;

    if findings.is_empty() {
        println!("{}", "✓ No vulnerabilities found!".green().bold());
        println!("  Scanned {} file(s)", files_scanned);
        return;
    }

    for finding in findings {
        let severity_badge = match finding.severity {
            zenvra_scanner::Severity::Critical => "CRITICAL".on_red().white().bold(),
            zenvra_scanner::Severity::High => "HIGH".on_truecolor(200, 80, 0).white().bold(),
            zenvra_scanner::Severity::Medium => "MEDIUM".on_yellow().black().bold(),
            zenvra_scanner::Severity::Low => "LOW".on_blue().white().bold(),
            zenvra_scanner::Severity::Info => "INFO".on_white().black().bold(),
        };

        println!("{} — {}", severity_badge, finding.title.bold());

        if let Some(ref file_path) = finding.file_path {
            println!(
                "  {}  line {}",
                file_path.dimmed(),
                finding.line_start.to_string().dimmed()
            );
        }

        if let Some(ref cve) = finding.cve_id {
            println!("  CVE: {}", cve.cyan());
        }

        println!();
        println!("  {}", finding.vulnerable_code.dimmed());
        println!();

        if !finding.explanation.is_empty() {
            println!("  {}", "What happened:".underline());
            println!("  {}", finding.explanation);
            println!();
        }

        if !finding.fixed_code.is_empty() {
            println!("  {}", "Fix:".underline());
            println!("  {}", finding.fixed_code.green());
            println!();
        }

        println!("{}", "─".repeat(60).dimmed());
        println!();
    }

    // Summary.
    let critical = findings
        .iter()
        .filter(|f| f.severity == zenvra_scanner::Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == zenvra_scanner::Severity::High)
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.severity == zenvra_scanner::Severity::Medium)
        .count();
    let low = findings
        .iter()
        .filter(|f| f.severity == zenvra_scanner::Severity::Low)
        .count();

    println!(
        "Found {} issue(s) ({} critical · {} high · {} medium · {} low) scanning {} file(s)",
        findings.len().to_string().yellow().bold(),
        critical.to_string().red(),
        high.to_string().truecolor(200, 80, 0),
        medium.to_string().yellow(),
        low.to_string().blue(),
        files_scanned,
    );
}

async fn cmd_auth(_token: Option<String>) -> Result<()> {
    println!("Opening zenvra.dev/cli-auth in your browser...");
    println!("(Browser launch not yet implemented — coming in v0.2)");
    Ok(())
}

async fn cmd_report(_id: Option<String>) -> Result<()> {
    println!("Report viewer coming in v0.2.");
    Ok(())
}
