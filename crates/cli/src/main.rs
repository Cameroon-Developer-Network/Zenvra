//! Zenvra CLI — `zenvra scan`, `zenvra report`, and more.

use anyhow::Result;
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

        /// Output format: text (default), json, sarif
        #[arg(short, long, default_value = "text")]
        output: String,

        /// Minimum severity to report: info, low, medium, high, critical
        #[arg(short, long, default_value = "medium")]
        severity: String,

        /// Disable specific engines (comma-separated: sast,sca,secrets,ai_code)
        #[arg(long)]
        disable: Option<String>,
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
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("zenvra=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { path, output, severity, disable } => {
            cmd_scan(path, output, severity, disable).await
        }
        Commands::Auth { token } => cmd_auth(token).await,
        Commands::Report { id } => cmd_report(id).await,
    }
}

async fn cmd_scan(
    path: PathBuf,
    _output: String,
    _severity: String,
    _disable: Option<String>,
) -> Result<()> {
    use colored::Colorize;
    use indicatif::{ProgressBar, ProgressStyle};

    println!("{}", "⚡ Zenvra — scanning for vulnerabilities".bold());
    println!("   Path: {}", path.display());
    println!();

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.set_message("Scanning...");
    pb.enable_steady_tick(std::time::Duration::from_millis(80));

    // TODO: read files from path, detect language, run scanner
    // For now: placeholder
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    pb.finish_and_clear();

    println!("{}", "✓ Scan complete".green().bold());
    println!();
    println!("  {} findings", "0".yellow());
    println!();
    println!(
        "  Run {} for the full scanner implementation.",
        "zenvra auth".cyan()
    );

    Ok(())
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
