//! linkwatch: per-second network path monitor for Linux.
//! See README.md and docs/CONTRACTS.md.
#![forbid(unsafe_code)]

mod agg;
mod advice;
mod analyze;
mod check;
mod classify;
mod compare;
mod config;
mod control;
mod cve;
mod host;
mod lan;
mod link;
mod live;
mod model;
mod notify;
mod probe;
mod router;
mod router_audit;
mod run;
mod security;
mod site;
mod speed;
mod store;
mod web;
mod wifi;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "linkwatch", version, about = "Find out where a network connection breaks: Wi-Fi, router, line or internet.")]
struct Cli {
    /// Config file (TOML). Defaults apply when omitted.
    #[arg(short, long, global = true, env = "LINKWATCH_CONFIG")]
    config: Option<PathBuf>,
    /// Override data_dir from the config.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the monitor until stopped (SIGTERM/SIGINT).
    Run {
        /// Observation point id from the site file, e.g. B1/F2/R3.
        #[arg(long)]
        point: Option<String>,
        /// Free-text label for this session.
        #[arg(long)]
        label: Option<String>,
        /// Start a new session even if an unfinished one with the same point exists.
        #[arg(long)]
        new_session: bool,
        /// Do not start the web UI.
        #[arg(long)]
        no_web: bool,
    },
    /// Check permissions, interfaces and settings before a run.
    Check,
    /// Print the effective configuration as TOML.
    Config,
    /// List recorded sessions.
    Sessions,
    /// Incident report for a session: outages and their cause, micro-drops, hourly profile,
    /// anomalies, patterns. Markdown by default.
    Analyze {
        /// Session directory or session id (under data_dir). Default: the newest session.
        session: Option<String>,
        /// Cable-modem DOCSIS event log copied from the router web UI, to match with outages.
        #[arg(long)]
        router_log: Option<PathBuf>,
        /// Print JSON instead of Markdown.
        #[arg(long)]
        json: bool,
    },
    /// Compare multiple sessions (different rooms/points, or 2.4 vs 5 GHz runs).
    Compare {
        /// Session directories or ids under data_dir (at least 2).
        #[arg(required = true, num_args = 2..)]
        sessions: Vec<String>,
        /// Maximum clock difference in seconds for matching concurrent incidents.
        #[arg(long, default_value_t = 2.0)]
        tolerance_s: f64,
        /// Print JSON instead of Markdown.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_target(false)
        .init();
    let cli = Cli::parse();
    let mut cfg = match config::Config::load(cli.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e:#}");
            return ExitCode::from(2);
        }
    };
    if let Some(d) = cli.data_dir {
        cfg.data_dir = d;
    }
    let rt = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: cannot start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let res = rt.block_on(async move {
        match cli.cmd {
            Cmd::Run { point, label, new_session, no_web } => run::run(cfg, run::RunOpts { point, label, new_session, no_web }).await.map(|_| true),
            Cmd::Check => Ok(check::print(&check::check(&cfg).await)),
            Cmd::Config => {
                println!("{}", toml::to_string_pretty(&cfg).unwrap_or_default());
                Ok(true)
            }
            Cmd::Analyze { session, router_log, json } => analyze_cmd(&cfg, session, router_log, json),
            Cmd::Compare { sessions, tolerance_s, json } => compare_cmd(&cfg, sessions, tolerance_s, json),
            Cmd::Sessions => {
                for (dir, m) in store::read::sessions(&cfg.data_dir) {
                    let done = if dir.join("summary.json").exists() { "done" } else { "open" };
                    println!("{}  {}  {}  {}", m.started.format("%Y-%m-%d %H:%M"), done, m.point.as_deref().unwrap_or("-"), dir.display());
                }
                Ok(true)
            }
        }
    });
    match res {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn analyze_cmd(cfg: &config::Config, session: Option<String>, router_log: Option<PathBuf>, json: bool) -> anyhow::Result<bool> {
    use model::Stream;
    let dir = match session {
        Some(s) if std::path::Path::new(&s).is_dir() => PathBuf::from(s),
        Some(s) => cfg.data_dir.join(s),
        None => store::read::sessions(&cfg.data_dir)
            .into_iter()
            .max_by_key(|(_, m)| m.started)
            .map(|(d, _)| d)
            .ok_or_else(|| anyhow::anyhow!("no sessions in {}", cfg.data_dir.display()))?,
    };
    anyhow::ensure!(dir.is_dir(), "session not found: {}", dir.display());
    let router = match router_log {
        Some(p) => analyze::parse_router_log(&std::fs::read_to_string(&p).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?),
        None => vec![],
    };
    let meta: Option<model::SessionMeta> = std::fs::read(dir.join("meta.json")).ok().and_then(|b| serde_json::from_slice(&b).ok());
    let mut a = analyze::Analyzer::new(analyze::Opts::for_session(meta.as_ref()));
    let mut skipped = 0;
    // Samples must be in order per interface; the other streams are used as sets.
    for st in Stream::ALL {
        let mut it = store::read::iter(&dir, st);
        for e in it.by_ref() {
            a.push(&e);
        }
        skipped += it.skipped();
    }
    let mut rep = a.finish(&router);
    if skipped > 0 {
        rep.monitor_gaps.push(format!("{skipped} malformed lines skipped while reading"));
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&rep)?);
    } else {
        print!("{}", analyze::to_markdown(&rep));
    }
    Ok(true)
}

fn compare_cmd(cfg: &config::Config, sessions: Vec<String>, tolerance_s: f64, json: bool) -> anyhow::Result<bool> {
    let mut views = Vec::with_capacity(sessions.len());
    for s in sessions {
        let dir = if std::path::Path::new(&s).is_dir() {
            PathBuf::from(&s)
        } else {
            cfg.data_dir.join(&s)
        };
        views.push(compare::SessionView::load(&dir)?);
    }
    let rep = compare::compare(views, &compare::CompareOpts { tolerance_s: tolerance_s.max(0.0) });
    if json {
        println!("{}", serde_json::to_string_pretty(&rep)?);
    } else {
        print!("{}", compare::to_markdown(&rep));
    }
    Ok(true)
}
