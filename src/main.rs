use agentclean::{
    agents::detect_agents,
    planner::CleanupPlan,
    scan::{scan_path, ScanOptions},
};
use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    env,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    name = "agentclean",
    version,
    about = "Read-only analysis and conservative cleanup planning"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Scan(Query),
    Analyze(Query),
    Report(Query),
    Inspect(Query),
    Doctor(DoctorArgs),
    Agents(OutputArgs),
    Config(ConfigArgs),
    Clean(CleanArgs),
    Purge(PurgeArgs),
    Docker(OutputArgs),
    History(StateArgs),
    Restore(RestoreArgs),
    Recover(RecoverArgs),
    Undo(StateArgs),
    Rules,
    Tui(Query),
}
#[derive(Args, Clone)]
struct Query {
    #[arg(short, long, default_value = ".")]
    path: PathBuf,
    #[arg(long)]
    rules: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}
#[derive(Args, Clone)]
struct OutputArgs {
    #[arg(long)]
    json: bool,
}
#[derive(Args, Clone)]
struct DoctorArgs {
    #[arg(short, long, default_value = ".")]
    path: PathBuf,
    #[arg(long)]
    json: bool,
}
#[derive(Args, Clone)]
struct ConfigArgs {
    #[arg(short, long)]
    path: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}
#[derive(Args, Clone)]
struct CleanArgs {
    #[arg(short, long, default_value = ".")]
    path: PathBuf,
    #[arg(long)]
    rules: Option<PathBuf>,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    execute: bool,
    #[arg(long)]
    yes: bool,
    #[arg(long, default_value_os_t = default_state_dir())]
    state_dir: PathBuf,
}
#[derive(Args, Clone)]
struct PurgeArgs {
    #[arg(long, default_value_os_t = default_state_dir())]
    state_dir: PathBuf,
    #[arg(long, default_value = "7")]
    retention_days: u64,
    #[arg(long)]
    execute: bool,
    #[arg(long)]
    yes: bool,
    #[arg(long)]
    json: bool,
}
#[derive(Args, Clone)]
struct RestoreArgs {
    id: String,
    #[arg(long, default_value_os_t = default_state_dir())]
    state_dir: PathBuf,
    #[arg(long)]
    json: bool,
}
#[derive(Args, Clone)]
struct RecoverArgs {
    #[arg(long, default_value_os_t = default_state_dir())]
    state_dir: PathBuf,
    #[arg(long)]
    execute: bool,
    #[arg(long)]
    yes: bool,
    #[arg(long)]
    json: bool,
}
#[derive(Args, Clone)]
struct StateArgs {
    #[arg(long, default_value_os_t = default_state_dir())]
    state_dir: PathBuf,
    #[arg(long)]
    json: bool,
}
fn default_state_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".agentclean")
}
#[derive(Serialize)]
struct Envelope<T: Serialize> {
    command: &'static str,
    #[serde(flatten)]
    data: T,
}
#[derive(Serialize)]
struct AnalyzeData {
    root: PathBuf,
    scanned_files: u64,
    scanned_bytes: u64,
    errors: Vec<String>,
    findings: Vec<agentclean::model::Finding>,
    status: agentclean::model::ScanStatus,
    space: serde_json::Value,
}
#[derive(Serialize)]
struct InspectData {
    root: PathBuf,
    directories: Vec<DirectorySummary>,
}
#[derive(Serialize)]
struct DirectorySummary {
    path: PathBuf,
    files: u64,
    bytes: u64,
}
#[derive(Serialize)]
struct Check {
    name: &'static str,
    status: &'static str,
    detail: String,
}
#[derive(Serialize)]
struct DoctorData {
    checks: Vec<Check>,
}
#[derive(Serialize)]
struct Agent {
    name: String,
    detected: bool,
    paths: Vec<PathBuf>,
    entries: Vec<agentclean::agents::AgentEntry>,
    notes: String,
    observed_apparent_bytes: u64,
    by_category: BTreeMap<String, serde_json::Value>,
}
#[derive(Serialize)]
struct AgentsData {
    agents: Vec<Agent>,
}
fn main() -> Result<()> {
    let result = match Cli::parse().command {
        Command::Scan(q) => scan(q, "scan"),
        Command::Analyze(q) => scan(q, "analyze"),
        Command::Report(q) => scan(q, "report"),
        Command::Inspect(q) => inspect(q),
        Command::Doctor(q) => doctor(q),
        Command::Agents(q) => agents(q),
        Command::Config(q) => config(q),
        Command::Clean(q) => clean(q),
        Command::Purge(q) => purge(q),
        Command::Docker(q) => docker(q),
        Command::History(q) => history(q),
        Command::Restore(q) => restore(q),
        Command::Recover(q) => recover(q),
        Command::Undo(q) => undo(q),
        Command::Rules => {
            println!("Rules are loaded from the library API; no rule editor is provided.");
            Ok(())
        }
        Command::Tui(q) => {
            let r = agentclean::scan::scan_path(&q.path, &Default::default())?;
            agentclean::tui::run(r)
        }
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(2)
    }
    Ok(())
}
fn recover(q: RecoverArgs) -> Result<()> {
    let engine = agentclean::core::cleanup::CleanupEngine::new(q.state_dir)?;
    let report = engine
        .recovery_report()
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    if q.execute && !q.yes {
        anyhow::bail!("refusing recovery without --yes; review the read-only report first")
    }
    if q.execute && q.yes && !report.blocked.is_empty() {
        anyhow::bail!("refusing recovery while ambiguous entries are blocked")
    }
    let applied = if q.execute && q.yes {
        engine
            .repair_recovery(&report)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?
    } else {
        agentclean::core::cleanup::RecoveryReport::default()
    };
    if q.json {
        println!(
            "{}",
            serde_json::json!({
                "command": "recover",
                "dry_run": !(q.execute && q.yes),
                "repairable": report.repairable.iter().map(|i| serde_json::json!({"id": i.id, "result": format!("{:?}", i.result), "action": format!("{:?}", i.action), "reason": i.reason})).collect::<Vec<_>>(),
                "blocked": report.blocked.iter().map(|i| serde_json::json!({"id": i.id, "result": format!("{:?}", i.result), "reason": i.reason})).collect::<Vec<_>>(),
                "applied": applied.repairable.iter().map(|i| serde_json::json!({"id": i.id, "result": format!("{:?}", i.result), "reason": i.reason})).collect::<Vec<_>>(),
            })
        );
    } else {
        println!("Recovery inspection (read-only by default)");
        println!("Repairable: {}", report.repairable.len());
        println!("Blocked: {}", report.blocked.len());
        for item in report.repairable.iter().chain(report.blocked.iter()) {
            println!("{}: {}", item.id, item.reason);
        }
        if q.execute && q.yes {
            println!("Applied repairs: {}", applied.repairable.len());
        } else {
            println!("Dry run: no journal or file state was modified.");
        }
    }
    Ok(())
}

fn history(q: StateArgs) -> Result<()> {
    let entries = agentclean::history::read(&q.state_dir)?;
    if q.json {
        println!(
            "{}",
            serde_json::json!({"command": "history", "entries": entries})
        );
    } else {
        for e in entries {
            println!("{} {} {}", e.id, e.result, e.original_path.display());
        }
    }
    Ok(())
}
fn restore(q: RestoreArgs) -> Result<()> {
    if q.id.is_empty()
        || !q.id.starts_with("q-")
        || q.id.len() >= 100
        || !q
            .id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        anyhow::bail!("invalid journal id");
    }
    let engine = agentclean::core::cleanup::CleanupEngine::new(q.state_dir)?;
    let entry = engine
        .restore(&q.id)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    if q.json {
        println!(
            "{}",
            serde_json::json!({"command":"restore", "id":entry.id, "result":"restored"})
        );
    } else {
        println!("Restored {}", entry.id);
    }
    Ok(())
}
fn undo(q: StateArgs) -> Result<()> {
    let entries = agentclean::history::read(&q.state_dir)?;
    let entry = agentclean::history::latest_undoable(&entries)
        .ok_or_else(|| anyhow::anyhow!("no undoable journal entry"))?;
    let engine = agentclean::core::cleanup::CleanupEngine::new(q.state_dir)?;
    let restored = engine
        .restore(&entry.id)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    if q.json {
        println!(
            "{}",
            serde_json::json!({"command":"undo", "id":restored.id, "result":"restored"})
        );
    } else {
        println!("Undid {}", restored.id);
    }
    Ok(())
}

fn scan(q: Query, command: &'static str) -> Result<()> {
    let options = if let Some(rule_path) = &q.rules {
        ScanOptions {
            rules: agentclean::rules::RuleSet::load(rule_path)?,
            ..Default::default()
        }
    } else {
        ScanOptions::default()
    };
    let r = agentclean::scan::scan_path(&q.path, &options)?;
    let mut by_risk = BTreeMap::<String, serde_json::Value>::new();
    for risk in [
        agentclean::model::Risk::Safe,
        agentclean::model::Risk::Caution,
        agentclean::model::Risk::Dangerous,
        agentclean::model::Risk::Protected,
        agentclean::model::Risk::Unknown,
    ] {
        let key = serde_json::to_value(risk)?
            .as_str()
            .unwrap_or("unknown")
            .to_owned();
        let files: Vec<_> = r.files.iter().filter(|f| f.risk == risk).collect();
        by_risk.insert(
            key,
            serde_json::json!({
                "files": files.len(),
                "apparent_bytes": files.iter().map(|f| f.apparent_bytes).sum::<u64>(),
                "allocated_bytes": files.iter().map(|f| f.allocated_bytes).sum::<u64>(),
            }),
        );
    }
    let space = serde_json::json!({
        "apparent_bytes": r.total_apparent_bytes(),
        "allocated_bytes": r.total_allocated_bytes(),
        "reclaimable_allocated_bytes": r.total_reclaimable_allocated_bytes(),
        "quarantine_freed_bytes": 0,
        "by_risk": by_risk,
        "note": "Allocated bytes are observed blocks, not a promise of free-space increase; shared extents and open handles may defer release.",
    });
    let data = AnalyzeData {
        status: r.status,
        space,
        root: r.root,
        scanned_files: r.scanned_files,
        scanned_bytes: r.scanned_bytes,
        errors: r.errors,
        findings: r.files,
    };
    if q.json {
        println!("{}", serde_json::to_string(&Envelope { command, data })?)
    } else {
        println!(
            "Scanned {}: {} files, {} bytes, {} errors",
            data.root.display(),
            data.scanned_files,
            data.scanned_bytes,
            data.errors.len()
        )
    }
    Ok(())
}
fn inspect(q: Query) -> Result<()> {
    let r = agentclean::scan::scan_path(&q.path, &Default::default())?;
    let mut m: BTreeMap<PathBuf, (u64, u64)> = BTreeMap::new();
    for f in r.files {
        let x = m
            .entry(f.path.parent().unwrap_or(Path::new(".")).to_path_buf())
            .or_default();
        x.0 += 1;
        x.1 += f.bytes
    }
    let data = InspectData {
        root: q.path,
        directories: m
            .into_iter()
            .map(|(path, (files, bytes))| DirectorySummary { path, files, bytes })
            .collect(),
    };
    if q.json {
        println!(
            "{}",
            serde_json::to_string(&Envelope {
                command: "inspect",
                data
            })?
        )
    } else {
        for d in &data.directories {
            println!("{}: {} files, {} bytes", d.path.display(), d.files, d.bytes)
        }
    }
    Ok(())
}
fn clean(q: CleanArgs) -> Result<()> {
    let scan_options = if let Some(rule_path) = &q.rules {
        ScanOptions {
            rules: agentclean::rules::RuleSet::load(rule_path)?,
            ..Default::default()
        }
    } else {
        ScanOptions::default()
    };
    let r = scan_path(&q.path, &scan_options)?;
    let plan = CleanupPlan::from_report(&r, q.dry_run || !q.execute);
    if q.json {
        println!(
            "{}",
            serde_json::to_string(&Envelope {
                command: "clean",
                data: &plan
            })?
        );
    } else {
        println!("Cleanup Plan");
        if plan.dry_run {
            println!("Dry run: no files will be modified.");
        }
        println!("\nSAFE\n");
        for i in &plan.items {
            println!(
                "Path: {}\nSize: {}\nRisk: {:?}\nReason: {}\nAction: {}\n",
                i.path.display(),
                i.expected_size,
                i.risk,
                i.reason,
                i.operation
            );
        }
        println!(
            "Total reclaimable: {}\nFiles: {}\nDirectories: {}",
            plan.total_reclaimable, plan.files, plan.directories
        );
        if !plan.blocked.is_empty() {
            println!("Blocked/protected items: {}", plan.blocked.len());
        }
        println!("No files were modified.\nNo files were changed.");
    }
    if q.execute && !q.dry_run {
        if !q.yes {
            anyhow::bail!("refusing execution without --yes; review the plan first")
        }
        let ids = plan.execute(q.state_dir)?;
        eprintln!(
            "Quarantined {} item(s); disk freed: 0 (quarantine is reversible; use purge after retention)",
            ids.len()
        );
    }
    Ok(())
}
fn purge(q: PurgeArgs) -> Result<()> {
    let engine = agentclean::core::cleanup::CleanupEngine::new(q.state_dir)?;
    let retention = std::time::Duration::from_secs(
        q.retention_days
            .checked_mul(24 * 60 * 60)
            .ok_or_else(|| anyhow::anyhow!("retention is too large"))?,
    );
    let plan = engine
        .plan_purge(&[], retention)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    if q.execute && !q.yes {
        anyhow::bail!("refusing purge without --yes; review the dry-run plan first")
    }
    let report = engine
        .execute_purge(&plan, q.execute && q.yes)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    if q.json {
        println!(
            "{}",
            serde_json::json!({
                "command": "purge",
                "dry_run": report.dry_run,
                "retention_days": q.retention_days,
                "eligible": plan.entries.len(),
                "blocked": plan.blocked.iter().map(|b| serde_json::json!({"id": b.id, "reason": b.reason})).collect::<Vec<_>>(),
                "purged_ids": report.purged_ids,
                "logical_bytes": report.logical_bytes,
                "allocated_bytes": report.allocated_bytes,
                "unlinked_bytes": report.unlinked_bytes,
                "free_bytes_before": report.free_bytes_before,
                "free_bytes_after": report.free_bytes_after,
                "observed_free_bytes": report.observed_free_bytes,
            })
        );
    } else {
        println!("Purge plan");
        println!("Retention: {} days", q.retention_days);
        println!("Eligible: {}", plan.entries.len());
        println!("Blocked: {}", plan.blocked.len());
        println!("Logical bytes: {}", report.logical_bytes);
        println!("Allocated bytes: {}", report.allocated_bytes);
        println!("Unlinked bytes: {}", report.unlinked_bytes);
        match (report.free_bytes_before, report.free_bytes_after) {
            (Some(before), Some(after)) => println!(
                "Observed filesystem free bytes: before={}, after={}, delta={}",
                before,
                after,
                report.observed_free_bytes.unwrap_or(0)
            ),
            _ => println!("Observed filesystem free bytes: unavailable"),
        }
        if report.dry_run {
            println!("Dry run: no files were modified.");
        } else {
            println!("Purged: {}", report.purged_ids.len());
        }
    }
    Ok(())
}

fn docker(q: OutputArgs) -> Result<()> {
    let report = agentclean::docker::analyze(std::time::Duration::from_secs(5));
    if q.json {
        println!(
            "{}",
            serde_json::to_string(&Envelope {
                command: "docker",
                data: report
            })?
        );
    } else {
        println!("Docker inventory");
        println!(
            "Executable: {}",
            report
                .executable
                .map_or_else(|| "not found".into(), |p| p.display().to_string())
        );
        println!(
            "Daemon: {}",
            if report.daemon_available {
                "available"
            } else {
                "unavailable"
            }
        );
        println!(
            "Images: {}\nContainers: {}\nVolumes: {}\nBuild cache entries: {}",
            report.images.len(),
            report.containers.len(),
            report.volumes.len(),
            report.builder_du.len()
        );
        for item in report.unsupported.iter().chain(report.errors.iter()) {
            println!("Note: {item}");
        }
    }
    Ok(())
}

fn doctor(q: DoctorArgs) -> Result<()> {
    let exists = q.path.exists();
    let checks = vec![
        Check {
            name: "scan_path",
            status: if exists { "ok" } else { "fail" },
            detail: if exists {
                format!("{} is accessible", q.path.display())
            } else {
                format!("{} does not exist", q.path.display())
            },
        },
        Check {
            name: "platform",
            status: "ok",
            detail: env::consts::OS.into(),
        },
    ];
    let fail = checks.iter().any(|c| c.status == "fail");
    let data = DoctorData { checks };
    if q.json {
        println!(
            "{}",
            serde_json::to_string(&Envelope {
                command: "doctor",
                data
            })?
        )
    } else {
        for c in &data.checks {
            println!("[{}] {}: {}", c.status, c.name, c.detail)
        }
    }
    if fail {
        std::process::exit(1)
    }
    Ok(())
}
fn agents(q: OutputArgs) -> Result<()> {
    let detected = detect_agents();
    let data = AgentsData {
        agents: detected
            .iter()
            .map(|a| Agent {
                observed_apparent_bytes: a.entries.iter().map(|e| e.size).sum(),
                by_category: {
                    let mut totals = BTreeMap::<String, (u64, u64)>::new();
                    for e in &a.entries {
                        let key = serde_json::to_value(e.kind).unwrap_or_default().as_str().unwrap_or("unknown").to_owned();
                        let total = totals.entry(key).or_default();
                        total.0 += 1;
                        total.1 = total.1.saturating_add(e.size);
                    }
                    totals.into_iter().map(|(key, (files, apparent_bytes))| (key, serde_json::json!({"files": files, "apparent_bytes": apparent_bytes}))).collect()
                },
                name: a.name.clone(),
                detected: a.detected,
                paths: a.roots.clone(),
                entries: a.entries.clone(),
                notes: "Bounded read-only detector; credentials and user state are protected."
                    .into(),
            })
            .collect(),
    };
    if q.json {
        println!(
            "{}",
            serde_json::to_string(&Envelope {
                command: "agents",
                data
            })?
        )
    } else {
        for a in &data.agents {
            println!(
                "{}: {}",
                a.name,
                if a.detected {
                    "detected"
                } else {
                    "not detected"
                }
            )
        }
    }
    Ok(())
}
fn config(q: ConfigArgs) -> Result<()> {
    let path = q.path.unwrap_or_else(|| {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("agentclean/config.yml")
    });
    let cfg = agentclean::config::Config::load(&path)?;
    #[derive(Serialize)]
    struct Data {
        path: PathBuf,
        config: agentclean::config::Config,
    }
    let data = Data { path, config: cfg };
    if q.json {
        println!(
            "{}",
            serde_json::to_string(&Envelope {
                command: "config",
                data
            })?
        )
    } else {
        println!(
            "Config: {}\n{}",
            data.path.display(),
            serde_yaml::to_string(&data.config)?
        )
    }
    Ok(())
}
