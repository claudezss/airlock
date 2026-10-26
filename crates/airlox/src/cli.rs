//! The participant commands: `airlox session|send|run|result|items|watch`
//! and `airlox runner list|approve|reject`.
//!
//! Each command joins with an invite link (`--invite` or `AIRLOX_INVITE`) as
//! the participant the local cache holds for that session and role, so
//! repeated commands, the Python SDK and the MCP server act as one
//! participant. `--json` prints machine-readable output for agents.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use airlox_core::session::{JobLimits, Mode};
use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use serde_json::{json, Value};

use crate::client;
use crate::session::{
    default_cache_root, file_type, Item, JobSpec, NewSession, NoRunnerAvailable, Outcome, Session, Status,
    Target, DEFAULT_TYPES, FILE_TYPES_HELP,
};

/// How a command reaches its session.
#[derive(Args, Debug, Clone)]
pub struct Conn {
    /// Invite link for the session (or set AIRLOX_INVITE). Its role decides
    /// what you can do: owner, sender, observer.
    #[arg(long, env = "AIRLOX_INVITE", hide_env_values = true)]
    pub invite: String,
    /// Display name shown to other participants when joining for the first time.
    #[arg(long = "as", env = "AIRLOX_NAME", default_value = "cli")]
    pub display_name: String,
    /// Session cache directory (default: ~/.cache/airlox).
    #[arg(long, env = "AIRLOX_CACHE_DIR")]
    pub cache_dir: Option<PathBuf>,
    /// Print JSON instead of text.
    #[arg(long)]
    pub json: bool,
}

impl Conn {
    async fn join(&self) -> Result<Session> {
        let root = self.cache_dir.clone().unwrap_or_else(default_cache_root);
        Session::join(&client::http()?, &self.invite, &self.display_name, &root).await
    }
}

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

/// `"90"` (seconds), `"500ms"`, `"30s"`, `"15m"`, `"2h"`, `"1d"`.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (n, unit) = s.split_at(split);
    let n: u64 = n.parse().map_err(|_| format!("bad duration {s:?}"))?;
    let ms = match unit.trim() {
        "ms" => n,
        "" | "s" => n * 1000,
        "m" => n * 60_000,
        "h" => n * 3_600_000,
        "d" => n * 86_400_000,
        _ => return Err(format!("bad duration {s:?}: use s, m, h or d")),
    };
    Ok(Duration::from_millis(ms))
}

// -------------------------------------------------------------- session --

#[derive(Subcommand, Debug)]
pub enum SessionCmd {
    /// Create a session and print its invite links.
    Create(CreateArgs),
    /// Print the invite links (owner invite only).
    Invites(Conn),
    /// Show the session's settings and participants.
    Info(Conn),
    /// Close the session and purge it from the relay (owner invite only).
    Close(Conn),
}

#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Relay URL.
    #[arg(long, env = "AIRLOX_RELAY", default_value = "https://airlox.app")]
    pub relay: String,
    /// Allow running Python on runners.
    #[arg(long)]
    pub execute: bool,
    /// Session lifetime, e.g. 30m, 1h, 1d.
    #[arg(long, default_value = "1h", value_parser = parse_duration)]
    pub ttl: Duration,
    /// Content types allowed, comma-separated (text, py, md, zip, image).
    #[arg(long, value_delimiter = ',', default_values_t = DEFAULT_TYPES.iter().map(|s| s.to_string()))]
    pub types: Vec<String>,
    /// Largest item, in MB.
    #[arg(long, default_value_t = 25)]
    pub max_item_mb: u64,
    /// execute: Python runtime.
    #[arg(long, default_value = "python3.12")]
    pub runtime: String,
    /// execute: longest a job may run.
    #[arg(long, default_value = "60s", value_parser = parse_duration)]
    pub job_timeout: Duration,
    /// execute: job memory limit (MB).
    #[arg(long, default_value_t = 512)]
    pub job_memory: u32,
    /// execute: let jobs reach the network.
    #[arg(long)]
    pub network: bool,
    /// execute: a package jobs may use (repeat, or comma-separated).
    #[arg(long = "package", value_delimiter = ',')]
    pub packages: Vec<String>,
    /// execute: don't return files jobs write to $AIRLOX_OUT.
    #[arg(long)]
    pub no_out_files: bool,
    /// execute: let runners take jobs without the owner's approval.
    #[arg(long)]
    pub no_approval: bool,
    /// Your display name.
    #[arg(long = "as", env = "AIRLOX_NAME", default_value = "owner")]
    pub display_name: String,
    #[arg(long, env = "AIRLOX_CACHE_DIR")]
    pub cache_dir: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
}

pub async fn session(cmd: SessionCmd) -> Result<()> {
    match cmd {
        SessionCmd::Create(a) => {
            let job_limits = a.execute.then(|| JobLimits {
                runtime: a.runtime.clone(),
                timeout_s: a.job_timeout.as_secs().max(1) as u32,
                memory_mb: a.job_memory,
                network: a.network,
                packages: a.packages.clone(),
                return_out: !a.no_out_files,
                approve_runners: !a.no_approval,
            });
            let new = NewSession {
                mode: if a.execute { Mode::Execute } else { Mode::Relay },
                ttl_ms: a.ttl.as_millis() as u64,
                allowed_types: a.types.clone(),
                max_item_bytes: a.max_item_mb * 1024 * 1024,
                job_limits,
            };
            let root = a.cache_dir.clone().unwrap_or_else(default_cache_root);
            let s = Session::create(&client::http()?, &a.relay, new, &a.display_name, &root).await?;
            print_invites(&s, a.json, true)
        }
        SessionCmd::Invites(c) => print_invites(&c.join().await?, c.json, false),
        SessionCmd::Info(c) => {
            let mut s = c.join().await?;
            s.sync().await?;
            let m = &s.manifest;
            let info = json!({
                "session_id": s.session_id,
                "relay": s.base_url,
                "your_role": s.role.as_str(),
                "mode": m.mode,
                "expires_at_ms": m.expires_at_ms,
                "allowed_types": m.allowed_types,
                "max_item_bytes": m.max_item_bytes,
                "job_limits": m.job_limits,
                "participants": s.participants(),
                "closed": s.closed,
            });
            if c.json {
                print_json(&info);
            } else {
                println!("session   {} on {}", s.session_id, s.base_url);
                println!("you       {}", s.role.as_str());
                println!("mode      {}", info["mode"].as_str().unwrap_or_default());
                println!("expires   in {}", human_left(m.expires_at_ms));
                println!(
                    "types     {}",
                    serde_json::from_value::<Vec<String>>(info["allowed_types"].clone())?.join(", ")
                );
                if let Some(l) = &m.job_limits {
                    println!(
                        "jobs      {} · {} s · {} MB · network {} · packages [{}] · approval {}",
                        l.runtime,
                        l.timeout_s,
                        l.memory_mb,
                        if l.network { "on" } else { "off" },
                        l.packages.join(", "),
                        if l.approve_runners { "required" } else { "off" }
                    );
                }
                println!("participants:");
                for p in s.participants() {
                    println!("  {:<20} {:<9}{}", p.display_name, p.role, if p.left { " (left)" } else { "" });
                }
                if let Some(c) = &s.closed {
                    println!("closed: {c}");
                }
            }
            Ok(())
        }
        SessionCmd::Close(c) => {
            let mut s = c.join().await?;
            s.close().await?;
            if c.json {
                print_json(&json!({"closed": s.session_id}));
            } else {
                println!("closed and purged {}", s.session_id);
            }
            Ok(())
        }
    }
}

fn print_invites(s: &Session, json_out: bool, created: bool) -> Result<()> {
    let inv = s.invites()?;
    if json_out {
        print_json(
            &json!({"session_id": s.session_id, "expires_at_ms": s.manifest.expires_at_ms, "invites": inv}),
        );
        return Ok(());
    }
    if created {
        println!("created session {} (expires in {})", s.session_id, human_left(s.manifest.expires_at_ms));
        println!();
    }
    for role in ["owner", "sender", "observer", "runner"] {
        if let Some(url) = inv.get(role) {
            println!("{role:<9} {url}");
        }
    }
    println!();
    println!("Each link carries its role's keys: share it only over a channel you trust.");
    println!("Keep the owner link to manage the session (--invite or AIRLOX_INVITE).");
    Ok(())
}

fn human_left(at_ms: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let s = at_ms.saturating_sub(now) / 1000;
    match s {
        0 => "expired".into(),
        s if s < 3600 => format!("{} min", s.div_ceil(60)),
        s if s < 86_400 => format!("{} h {} min", s / 3600, (s % 3600) / 60),
        s => format!("{} d {} h", s / 86_400, (s % 86_400) / 3600),
    }
}

// ----------------------------------------------------------------- send --

#[derive(Subcommand, Debug)]
pub enum SendCmd {
    /// Send a message (use - to read it from stdin).
    Text {
        #[command(flatten)]
        conn: Conn,
        text: String,
    },
    /// Send files (.py, .md, .zip, .png, .jpg, .webp).
    File {
        #[command(flatten)]
        conn: Conn,
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
}

pub async fn send(cmd: SendCmd) -> Result<()> {
    match cmd {
        SendCmd::Text { conn, text } => {
            let text = if text == "-" {
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s)?;
                s
            } else {
                text
            };
            let mut s = conn.join().await?;
            let r = s.send_text(&text).await?;
            if conn.json {
                print_json(&json!({"sent": r}));
            } else {
                println!("sent {}", r["id"].as_str().unwrap_or_default());
            }
        }
        SendCmd::File { conn, paths } => {
            let mut s = conn.join().await?;
            let mut sent = Vec::new();
            for p in &paths {
                let r = send_path(&mut s, p).await?;
                if !conn.json {
                    println!("sent {} as {}", p.display(), r["id"].as_str().unwrap_or_default());
                }
                sent.push(json!({"path": p, "ref": r}));
            }
            if conn.json {
                print_json(&json!({"sent": sent}));
            }
        }
    }
    Ok(())
}

pub async fn send_path(s: &mut Session, p: &Path) -> Result<Value> {
    let name = p.file_name().and_then(|n| n.to_str()).context("the path has no file name")?;
    if file_type(name).is_none() {
        bail!("{} has an unsupported type; use {FILE_TYPES_HELP}", p.display());
    }
    let data = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
    s.send_file(data, name).await
}

// ------------------------------------------------------------------ run --

#[derive(Args, Debug)]
pub struct RunArgs {
    #[command(flatten)]
    pub conn: Conn,
    /// The Python file to run.
    pub file: PathBuf,
    /// Send to this runner (name or key).
    #[arg(long, conflicts_with_all = ["label"])]
    pub runner: Option<String>,
    /// Send to any idle runner with all these labels (repeat, or comma-separated).
    #[arg(long, value_delimiter = ',')]
    pub label: Vec<String>,
    /// A file to send with the job (repeat); ZIPs are unpacked in the job's directory.
    #[arg(long = "input")]
    pub inputs: Vec<PathBuf>,
    /// Job time limit (default: the session's).
    #[arg(long, value_parser = parse_duration)]
    pub timeout: Option<Duration>,
    /// Job memory limit in MB (default: the session's).
    #[arg(long)]
    pub memory: Option<u32>,
    /// A package from the session's allowlist the job needs (repeat).
    #[arg(long = "requirement")]
    pub requirements: Vec<String>,
    /// Save the job's out files here.
    #[arg(long)]
    pub out_dir: Option<PathBuf>,
    /// Submit and print the job id without waiting.
    #[arg(long)]
    pub no_wait: bool,
    /// Give up waiting after this long (the job keeps running).
    #[arg(long, default_value = "10m", value_parser = parse_duration)]
    pub wait: Duration,
}

/// Exit status for a job: its own exit code, or 1 if it produced none.
pub async fn run(a: RunArgs) -> Result<i32> {
    let code = std::fs::read_to_string(&a.file).with_context(|| format!("reading {}", a.file.display()))?;
    let filename = a.file.file_name().and_then(|n| n.to_str()).unwrap_or("main.py").to_string();
    let mut s = a.conn.join().await?;
    let mut files = Vec::new();
    for p in &a.inputs {
        files.push(send_path(&mut s, p).await?);
    }
    let target = match (&a.runner, a.label.is_empty()) {
        (Some(r), _) => Target::Runner(r.clone()),
        (None, false) => Target::Labels(a.label.clone()),
        (None, true) => Target::Any,
    };
    let spec = JobSpec {
        code,
        filename,
        files,
        target,
        timeout_s: a.timeout.map(|t| t.as_secs().max(1) as u32),
        memory_mb: a.memory,
        requirements: a.requirements.clone(),
    };
    let (job, runner) = match s.run_python(spec).await {
        Ok(j) => j,
        Err(e) => {
            if let Some(n) = e.downcast_ref::<NoRunnerAvailable>() {
                if a.conn.json {
                    print_json(
                        &json!({"job": n.job, "status": "failed", "reason": "no_runner_available", "message": n.message}),
                    );
                    return Ok(1);
                }
            }
            return Err(e);
        }
    };
    if a.no_wait {
        if a.conn.json {
            print_json(&json!({"job": job, "runner": runner}));
        } else {
            println!("submitted job {job}; get its result with: airlox result {job}");
        }
        return Ok(0);
    }
    if !a.conn.json {
        eprintln!("job {job} submitted; waiting for its result…");
    }
    finish(&mut s, &job, a.wait, a.out_dir.as_deref(), a.conn.json).await
}

#[derive(Args, Debug)]
pub struct ResultArgs {
    #[command(flatten)]
    pub conn: Conn,
    /// The job's id (from `airlox run`).
    pub job: String,
    /// Save the job's out files here.
    #[arg(long)]
    pub out_dir: Option<PathBuf>,
    /// How long to wait for the result.
    #[arg(long, default_value = "0s", value_parser = parse_duration)]
    pub wait: Duration,
}

pub async fn result(a: ResultArgs) -> Result<i32> {
    let mut s = a.conn.join().await?;
    finish(&mut s, &a.job, a.wait, a.out_dir.as_deref(), a.conn.json).await
}

async fn finish(
    s: &mut Session,
    job: &str,
    wait: Duration,
    out_dir: Option<&Path>,
    json_out: bool,
) -> Result<i32> {
    let Some(r) = s.wait(job, Some(wait)).await? else {
        if json_out {
            print_json(&json!({"job": job, "status": "running"}));
        } else {
            println!("no result yet for job {job}; check later with: airlox result {job} --wait 5m");
        }
        return Ok(75); // EX_TEMPFAIL
    };
    let saved = match out_dir {
        Some(d) => save_out_files(&r, d)?,
        None => vec![],
    };
    if json_out {
        let mut v = serde_json::to_value(&r)?;
        v["saved"] = json!(saved);
        print_json(&v);
    } else {
        print_outcome(&r, &saved, out_dir.is_none());
    }
    Ok(match (r.signed, r.exit_code) {
        (true, Some(c)) => c.clamp(0, 255) as i32,
        _ => 1,
    })
}

fn safe_name(name: &str) -> Option<&str> {
    let n = Path::new(name).file_name()?.to_str()?;
    (!n.starts_with('.') && n == name).then_some(n)
}

fn save_out_files(r: &Outcome, dir: &Path) -> Result<Vec<String>> {
    std::fs::create_dir_all(dir)?;
    let mut saved = Vec::new();
    for f in &r.out_files {
        let (Some(data), Some(name)) = (&f.data, safe_name(&f.name)) else { continue };
        let p = dir.join(name);
        std::fs::write(&p, data)?;
        saved.push(p.display().to_string());
    }
    Ok(saved)
}

fn print_outcome(r: &Outcome, saved: &[String], hint: bool) {
    if !r.stdout.is_empty() {
        print!("{}", r.stdout);
        if !r.stdout.ends_with('\n') {
            println!();
        }
    }
    if !r.stderr.is_empty() {
        eprint!("{}", r.stderr);
        if !r.stderr.ends_with('\n') {
            eprintln!();
        }
    }
    let code = r.exit_code.map(|c| format!("exit {c}")).unwrap_or_else(|| "no exit code".into());
    let reason = r.reason.as_deref().map(|x| format!(" ({x})")).unwrap_or_default();
    let signed = if r.signed { "signed by the runner" } else { "reported by the relay, unsigned" };
    eprintln!("── {} · {code}{reason} · {} ms · {signed}", r.status, r.wall_ms);
    if r.stdout_truncated || r.stderr_truncated {
        eprintln!("   output was truncated by the runner");
    }
    for p in saved {
        eprintln!("   saved {p}");
    }
    let unsaved: Vec<_> = r.out_files.iter().filter(|f| f.data.is_some()).map(|f| f.name.as_str()).collect();
    if hint && !unsaved.is_empty() {
        eprintln!("   out files: {} (save them with --out-dir)", unsaved.join(", "));
    }
    let gone: Vec<_> = r.out_files.iter().filter(|f| f.data.is_none()).map(|f| f.name.as_str()).collect();
    if !gone.is_empty() {
        eprintln!("   left the relay before they were fetched: {}", gone.join(", "));
    }
}

#[derive(Args, Debug)]
pub struct CancelArgs {
    #[command(flatten)]
    pub conn: Conn,
    /// The job's id.
    pub job: String,
}

/// Ask the job's runner to stop it (owner, or the sender who submitted it).
pub async fn cancel(a: CancelArgs) -> Result<()> {
    let mut s = a.conn.join().await?;
    s.cancel_job(&a.job).await?;
    if a.conn.json {
        print_json(&json!({"cancelled": a.job}));
    } else {
        println!("asked the runner to stop job {}", a.job);
    }
    Ok(())
}

// --------------------------------------------------------------- receive --

#[derive(Args, Debug)]
pub struct ItemsArgs {
    #[command(flatten)]
    pub conn: Conn,
    /// Save received files into this directory.
    #[arg(long)]
    pub save: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct WatchArgs {
    #[command(flatten)]
    pub items: ItemsArgs,
    /// Only show items that arrive from now on.
    #[arg(long)]
    pub new: bool,
    /// Stop after this long.
    #[arg(long, value_parser = parse_duration)]
    pub timeout: Option<Duration>,
}

/// One item as JSON: the verified header fields plus readable content.
pub fn item_json(i: &Item) -> Value {
    let mut v = json!({
        "seq": i.seq,
        "id": i.id,
        "kind": i.kind,
        "subkind": i.subkind,
        "author": i.author,
        "author_role": i.author_role,
        "author_name": i.author_name,
        "created_at_ms": i.created_at_ms,
        "status": i.status,
        "ref": i.item_ref,
    });
    if let Some(e) = &i.error {
        v["error"] = json!(e);
    }
    let Some(m) = &i.meta else { return v };
    match i.kind.as_str() {
        "text" => v["text"] = m["text"].clone(),
        "file" => {
            v["name"] = m["name"].clone();
            v["mime"] = m["mime"].clone();
            v["size"] = json!(i.body.len());
            if i.subkind.as_deref() == Some("md") || i.subkind.as_deref() == Some("py") {
                v["content"] = json!(String::from_utf8_lossy(&i.body));
            }
        }
        "job" => {
            v["filename"] = m["filename"].clone();
            v["code"] = m["code"].clone();
            v["target"] = m["target"].clone();
            v["files"] = m["files"].clone();
        }
        "result" => {
            v["job"] = m["job"]["id"].clone();
            for k in ["status", "exit_code", "reason", "stdout", "stderr", "wall_ms"] {
                v[k] = m[k].clone();
            }
            v["out_files"] = json!(m["out_files"]
                .as_array()
                .map(|a| a.iter().map(|o| o["name"].clone()).collect::<Vec<_>>()));
        }
        _ => v["meta"] = m.clone(),
    }
    v
}

fn item_line(i: &Item) -> String {
    let who =
        format!("{} ({})", i.author_name.as_deref().unwrap_or("?"), i.author_role.as_deref().unwrap_or("?"));
    let what = match i.status {
        Status::Ok => match i.kind.as_str() {
            "text" => i.text().unwrap_or_default().to_string(),
            "file" => format!("file {} ({} bytes)", i.name().unwrap_or("?"), i.body.len()),
            "job" => {
                let m = i.meta.as_ref();
                format!("job {} → {}", m.map(|m| m["filename"].as_str().unwrap_or("?")).unwrap_or("?"), i.id)
            }
            "result" => {
                let m = i.meta.as_ref().unwrap();
                format!(
                    "result for {}: {} exit {}",
                    m["job"]["id"].as_str().unwrap_or("?"),
                    m["status"].as_str().unwrap_or("?"),
                    m["exit_code"]
                )
            }
            "event" => format!("event {}", i.meta.as_ref().unwrap()["event"].as_str().unwrap_or("?")),
            k => k.to_string(),
        },
        Status::Evicted => format!("{} (left the relay before it was fetched)", i.kind),
        Status::Pending => format!("{} (not fetched yet)", i.kind),
        Status::Rejected => format!("{} REJECTED: {}", i.kind, i.error.as_deref().unwrap_or("?")),
    };
    format!("#{:<4} {who}: {what}", i.seq)
}

fn save_item(i: &Item, dir: Option<&Path>) -> Result<Option<String>> {
    let (Some(dir), Some(name)) = (dir, i.name()) else { return Ok(None) };
    if i.status != Status::Ok {
        return Ok(None);
    }
    let Some(name) = safe_name(name) else { return Ok(None) };
    std::fs::create_dir_all(dir)?;
    let p = dir.join(format!("{}-{name}", &i.id[..i.id.len().min(8)]));
    std::fs::write(&p, &i.body)?;
    Ok(Some(p.display().to_string()))
}

fn emit(i: &Item, a: &ItemsArgs) -> Result<()> {
    let saved = save_item(i, a.save.as_deref())?;
    if a.conn.json {
        let mut v = item_json(i);
        if let Some(p) = saved {
            v["saved"] = json!(p);
        }
        println!("{}", serde_json::to_string(&v)?);
    } else {
        println!("{}", item_line(i));
        if let Some(p) = saved {
            println!("       saved {p}");
        }
    }
    Ok(())
}

/// Print every item in the session so far (JSON lines with `--json`).
pub async fn items(a: ItemsArgs) -> Result<()> {
    let mut s = a.conn.join().await?;
    s.sync().await?;
    for i in s.items().to_vec() {
        emit(&i, &a)?;
    }
    Ok(())
}

/// Print items as they arrive (after the history, unless `--new`).
pub async fn watch(a: WatchArgs) -> Result<()> {
    let mut s = a.items.conn.join().await?;
    s.sync().await?;
    if !a.new {
        for i in s.items().to_vec() {
            emit(&i, &a.items)?;
        }
    }
    let args = &a.items;
    s.stream(a.timeout, &mut |i| {
        emit(i, args)?;
        Ok(true)
    })
    .await?;
    if let Some(c) = &s.closed {
        eprintln!("session ended: {c}");
    }
    Ok(())
}

// --------------------------------------------------------------- runners --

pub async fn runner_list(conn: Conn) -> Result<()> {
    let mut s = conn.join().await?;
    let rs = s.runners().await?;
    if conn.json {
        print_json(&json!({"runners": rs}));
        return Ok(());
    }
    if rs.is_empty() {
        println!("no runners have joined");
    }
    for r in rs {
        let state = if r.rejected {
            "rejected"
        } else if !r.approved {
            "awaiting approval"
        } else if !r.online {
            "offline"
        } else if r.job.is_some() {
            "busy"
        } else {
            "idle"
        };
        let net = if r.network_unblocked { " · cannot block network" } else { "" };
        println!("{:<20} {:<18} {} on {} [{}]{net}", r.name, state, r.sandbox, r.host, r.labels.join(","));
    }
    Ok(())
}

pub async fn runner_approve(conn: Conn, name: String) -> Result<()> {
    let mut s = conn.join().await?;
    let r = s.approve_runner(&name).await?;
    if conn.json {
        print_json(&json!({"approved": r}));
    } else {
        println!("approved {} ({} on {})", r.name, r.sandbox, r.host);
    }
    Ok(())
}

pub async fn runner_reject(conn: Conn, name: String, reason: Option<String>) -> Result<()> {
    let mut s = conn.join().await?;
    let r = s.reject_runner(&name, reason.as_deref()).await?;
    if conn.json {
        print_json(&json!({"rejected": r}));
    } else {
        println!("rejected {}", r.name);
    }
    Ok(())
}
