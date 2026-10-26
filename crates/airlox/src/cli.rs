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
use crate::files::{clean_line, clean_text, out_file_name, received_name, save_new};
use crate::session::{
    default_cache_root, file_type, Item, JobSpec, NewSession, NoRunnerAvailable, Outcome, Profile, Session,
    Status, Target, DEFAULT_TYPES, FILE_TYPES_HELP,
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
    /// What you are or do, shown to other participants when joining for the
    /// first time (up to 280 characters).
    #[arg(long, env = "AIRLOX_DESCRIPTION")]
    pub description: Option<String>,
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
        let me = Profile::new(&self.display_name, self.description.as_deref());
        let mut s = Session::join(&client::http()?, &self.invite, &me, &root).await?;
        if !s.joined_now && me.description.is_some() && s.my_description().is_none() {
            // Our own join is not cached yet: fetch it to compare.
            let _ = s.sync().await;
        }
        if !s.joined_now
            && me.description.is_some()
            && s.my_description().is_some_and(|d| d != me.description.as_deref())
        {
            eprintln!(
                "note: you already joined this session with this invite; your description stays as it was \
                 (it is fixed at the first join)"
            );
        }
        Ok(s)
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
    let unit_ms: u64 = match unit.trim() {
        "ms" => 1,
        "" | "s" => 1000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => return Err(format!("bad duration {s:?}: use s, m, h or d")),
    };
    n.checked_mul(unit_ms).map(Duration::from_millis).ok_or_else(|| format!("duration {s:?} is too long"))
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
    /// Cut off a role (owner invite only): its participants lose access and
    /// its invite admits no one. Anyone who kept that invite can still
    /// decrypt what they already copied; close the session to end the rest.
    Revoke(RevokeArgs),
    /// Print the audit trail as JSON lines (owner or observer invite): who
    /// joined, posted, acked, approved and revoked, with the signed material
    /// to check it. It is purged with the session.
    Audit(AuditArgs),
}

#[derive(Args, Debug)]
pub struct RevokeArgs {
    #[command(flatten)]
    pub conn: Conn,
    /// The role to revoke.
    #[arg(value_parser = ["sender", "observer", "runner"])]
    pub role: String,
}

#[derive(Args, Debug)]
pub struct AuditArgs {
    #[command(flatten)]
    pub conn: Conn,
    /// Write it to this new file instead of printing it.
    #[arg(long)]
    pub out: Option<PathBuf>,
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
    /// What you are or do, shown to the other participants.
    #[arg(long, env = "AIRLOX_DESCRIPTION")]
    pub description: Option<String>,
    #[arg(long, env = "AIRLOX_CACHE_DIR")]
    pub cache_dir: Option<PathBuf>,
    /// Write the owner invite to this new file (mode 0600) instead of
    /// printing it. Agents should use this, so the link that controls the
    /// session never enters their context: `AIRLOX_INVITE="$(cat FILE)"`.
    #[arg(long)]
    pub owner_invite_file: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
}

/// Write an invite to a new private file; never over an existing one.
fn write_private(path: &Path, link: &str) -> Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o.open(path).with_context(|| format!("creating {}", path.display()))?;
    std::io::Write::write_all(&mut f, format!("{link}\n").as_bytes())?;
    Ok(())
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
                max_item_bytes: a
                    .max_item_mb
                    .checked_mul(1024 * 1024)
                    .context("--max-item-mb is too large")?,
                job_limits,
            };
            // Check the owner-invite file can be written before the session
            // exists, so a bad path cannot leave a session nobody can use.
            if let Some(f) = &a.owner_invite_file {
                if f.exists() {
                    bail!("{} already exists; pass a new file for the owner invite", f.display());
                }
                let parent = f.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
                if !parent.is_dir() {
                    bail!("{} is not a directory", parent.display());
                }
            }
            let root = a.cache_dir.clone().unwrap_or_else(default_cache_root);
            let me = Profile::new(&a.display_name, a.description.as_deref());
            let s = Session::create(&client::http()?, &a.relay, new, &me, &root).await?;
            print_invites(&s, a.json, true, a.owner_invite_file.as_deref())
        }
        SessionCmd::Invites(c) => print_invites(&c.join().await?, c.json, false, None),
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
                    let name = clean_line(&p.display_name);
                    println!("  {name:<20} {:<9}{}", p.role, if p.left { " (left)" } else { "" });
                    if let Some(d) = &p.description {
                        println!("  {:<20} {}", "", clean_line(d));
                    }
                }
                if let Some(c) = &s.closed {
                    println!("closed: {}", clean_line(c));
                }
            }
            Ok(())
        }
        SessionCmd::Revoke(a) => {
            let mut s = a.conn.join().await?;
            s.revoke(&a.role).await?;
            if a.conn.json {
                print_json(&json!({"revoked": a.role}));
            } else {
                println!(
                    "revoked the {} role: its participants are cut off and its invite no longer works",
                    a.role
                );
            }
            Ok(())
        }
        SessionCmd::Audit(a) => {
            let s = a.conn.join().await?;
            let raw = s.audit().await?;
            // Each line re-serialized: JSON from the relay, never raw bytes.
            let mut out = String::new();
            for line in raw.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
                let v: Value =
                    serde_json::from_slice(line).context("the relay sent an audit line that is not JSON")?;
                out.push_str(&v.to_string());
                out.push('\n');
            }
            match &a.out {
                Some(path) => {
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(path)
                        .with_context(|| format!("{}: choose a new file", path.display()))?;
                    std::io::Write::write_all(&mut f, out.as_bytes())?;
                    eprintln!("wrote {} lines to {}", out.lines().count(), path.display());
                }
                None => print!("{out}"),
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

fn print_invites(s: &Session, json_out: bool, created: bool, owner_file: Option<&Path>) -> Result<()> {
    let mut inv = s.invites()?;
    if let Some(path) = owner_file {
        let owner = inv.remove("owner").unwrap_or_default();
        if let Err(e) = write_private(path, &owner) {
            // The session exists now: hand out the owner link rather than lose it.
            eprintln!("could not write the owner invite file ({e:#}); printing it instead");
            inv.insert("owner".into(), owner);
        }
    }
    if json_out {
        let mut v =
            json!({"session_id": s.session_id, "expires_at_ms": s.manifest.expires_at_ms, "invites": inv});
        if let Some(path) = owner_file {
            v["owner_invite_file"] = json!(path);
        }
        print_json(&v);
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
    if let Some(path) = owner_file {
        println!("owner     (written to {})", path.display());
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
                let r = match send_path(&mut s, p).await {
                    Ok(r) => r,
                    Err(e) => {
                        // Say what already went out before failing.
                        if conn.json {
                            print_json(&json!({"sent": sent, "failed": p, "error": format!("{e:#}")}));
                        }
                        return Err(e.context(format!("sending {}", p.display())));
                    }
                };
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
                        &json!({"job": n.job, "status": "failed", "reason": "no_runner_available", "message": client::relay_text(&n.message)}),
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
            println!("submitted job {job}; get its result with: airlox result -- {job}");
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
    // Ids are base64url and may start with '-'.
    #[arg(allow_hyphen_values = true)]
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
            println!("no result yet for job {job}; check later with: airlox result --wait 5m -- {job}");
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
    Ok(exit_status(&r))
}

/// The process exit status for an outcome: the job's own exit code when the
/// runner signed one, else 1 (timed out, out of memory, cancelled, or failed
/// on the relay; `--json` tells these apart).
fn exit_status(r: &Outcome) -> i32 {
    match (r.signed, r.exit_code) {
        (true, Some(c)) if r.status == "completed" || c != 0 => c.clamp(0, 255) as i32,
        _ => 1,
    }
}

/// Save a job's out files into `dir`, never over an existing file. Only
/// the names runners produce (top-level images, `out.zip`) are saved.
pub fn save_out_files(r: &Outcome, dir: &Path) -> Result<Vec<String>> {
    let mut saved = Vec::new();
    for f in &r.out_files {
        let Some(data) = &f.data else { continue };
        let Some(name) = out_file_name(&f.name) else {
            eprintln!("   not saving out file {:?}: not an image or out.zip", clean_line(&f.name));
            continue;
        };
        saved.push(save_new(dir, name, data)?.display().to_string());
    }
    Ok(saved)
}

fn print_outcome(r: &Outcome, saved: &[String], hint: bool) {
    if !r.stdout.is_empty() {
        print!("{}", clean_text(&r.stdout));
        if !r.stdout.ends_with('\n') {
            println!();
        }
    }
    if !r.stderr.is_empty() {
        eprint!("{}", clean_text(&r.stderr));
        if !r.stderr.ends_with('\n') {
            eprintln!();
        }
    }
    let code = r.exit_code.map(|c| format!("exit {c}")).unwrap_or_else(|| "no exit code".into());
    let reason = r.reason.as_deref().map(|x| format!(" ({})", clean_line(x))).unwrap_or_default();
    let signed = if r.signed { "signed by the runner" } else { "reported by the relay, unsigned" };
    eprintln!("── {} · {code}{reason} · {} ms · {signed}", r.status, r.wall_ms);
    if r.stdout_truncated || r.stderr_truncated {
        eprintln!("   output was truncated by the runner");
    }
    for p in saved {
        eprintln!("   saved {p}");
    }
    let unsaved: Vec<_> =
        r.out_files.iter().filter(|f| f.data.is_some()).map(|f| clean_line(&f.name)).collect();
    if hint && !unsaved.is_empty() {
        eprintln!("   out files: {} (save them with --out-dir)", unsaved.join(", "));
    }
    let gone: Vec<_> = r.out_files.iter().filter(|f| f.data.is_none()).map(|f| clean_line(&f.name)).collect();
    if !gone.is_empty() {
        eprintln!("   left the relay before they were fetched: {}", gone.join(", "));
    }
}

#[derive(Args, Debug)]
pub struct CancelArgs {
    #[command(flatten)]
    pub conn: Conn,
    /// The job's id.
    // Ids are base64url and may start with '-'.
    #[arg(allow_hyphen_values = true)]
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
/// Markdown and Python files are inlined up to `max_content` bytes. A result
/// that is not a valid answer to its job (wrong runner, not approved) is
/// shown without its output.
pub fn item_json(s: &Session, i: &Item, max_content: Option<usize>) -> Value {
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
        "text" => match (max_content, m["text"].as_str()) {
            (Some(max), Some(t)) if t.len() > max => {
                let cut = (0..=max).rev().find(|&i| t.is_char_boundary(i)).unwrap_or(0);
                v["text"] = json!(&t[..cut]);
                v["text_truncated"] = json!(format!("{} bytes in all; the rest is not shown", t.len()));
            }
            _ => v["text"] = m["text"].clone(),
        },
        "file" => {
            v["name"] = m["name"].clone();
            v["mime"] = m["mime"].clone();
            v["size"] = json!(i.body.len());
            if i.subkind.as_deref() == Some("md") || i.subkind.as_deref() == Some("py") {
                match max_content {
                    Some(max) if i.body.len() > max => {
                        v["content_omitted"] =
                            json!(format!("larger than {max} bytes; save the file to read it"));
                    }
                    _ => v["content"] = json!(String::from_utf8_lossy(&i.body)),
                }
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
            let valid = s.result_is_valid(i);
            v["valid"] = json!(valid);
            if !valid {
                v["error"] = json!("not a valid result for this job: wrong or unapproved runner");
                return v;
            }
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

/// One item as a line of text. Everything a participant chose (names, text,
/// file names) goes through `clean_line`, so it cannot forge other lines or
/// drive the terminal.
fn item_line(s: &Session, i: &Item) -> String {
    let who = format!(
        "{} ({})",
        clean_line(i.author_name.as_deref().unwrap_or("?")),
        i.author_role.as_deref().unwrap_or("?")
    );
    let what = match i.status {
        Status::Ok => match i.kind.as_str() {
            "text" => clean_line(i.text().unwrap_or_default()),
            "file" => format!("file {} ({} bytes)", clean_line(i.name().unwrap_or("?")), i.body.len()),
            "job" => {
                let m = i.meta.as_ref();
                let name = m.map(|m| m["filename"].as_str().unwrap_or("?")).unwrap_or("?");
                format!("job {} → {}", clean_line(name), i.id)
            }
            "result" if !s.result_is_valid(i) => "result REJECTED: wrong or unapproved runner".into(),
            "result" => {
                let m = i.meta.as_ref().unwrap();
                clean_line(&format!(
                    "result for {}: {} exit {}",
                    m["job"]["id"].as_str().unwrap_or("?"),
                    m["status"].as_str().unwrap_or("?"),
                    m["exit_code"]
                ))
            }
            "event" => {
                format!("event {}", clean_line(i.meta.as_ref().unwrap()["event"].as_str().unwrap_or("?")))
            }
            k => clean_line(k),
        },
        Status::Evicted => format!("{} (left the relay before it was fetched)", clean_line(&i.kind)),
        Status::Pending => format!("{} (not fetched yet)", clean_line(&i.kind)),
        Status::Rejected => {
            format!("{} REJECTED: {}", clean_line(&i.kind), clean_line(i.error.as_deref().unwrap_or("?")))
        }
    };
    format!("#{:<4} {who}: {what}", i.seq)
}

/// Save a received file in `dir` under [`received_name`] (never a name the
/// sender picked, Python as `.py.txt`), and never over an existing file.
pub fn save_item(i: &Item, dir: &Path) -> Result<PathBuf> {
    let name = i.name().filter(|_| i.status == Status::Ok).context("the item is not an available file")?;
    let meta = i.meta.as_ref().context("the item is not an available file")?;
    let name = received_name(
        name,
        i.subkind.as_deref().unwrap_or_default(),
        meta["mime"].as_str().unwrap_or_default(),
    )
    .context("the file's name is not safe to save")?;
    save_new(dir, &name, &i.body)
}

fn emit(s: &Session, i: &Item, a: &ItemsArgs) -> Result<()> {
    let saved = match &a.save {
        Some(dir) if i.name().is_some() && i.status == Status::Ok => match save_item(i, dir) {
            Ok(p) => Some(p.display().to_string()),
            Err(e) => {
                eprintln!("not saving item {}: {e:#}", i.id);
                None
            }
        },
        _ => None,
    };
    if a.conn.json {
        let mut v = item_json(s, i, None);
        if let Some(p) = saved {
            v["saved"] = json!(p);
        }
        println!("{}", serde_json::to_string(&v)?);
    } else {
        println!("{}", item_line(s, i));
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
    for i in s.items() {
        emit(&s, i, &a)?;
    }
    Ok(())
}

/// Print items as they arrive (after the history, unless `--new`).
pub async fn watch(a: WatchArgs) -> Result<()> {
    let mut s = a.items.conn.join().await?;
    s.sync().await?;
    if !a.new {
        for i in s.items() {
            emit(&s, i, &a.items)?;
        }
    }
    let args = &a.items;
    s.stream(a.timeout, &mut |s, i| {
        emit(s, i, args)?;
        Ok(true)
    })
    .await?;
    if let Some(c) = &s.closed {
        eprintln!("session ended: {}", clean_line(c));
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
        println!(
            "{:<20} {:<18} {} on {} [{}]{net}",
            clean_line(&r.name),
            state,
            clean_line(&r.sandbox),
            clean_line(&r.host),
            clean_line(&r.labels.join(","))
        );
        if let Some(d) = &r.description {
            println!("{:<20} {}", "", clean_line(d));
        }
    }
    Ok(())
}

pub async fn runner_approve(conn: Conn, name: String) -> Result<()> {
    let mut s = conn.join().await?;
    let r = s.approve_runner(&name).await?;
    if conn.json {
        print_json(&json!({"approved": r}));
    } else {
        println!("approved {} ({} on {})", clean_line(&r.name), clean_line(&r.sandbox), clean_line(&r.host));
    }
    Ok(())
}

pub async fn runner_reject(conn: Conn, name: String, reason: Option<String>) -> Result<()> {
    let mut s = conn.join().await?;
    let r = s.reject_runner(&name, reason.as_deref()).await?;
    if conn.json {
        print_json(&json!({"rejected": r}));
    } else {
        println!("rejected {}", clean_line(&r.name));
    }
    Ok(())
}
