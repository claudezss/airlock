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
use crate::files::{clean_line, clean_text, out_file_name, received_name, save_new, unpack_out_zip};
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

/// A session lifetime: a duration, or `never` (`None`).
#[derive(Clone, Copy, Debug)]
pub struct Lifetime(pub Option<Duration>);

pub fn parse_lifetime(s: &str) -> Result<Lifetime, String> {
    if s.trim() == "never" {
        return Ok(Lifetime(None));
    }
    parse_duration(s).map(|d| Lifetime(Some(d)))
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
    /// Session lifetime, e.g. 30m, 1h, 1d (at most 30d), or `never` for a
    /// session that lasts until it is closed (if the relay allows it).
    #[arg(long, default_value = "1h", value_parser = parse_lifetime)]
    pub ttl: Lifetime,
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
pub(crate) fn write_private(path: &Path, link: &str) -> Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o.open(path).with_context(|| format!("creating {}", path.display()))?;
    std::io::Write::write_all(&mut f, format!("{link}\n").as_bytes())?;
    Ok(())
}

#[derive(Args, Debug)]
pub struct ReceiveArgs {
    /// The one-time code shown on the other machine, like 7-guitar-orbit.
    pub code: String,
    /// The relay the code was made on.
    #[arg(long, env = "AIRLOX_RELAY", default_value = "https://airlox.app")]
    pub relay: String,
}

/// Print the invite link a transfer code carries.
pub async fn receive(a: ReceiveArgs) -> Result<()> {
    let invite = client::receive_code(&client::http()?, &a.relay, &a.code).await?;
    println!("{invite}");
    eprintln!("The code is used up. Pass this link as --invite or AIRLOX_INVITE, and keep it private.");
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
                ttl_ms: a.ttl.0.map(|t| t.as_millis() as u64),
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
                println!("expires   {}", expiry(m.expires_at_ms));
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
            let out = s.audit().await?;
            match &a.out {
                Some(path) => {
                    let mut opts = std::fs::OpenOptions::new();
                    opts.write(true).create_new(true);
                    #[cfg(unix)]
                    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
                    let mut f =
                        opts.open(path).with_context(|| format!("{}: choose a new file", path.display()))?;
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
        println!("created session {} (expires {})", s.session_id, expiry(s.manifest.expires_at_ms));
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

/// "in 3 h 5 min", or "never".
fn expiry(at_ms: Option<u64>) -> String {
    at_ms.map_or_else(|| "never".into(), |t| format!("in {}", human_left(t)))
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
    /// A file in the job's work dir (e.g. a simulator's log) whose tail the
    /// runner posts as progress while the job runs.
    #[arg(long)]
    pub progress_file: Option<String>,
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
        progress_file: a.progress_file.clone(),
    };
    let (job, runner) = match s.run_python(spec).await {
        Ok(j) => j,
        Err(e) => {
            if let Some(n) = e.downcast_ref::<NoRunnerAvailable>() {
                if a.conn.json {
                    print_json(
                        &json!({"job": n.job, "status": "failed", "reason": n.reason, "message": client::relay_text(&n.message)}),
                    );
                    return Ok(1);
                }
            }
            return Err(e);
        }
    };
    if a.no_wait {
        if a.conn.json {
            let runner_name = runner.as_deref().and_then(|k| s.participant_name(k));
            print_json(&json!({"job": job, "runner": runner, "runner_name": runner_name}));
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
    let (saved, notes) = match out_dir {
        Some(d) => save_out_files(&r, d),
        None => (vec![], vec![]),
    };
    if json_out {
        let mut v = serde_json::to_value(&r)?;
        v["saved"] = json!(saved);
        v["notes"] = json!(notes);
        print_json(&v);
    } else if r.runner_lost() {
        eprintln!(
            "lost contact with the runner; it may still finish and post its result: airlox result --wait 30m -- {job}"
        );
    } else {
        print_outcome(&r, &saved, out_dir.is_none());
        for n in &notes {
            eprintln!("   {}", clean_line(n));
        }
    }
    Ok(exit_status(&r))
}

/// The process exit status for an outcome: the job's own exit code when the
/// runner signed one; 75 (EX_TEMPFAIL, as when the wait runs out) when the
/// relay lost the runner, which may still post a result; else 1 (timed out,
/// out of memory, cancelled, or failed on the relay; `--json` tells these
/// apart).
fn exit_status(r: &Outcome) -> i32 {
    if r.runner_lost() {
        return 75;
    }
    match (r.signed, r.exit_code) {
        (true, Some(c)) if r.status == "completed" || c != 0 => c.clamp(0, 255) as i32,
        _ => 1,
    }
}

/// Unpacked files listed by name in `saved`; past this, a note counts them.
const MAX_LISTED: usize = 20;

/// Save a job's out files into `dir`, never over an existing file: the
/// names runners produce (top-level images, `out.zip`), and `out.zip`
/// unpacked into a new `out/` beside it ([`unpack_out_zip`]). Returns what
/// was saved and notes on what was not. Saving never fails the result: a
/// file that cannot be saved is a note.
pub fn save_out_files(r: &Outcome, dir: &Path) -> (Vec<String>, Vec<String>) {
    let (mut saved, mut notes) = (Vec::new(), Vec::new());
    for f in &r.out_files {
        let Some(data) = &f.data else { continue };
        let Some(name) = out_file_name(&f.name) else {
            notes.push(format!("not saving out file {:?}: not an image or out.zip", clean_line(&f.name)));
            continue;
        };
        match save_new(dir, name, data) {
            Ok(p) => saved.push(p.display().to_string()),
            Err(e) => {
                notes.push(format!("could not save {name}: {e:#}"));
                continue;
            }
        }
        if name == "out.zip" {
            match unpack_out_zip(data, dir) {
                Ok((dest, files, skipped)) => {
                    saved.extend(files.iter().take(MAX_LISTED).map(|p| p.display().to_string()));
                    if files.len() > MAX_LISTED {
                        notes.push(format!("{} more files in {}", files.len() - MAX_LISTED, dest.display()));
                    }
                    notes.extend(skipped);
                }
                Err(e) => notes.push(format!("could not unpack out.zip (it is saved as is): {e:#}")),
            }
        }
    }
    (saved, notes)
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
    let signed = match (r.signed, &r.runner_name) {
        (true, Some(n)) => format!("signed by runner {}", clean_line(n)),
        (true, None) => "signed by the runner".into(),
        (false, _) => "reported by the relay, unsigned".into(),
    };
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
        // Posted by this participant: what it sent itself, not a reply.
        "mine": i.author == s.me,
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
            "progress" => progress_line(i.meta.as_ref().unwrap()),
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

/// Longest tail line shown for a progress item, in characters.
const PROGRESS_TAIL_CHARS: usize = 120;

/// "progress for <job>: running 2 min 5 s · <last line of the tail>".
fn progress_line(m: &Value) -> String {
    let job = clean_line(m["job"]["id"].as_str().unwrap_or("?"));
    let elapsed = human_elapsed(m["elapsed_ms"].as_u64().unwrap_or(0));
    // A carriage return ends a line too: progress bars redraw themselves with it.
    let last = m["tail"].as_str().and_then(|t| t.split(['\n', '\r']).rev().find(|l| !l.trim().is_empty()));
    match last {
        Some(l) => {
            let mut l = clean_line(l.trim());
            if l.chars().count() > PROGRESS_TAIL_CHARS {
                l = l.chars().take(PROGRESS_TAIL_CHARS).collect::<String>() + "…";
            }
            format!("progress for {job}: running {elapsed} · {l}")
        }
        None => format!("progress for {job}: running {elapsed}"),
    }
}

/// "45 s", "2 min 5 s", "3 h 10 min", "2 d 4 h".
fn human_elapsed(ms: u64) -> String {
    match ms / 1000 {
        s if s < 60 => format!("{s} s"),
        s if s < 3600 => format!("{} min {} s", s / 60, s % 60),
        s if s < 86_400 => format!("{} h {} min", s / 3600, (s % 3600) / 60),
        s => format!("{} d {} h", s / 86_400, (s % 86_400) / 3600),
    }
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
        let failed = r.detail.as_deref().map(|d| format!("failed: {}", clean_line(d)));
        let state = if r.rejected {
            "rejected"
        } else if r.state.as_deref() == Some("failed") {
            "setup failed"
        } else if r.state.as_deref() == Some("preparing") && !r.online {
            "preparing"
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
        let versions = match (&r.version, &r.python) {
            (Some(v), Some(p)) => format!(" · airlox {} · python {}", clean_line(v), clean_line(p)),
            (Some(v), None) => format!(" · airlox {}", clean_line(v)),
            (None, Some(p)) => format!(" · python {}", clean_line(p)),
            (None, None) => String::new(),
        };
        println!(
            "{:<20} {:<18} {} on {} [{}]{net}{versions}",
            clean_line(&r.name),
            state,
            clean_line(&r.sandbox),
            clean_line(&r.host),
            clean_line(&r.labels.join(","))
        );
        if let Some(d) = &r.description {
            println!("{:<20} {}", "", clean_line(d));
        }
        if let Some(f) = failed.filter(|_| r.state.as_deref() == Some("failed")) {
            println!("{:<20} {f}", "");
        }
    }
    Ok(())
}

#[derive(Args, Debug)]
pub struct WaitArgs {
    #[command(flatten)]
    pub conn: Conn,
    /// Runner name or key.
    pub runner: String,
    /// Also wait until the owner's signed approval has reached you, so a job
    /// sent next is not refused.
    #[arg(long)]
    pub approved: bool,
    /// Give up after this long.
    #[arg(long, default_value = "2m", value_parser = parse_duration)]
    pub timeout: Duration,
}

pub async fn runner_wait(a: WaitArgs) -> Result<i32> {
    let mut s = a.conn.join().await?;
    let deadline = std::time::Instant::now() + a.timeout;
    loop {
        let rs = s.runners().await?;
        // A key names one runner; only then names, of which a runner can
        // pick any (another's included), so a name two runners use is refused.
        let by_key: Vec<_> = rs.iter().filter(|r| r.participant_pub == a.runner).collect();
        let found =
            if by_key.is_empty() { rs.iter().filter(|r| r.name == a.runner).collect() } else { by_key };
        if found.len() > 1 {
            bail!(
                "more than one runner is called {}; use its key (airlox runner list)",
                clean_line(&a.runner)
            );
        }
        if let Some(r) = found.first() {
            let (code, what) = if r.state.as_deref() == Some("failed") {
                (
                    1,
                    format!(
                        "could not start: {}",
                        clean_line(r.detail.as_deref().unwrap_or("no reason given"))
                    ),
                )
            } else if r.rejected {
                (1, "was rejected".into())
            } else if r.online && (r.approved || !a.approved) {
                (0, if r.approved { "is online and approved".into() } else { "is online".into() })
            } else {
                (-1, String::new())
            };
            if code >= 0 {
                if a.conn.json {
                    print_json(&json!({"runner": r}));
                } else if code == 0 {
                    println!("runner {} {what}", clean_line(&r.name));
                } else {
                    eprintln!("runner {} {what}", clean_line(&r.name));
                }
                return Ok(code);
            }
        }
        if std::time::Instant::now() >= deadline {
            if a.conn.json {
                print_json(&json!({"runner": found.first(), "status": "timeout"}));
            }
            eprintln!("runner {} is not ready after {}s", clean_line(&a.runner), a.timeout.as_secs());
            return Ok(75); // EX_TEMPFAIL
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
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

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::session::OutFile;

    fn zip_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, data) in files {
            w.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn outcome(out_zip: Vec<u8>) -> Outcome {
        Outcome {
            job: "j".into(),
            status: "completed".into(),
            exit_code: Some(0),
            reason: None,
            stdout: String::new(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            wall_ms: 0,
            peak_mem_mb: 0,
            out_files: vec![OutFile {
                name: "out.zip".into(),
                size: out_zip.len() as u64,
                item_ref: json!({}),
                data: Some(out_zip),
            }],
            out_text: vec![],
            runner: None,
            runner_name: None,
            signed: true,
        }
    }

    #[test]
    fn out_zip_is_unpacked_beside_it_into_a_new_directory() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("out")).unwrap();
        std::fs::write(d.path().join("out/report.json"), "mine").unwrap();
        let r = outcome(zip_of(&[("report.json", b"{}"), ("logs/run.txt", b"ok")]));
        let (saved, notes) = save_out_files(&r, d.path());
        let names: Vec<_> =
            saved.iter().map(|p| Path::new(p).strip_prefix(d.path()).unwrap().to_owned()).collect();
        assert_eq!(
            names,
            [Path::new("out.zip"), Path::new("out (1)/report.json"), Path::new("out (1)/logs/run.txt")]
        );
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(std::fs::read_to_string(d.path().join("out/report.json")).unwrap(), "mine");
    }

    #[test]
    fn unpacked_files_are_never_ones_tools_load() {
        let d = tempfile::tempdir().unwrap();
        let r = outcome(zip_of(&[
            ("conftest.py", b"x"),
            ("tests/test_x.py", b"x"),
            ("CLAUDE.md", b"x"),
            ("Makefile", b"x"),
            ("package.json", b"x"),
            ("report.md", b"x"),
            (".envrc", b"x"),
            (".claude/settings.json", b"x"),
            (".git/config", b"x"),
        ]));
        let (saved, notes) = save_out_files(&r, d.path());
        let mut names: Vec<_> = saved
            .iter()
            .map(|p| p.strip_prefix(&*d.path().to_string_lossy()).unwrap().replace('\\', "/"))
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "/out.zip",
                "/out/CLAUDE.md.txt",
                "/out/Makefile.txt",
                "/out/conftest.py.txt",
                "/out/package.json.txt",
                "/out/report.md",
                "/out/tests/test_x.py.txt"
            ]
        );
        assert_eq!(notes.iter().filter(|n| n.contains("hidden")).count(), 3, "{notes:?}");
        assert!(!d.path().join("out/.git").exists() && !d.path().join("out/.claude").exists());
    }

    #[test]
    fn a_hostile_out_zip_writes_nothing_outside_and_keeps_the_result() {
        let d = tempfile::tempdir().unwrap();
        let inner = d.path().join("save");
        let r = outcome(zip_of(&[("ok.txt", b"x"), ("../escaped.txt", b"x")]));
        let (saved, notes) = save_out_files(&r, &inner);
        assert_eq!(saved.len(), 1, "out.zip itself is kept: {saved:?}");
        assert!(notes.iter().any(|n| n.contains("could not unpack out.zip")), "{notes:?}");
        assert!(!d.path().join("escaped.txt").exists());
        assert!(crate::session::out_text(&r.out_files).is_empty());
    }

    #[test]
    fn many_unpacked_files_are_counted_not_listed() {
        let d = tempfile::tempdir().unwrap();
        let names: Vec<String> = (0..50).map(|i| format!("f{i}.txt")).collect();
        let files: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), b"x".as_slice())).collect();
        let (saved, notes) = save_out_files(&outcome(zip_of(&files)), d.path());
        assert_eq!(saved.len(), 1 + MAX_LISTED);
        assert!(notes.iter().any(|n| n.starts_with("30 more files in")), "{notes:?}");
    }

    #[test]
    fn progress_lines_show_elapsed_time_and_the_last_line() {
        let m = json!({"job": {"id": "j1"}, "elapsed_ms": 125_000,
            "tail": "step 1\nstep 2\x1b[31m\n\n", "tail_truncated": false});
        assert_eq!(progress_line(&m), "progress for j1: running 2 min 5 s · step 2\\u{1b}[31m");
        let m = json!({"job": {"id": "j1"}, "elapsed_ms": 7_265_000,
            "tail": "10%\r50%\r90%\r", "tail_truncated": false});
        assert_eq!(progress_line(&m), "progress for j1: running 2 h 1 min · 90%");
        let m = json!({"job": {"id": "j1"}, "elapsed_ms": 4_000, "tail": null, "tail_truncated": false});
        assert_eq!(progress_line(&m), "progress for j1: running 4 s");
        let m =
            json!({"job": {"id": "j1"}, "elapsed_ms": 0, "tail": "x".repeat(500), "tail_truncated": true});
        assert_eq!(progress_line(&m), format!("progress for j1: running 0 s · {}…", "x".repeat(120)));
    }

    #[test]
    fn a_lost_runner_exits_like_a_wait_that_ran_out() {
        let mut r = outcome(vec![]);
        r.out_files.clear();
        (r.signed, r.status, r.reason) = (false, "failed".into(), Some("runner_lost".into()));
        assert_eq!(exit_status(&r), 75);
        r.reason = Some("no_runner_available".into());
        assert_eq!(exit_status(&r), 1);
    }
}
