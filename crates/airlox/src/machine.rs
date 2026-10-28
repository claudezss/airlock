//! `airlox machine`: a long-lived execute session with a name, so pairing a
//! machine and running jobs on it need no session vocabulary.
//!
//! ```text
//! <cache-dir>/machines/<name>/machine.json        the session, relay and approved runner
//! <cache-dir>/machines/<name>/invite-sender.txt   what `--on <name>` joins with (0600)
//! <cache-dir>/machines/<name>/owner/invite.txt    the owner invite (0600, in a 0700 dir)
//! ```
//!
//! Everything lives under the cache directory, which the MCP server's file
//! tools refuse, so neither invite is readable through them.

use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use airlox_core::cert::is_runner_token;
use airlox_core::session::{JobKind, JobLimits, Mode, DEFAULT_MAX_ITEM_BYTES};
use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::cli::{human_bytes, jobs_line, parse_duration, parse_kind, write_private};
use crate::client;
use crate::files::clean_line;
use crate::session::{default_cache_root, NewSession, Profile, Runner, Session, Status, DEFAULT_TYPES};

#[derive(Subcommand, Debug)]
pub enum MachineCmd {
    /// Pair a machine: create its session, print the one command to run on
    /// it, wait for that runner to join and approve it.
    Add(AddArgs),
    /// The machines you added: runners online, labels, kinds, sandbox, last job.
    Ls(LsArgs),
    /// An invite to a machine for another agent (a hosted one, say), as a
    /// link or a one-time code.
    Invite(InviteArgs),
    /// Approve a runner that joined a machine later (a second box in a pool).
    Approve(ApproveArgs),
    /// Close the machine's session: its runners exit and their workspaces
    /// are removed.
    Rm(RmArgs),
}

#[derive(Args, Debug, Clone)]
pub struct Common {
    /// Session cache directory (default: ~/.cache/airlox).
    #[arg(long, env = "AIRLOX_CACHE_DIR")]
    pub cache_dir: Option<PathBuf>,
    /// Your display name in the machine's session.
    #[arg(long = "as", env = "AIRLOX_NAME", default_value = "owner")]
    pub display_name: String,
    /// Print JSON instead of text.
    #[arg(long)]
    pub json: bool,
}

impl Common {
    fn root(&self) -> PathBuf {
        self.cache_dir.clone().unwrap_or_else(default_cache_root)
    }

    async fn owner(&self, name: &str) -> Result<(Machine, Session)> {
        let root = self.root();
        let m = Machine::load(&root, name)?;
        let link = std::fs::read_to_string(m.owner_file(&root))
            .with_context(|| format!("machine {name} has no owner invite; add it again"))?;
        let me = Profile::new(&self.display_name, None);
        let s = Session::join(&client::http()?, link.trim(), &me, &root).await?;
        Ok((m, s))
    }
}

#[derive(Args, Debug)]
pub struct AddArgs {
    /// The machine's name, which is also its runner's name: [a-z0-9][a-z0-9._-]{0,62}.
    pub name: String,
    /// Relay URL.
    #[arg(long, env = "AIRLOX_RELAY", default_value = "https://airlox.app")]
    pub relay: String,
    /// Labels for the runner, comma-separated (put in the printed command).
    #[arg(long, value_delimiter = ',')]
    pub labels: Vec<String>,
    /// Kinds of job allowed, comma-separated: python, shell.
    #[arg(long, value_delimiter = ',', value_parser = parse_kind, default_value = "python,shell")]
    pub kinds: Vec<JobKind>,
    /// Longest a job may run.
    #[arg(long, default_value = "30m", value_parser = parse_duration)]
    pub timeout: Duration,
    /// Job memory limit (MB).
    #[arg(long, default_value_t = 4096)]
    pub memory: u32,
    /// Let jobs reach the network (CI against a database needs it; most
    /// numerics do not).
    #[arg(long)]
    pub network: bool,
    /// A package python jobs may use (repeat), as for `session create`.
    #[arg(long = "package")]
    pub packages: Vec<String>,
    /// The sandbox to put in the printed command [default: docker with
    /// --image, else local].
    #[arg(long, value_parser = ["docker", "local", "process"])]
    pub sandbox: Option<String>,
    /// docker: the image jobs run in, with the project's toolchain and python3
    /// (put in the printed command; shell jobs need it).
    #[arg(long)]
    pub image: Option<String>,
    /// Jobs the runner runs at once, 1 to 16 (put in the printed command).
    /// Each gets the full --memory; a sender's workspace serves one at a
    /// time.
    #[arg(
        long,
        default_value_t = 1,
        value_parser = clap::value_parser!(u32).range(1..=airlox_core::cert::MAX_SLOTS as i64)
    )]
    pub concurrency: u32,
    /// Make the code and print the command, but do not wait for the runner;
    /// approve it later with `airlox machine approve`.
    #[arg(long)]
    pub no_wait: bool,
    /// Approve the runner that used the code without asking first (at a
    /// terminal, `machine add` shows it and asks).
    #[arg(long, short = 'y')]
    pub yes: bool,
    /// How long to wait for the runner to join.
    #[arg(long, default_value = "30m", value_parser = parse_duration)]
    pub wait: Duration,
    #[command(flatten)]
    pub common: Common,
}

#[derive(Args, Debug)]
pub struct LsArgs {
    #[command(flatten)]
    pub common: Common,
}

#[derive(Args, Debug)]
pub struct InviteArgs {
    pub name: String,
    /// The role to invite: sender (submits jobs), observer (reads), or
    /// runner (another box for the machine's pool).
    #[arg(long, default_value = "sender", value_parser = ["sender", "observer", "runner"])]
    pub role: String,
    /// A one-time code for the invite instead of the link.
    #[arg(long)]
    pub code: bool,
    #[command(flatten)]
    pub common: Common,
}

#[derive(Args, Debug)]
pub struct ApproveArgs {
    pub name: String,
    /// The runner to approve (name or key); the only one waiting, if unsaid.
    pub runner: Option<String>,
    #[command(flatten)]
    pub common: Common,
}

#[derive(Args, Debug)]
pub struct RmArgs {
    pub name: String,
    #[command(flatten)]
    pub common: Common,
}

/// `machine.json`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Machine {
    pub name: String,
    pub session_id: String,
    pub relay: String,
    /// The runner `machine add` approved, once it has.
    #[serde(default)]
    pub runner_pub: Option<String>,
    pub created_at_ms: u64,
}

/// `name` and the label of `--on name/label`.
pub fn split_on(on: &str) -> (&str, Option<&str>) {
    match on.split_once('/') {
        Some((n, l)) if !l.is_empty() => (n, Some(l)),
        Some((n, _)) => (n, None),
        None => (on, None),
    }
}

fn machines_dir(root: &Path) -> PathBuf {
    root.join("machines")
}

fn check_name(name: &str) -> Result<()> {
    if !is_runner_token(name) {
        bail!("{name:?} is not a valid machine name: use [a-z0-9][a-z0-9._-]{{0,62}}");
    }
    Ok(())
}

/// The sender invite `--on <name>` joins with.
pub fn sender_invite(root: &Path, name: &str) -> Result<String> {
    check_name(name)?;
    let path = machines_dir(root).join(name).join("invite-sender.txt");
    match std::fs::read_to_string(&path) {
        Ok(s) => Ok(s.trim().to_string()),
        Err(_) => bail!("no machine named {name}; add it with: airlox machine add {name}"),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

impl Machine {
    fn dir(&self, root: &Path) -> PathBuf {
        machines_dir(root).join(&self.name)
    }

    fn owner_file(&self, root: &Path) -> PathBuf {
        self.dir(root).join("owner").join("invite.txt")
    }

    fn load(root: &Path, name: &str) -> Result<Machine> {
        check_name(name)?;
        let path = machines_dir(root).join(name).join("machine.json");
        let raw = std::fs::read(&path).map_err(|_| {
            anyhow::anyhow!("no machine named {name}; add it with: airlox machine add {name}")
        })?;
        serde_json::from_slice(&raw).with_context(|| format!("reading {}", path.display()))
    }

    fn save(&self, root: &Path) -> Result<()> {
        crate::view::write_atomic(
            &self.dir(root).join("machine.json"),
            &serde_json::to_vec_pretty(self)?,
            0o600,
        )
    }

    fn all(root: &Path) -> Vec<Machine> {
        let mut out: Vec<Machine> = std::fs::read_dir(machines_dir(root))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| Machine::load(root, e.file_name().to_str()?).ok())
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }
}

pub async fn machine(cmd: MachineCmd) -> Result<()> {
    match cmd {
        MachineCmd::Add(a) => add(a).await,
        MachineCmd::Ls(a) => ls(a).await,
        MachineCmd::Invite(a) => invite(a).await,
        MachineCmd::Approve(a) => approve(a).await,
        MachineCmd::Rm(a) => rm(a).await,
    }
}

/// The machine's session, or the one a previous `add` of this name made
/// (whose runner never joined, say).
async fn session_for(a: &AddArgs, root: &Path) -> Result<(Machine, Session, bool)> {
    let me = Profile::new(&a.common.display_name, None);
    if let Ok(m) = Machine::load(root, &a.name) {
        if m.runner_pub.is_some() {
            bail!(
                "machine {} already has its runner; `airlox machine invite {} --role runner --code` adds another \
                 box, `airlox machine rm {}` starts over",
                a.name,
                a.name,
                a.name
            );
        }
        let (m, s) = a.common.owner(&a.name).await?;
        return Ok((m, s, false));
    }
    let http = client::http()?;
    let packages: Vec<String> =
        a.packages.iter().flat_map(|p| p.split(',')).map(|p| p.trim().to_string()).collect();
    let mut kinds = a.kinds.clone();
    kinds.sort();
    kinds.dedup();
    let new = NewSession {
        mode: Mode::Execute,
        ttl_ms: None,
        allowed_types: DEFAULT_TYPES.iter().map(|s| s.to_string()).collect(),
        max_item_bytes: client::relay_max_item_bytes(&http, &a.relay).await.unwrap_or(DEFAULT_MAX_ITEM_BYTES),
        job_limits: Some(JobLimits {
            timeout_s: a.timeout.as_secs().max(1) as u32,
            memory_mb: a.memory,
            network: a.network,
            packages: packages.into_iter().filter(|p| !p.is_empty()).collect(),
            approve_runners: true,
            kinds: crate::cli::job_kinds(&kinds, false),
            workspace: true,
            ..JobLimits::default()
        }),
        insecure_http_host: None,
    };
    let s = Session::create(&http, &a.relay, new, &me, root).await?;
    let m = Machine {
        name: a.name.clone(),
        session_id: s.session_id.clone(),
        relay: s.base_url.clone(),
        runner_pub: None,
        created_at_ms: now_ms(),
    };
    // Saved before anything can fail, so the session is never lost.
    let dir = m.dir(root);
    private_dir(&dir)?;
    private_dir(&dir.join("owner"))?;
    let invites = s.invites()?;
    write_private(&m.owner_file(root), &invites["owner"])?;
    write_private(&dir.join("invite-sender.txt"), &invites["sender"])?;
    m.save(root)?;
    Ok((m, s, true))
}

fn shell_quote(s: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || "-_./:@=+,".contains(c);
    if !s.is_empty() && s.chars().all(safe) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// The sandbox the printed command names.
fn sandbox_of(a: &AddArgs) -> String {
    a.sandbox.clone().unwrap_or_else(|| if a.image.is_some() { "docker" } else { "local" }.into())
}

/// The `runner join` line to run on the machine. It never says
/// `--accept-network-gap`: whoever runs it on the machine adds that, knowing
/// what it accepts.
fn join_line(a: &AddArgs, code: &str, relay: &str) -> String {
    let mut line = format!("airlox runner join --code {code}");
    if relay != crate::runner::DEFAULT_RELAY {
        line.push_str(&format!(" --relay {}", shell_quote(relay)));
    }
    line.push_str(&format!(" --name {}", a.name));
    if !a.labels.is_empty() {
        line.push_str(&format!(" --labels {}", shell_quote(&a.labels.join(","))));
    }
    let sandbox = sandbox_of(a);
    line.push_str(&format!(" --sandbox {sandbox}"));
    if let Some(img) = &a.image {
        line.push_str(&format!(" --image {}", shell_quote(img)));
    }
    if a.concurrency > 1 {
        line.push_str(&format!(" --concurrency {}", a.concurrency));
    }
    line.push_str(" --workspace");
    line
}

async fn add(a: AddArgs) -> Result<()> {
    check_name(&a.name)?;
    for l in &a.labels {
        if !is_runner_token(l) {
            bail!("{l:?} is not a valid label: use [a-z0-9][a-z0-9._-]{{0,62}}");
        }
    }
    let root = a.common.root();
    let (m, mut s, created) = session_for(&a, &root).await?;
    let http = client::http()?;
    let invites = s.invites()?;
    let code = client::send_code(&http, &s.base_url, &invites["runner"]).await?;
    let limits = s.manifest.job_limits.clone().context("execute session without job limits")?;
    let line = join_line(&a, &code.code, &s.base_url);
    if a.common.json {
        println!(
            "{}",
            json!({"machine": a.name, "session_id": m.session_id, "created": created, "code": code.code,
                   "expires_at_ms": code.expires_at_ms, "command": line})
        );
    } else {
        if created {
            eprintln!("Machine {} · {}", a.name, jobs_line(&limits));
            if !limits.network && sandbox_of(&a) != "process" {
                eprintln!("Jobs have no network; add the machine with --network if they need it.");
            }
        }
        if sandbox_of(&a) == "process" {
            eprintln!(
                "Warning: --sandbox process runs jobs as plain processes of the runner's user: they can read \
                 that user's files and reach the network{}. Send it only code you trust, or use --sandbox \
                 docker (or local, where it isolates).",
                if limits.network {
                    ""
                } else {
                    ", whatever the session says. The runner starts only with --accept-network-gap added to \
                     the command below, by whoever runs it there"
                }
            );
        }
        eprintln!("On {}, run (the code works once, for a few minutes):\n\n  {line}\n", a.name);
    }
    if a.no_wait {
        if !a.common.json {
            eprintln!("Then approve it with: airlox machine approve {}", a.name);
        }
        return Ok(());
    }
    if !a.common.json {
        eprintln!("Waiting for it to join (Ctrl-C stops waiting and cancels the code)…");
    }
    let deadline = tokio::time::Instant::now() + a.wait;
    let claimed = async {
        loop {
            match code.status(&http).await? {
                (st, _) if st == "waiting" => {
                    if tokio::time::Instant::now() >= deadline {
                        code.cancel(&http).await?;
                        bail!("no runner used the code within {} s", a.wait.as_secs());
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await
                }
                (st, claimant) if st == "picked_up" => return Ok::<_, anyhow::Error>(claimant),
                (st, _) => bail!("the code no longer works ({})", clean_line(&st)),
            }
        }
    };
    let claimant = tokio::select! {
        r = claimed => r?,
        _ = tokio::signal::ctrl_c() => {
            let _ = code.cancel(&http).await;
            bail!("stopped waiting; the code is cancelled. Run `airlox machine add {}` again for a new one", a.name);
        }
    };
    let Some(key) = claimant else {
        if a.common.json {
            println!("{}", json!({"machine": a.name, "state": "picked_up", "approved": null}));
        } else {
            eprintln!(
                "The code was used, but the relay did not say by whom, so nothing is approved. Once the runner \
                 has joined, check it and approve it: airlox machine approve {}",
                a.name
            );
        }
        return Ok(());
    };
    // The claimant joins once it has the invite; then approve exactly it.
    let runner = loop {
        let found = s.runners().await?.into_iter().find(|r| r.participant_pub == key);
        if let Some(r) = found {
            break r;
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "the code was used, but runner {} did not join within {} s; approve it later with: airlox \
                 machine approve {}",
                airlox_core::keys::PublicKey::from_b64(&key).map(|k| k.fingerprint()).unwrap_or_default(),
                a.wait.as_secs(),
                a.name
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    // The code went to one machine under this name; a runner that joined as
    // something else is not the one this command set up.
    let leave = |why: String| -> Result<()> {
        bail!(
            "{why}; it is not approved. If it is yours, approve it with: airlox machine approve {} (or remove              the machine with airlox machine rm {})",
            a.name,
            a.name
        )
    };
    if runner.name != a.name {
        return leave(format!(
            "the runner that used the code joined as {:?}, not {:?}",
            clean_line(&runner.name),
            a.name
        ));
    }
    // A code is a secret on a screen: at a terminal, show who used it
    // before approving.
    if !a.yes && !a.common.json && std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        eprint!(
            "Runner {} on host {} ({} sandbox), key {}, used the code.\nCheck the key against the one the \
             runner printed when it joined. Approve it? [y/N] ",
            clean_line(&runner.name),
            clean_line(&runner.host),
            clean_line(&runner.sandbox),
            fingerprint(&runner.participant_pub)
        );
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            return leave("you did not approve it".into());
        }
    }
    let runner = s.approve_runner(&runner.participant_pub).await?;
    let mut m = m;
    m.runner_pub = Some(runner.participant_pub.clone());
    m.save(&root)?;
    // Say how its setup goes: a runner that cannot prepare shows up here.
    let mut state = runner.state.clone();
    let setup_until = tokio::time::Instant::now() + Duration::from_secs(600).min(a.wait);
    while !matches!(state.as_deref(), Some("ready" | "failed")) && tokio::time::Instant::now() < setup_until {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let now = s.runners().await?.into_iter().find(|r| r.participant_pub == runner.participant_pub);
        if let Some(r) = now {
            if r.state != state && !a.common.json {
                eprintln!("  {}: {}", clean_line(&r.name), r.state.as_deref().unwrap_or("joined"));
            }
            state = r.state.clone();
            if r.state.as_deref() == Some("failed") {
                bail!(
                    "runner {} could not prepare its sandbox: {}",
                    clean_line(&r.name),
                    clean_line(r.detail.as_deref().unwrap_or("no detail"))
                );
            }
        }
    }
    if a.common.json {
        println!(
            "{}",
            json!({"machine": a.name, "runner": runner.participant_pub, "runner_name": runner.name,
                   "approved": true, "state": state})
        );
    } else {
        eprintln!(
            "Approved runner {} ({}). Run jobs on it from any checkout:\n\n  airlox run --on {} --tree -- <command>\n",
            clean_line(&runner.name),
            fingerprint(&runner.participant_pub),
            a.name
        );
        if state.as_deref() != Some("ready") {
            eprintln!("It is still preparing; `airlox machine ls` shows when it is ready.");
        }
    }
    Ok(())
}

fn fingerprint(key: &str) -> String {
    airlox_core::keys::PublicKey::from_b64(key).map(|k| k.fingerprint()).unwrap_or_else(|_| key.to_string())
}

/// What a machine's runners last reported in their signed results:
/// `runner key -> (kinds, interpreter)`, and the newest job's id, age and
/// state.
fn last_seen(s: &Session) -> (std::collections::HashMap<String, Value>, Option<Value>) {
    let mut envs = std::collections::HashMap::new();
    let mut last_job: Option<Value> = None;
    for i in s.items() {
        if i.status != Status::Ok {
            continue;
        }
        let Some(m) = i.meta.as_ref() else { continue };
        if i.kind == "result" && s.result_is_valid(i) {
            if let Some(env) = m.get("env").filter(|e| e.is_object()) {
                envs.insert(i.author.clone(), env.clone());
            }
        }
        if i.kind == "job" {
            let status = s.result(&i.id).map(|r| json!(r.status)).unwrap_or(json!("running"));
            last_job = Some(json!({"job": i.id, "created_at_ms": i.created_at_ms, "status": status}));
        }
    }
    (envs, last_job)
}

fn runner_json(r: &Runner, env: Option<&Value>) -> Value {
    json!({
        "name": r.name,
        "participant_pub": r.participant_pub,
        "online": r.online,
        "approved": r.approved,
        "rejected": r.rejected,
        "state": r.state,
        "labels": r.labels,
        "sandbox": r.sandbox,
        "kinds": r.kinds,
        "shell": r.shell,
        "interpreter": env.map(|e| e["interpreter"].clone()).unwrap_or(Value::Null),
        "jobs": r.jobs,
        "slots": r.slots,
        "busy": r.busy,
    })
}

fn ago(ms: u64) -> String {
    let s = now_ms().saturating_sub(ms) / 1000;
    match s {
        s if s < 60 => format!("{s} s ago"),
        s if s < 3600 => format!("{} min ago", s / 60),
        s if s < 86400 => format!("{} h ago", s / 3600),
        s => format!("{} d ago", s / 86400),
    }
}

async fn ls(a: LsArgs) -> Result<()> {
    let root = a.common.root();
    let machines = Machine::all(&root);
    let mut out = Vec::new();
    for m in &machines {
        let entry = match a.common.owner(&m.name).await {
            Ok((_, mut s)) => match s.runners().await {
                Ok(runners) => {
                    let (envs, last_job) = last_seen(&s);
                    let limits = s.manifest.job_limits.clone();
                    json!({
                        "machine": m.name,
                        "session_id": m.session_id,
                        "relay": m.relay,
                        "jobs": limits.as_ref().map(jobs_line),
                        "max_item": human_bytes(s.manifest.max_item_bytes),
                        "runners": runners.iter().map(|r| runner_json(r, envs.get(&r.participant_pub))).collect::<Vec<_>>(),
                        "last_job": last_job,
                        "closed": s.closed,
                    })
                }
                Err(e) => json!({"machine": m.name, "session_id": m.session_id, "error": format!("{e:#}")}),
            },
            Err(e) => json!({"machine": m.name, "session_id": m.session_id, "error": format!("{e:#}")}),
        };
        out.push(entry);
    }
    if a.common.json {
        println!("{}", serde_json::to_string_pretty(&json!({"machines": out}))?);
        return Ok(());
    }
    if out.is_empty() {
        println!("no machines; add one with: airlox machine add <name>");
        return Ok(());
    }
    for e in &out {
        let name = e["machine"].as_str().unwrap_or_default();
        if let Some(err) = e["error"].as_str() {
            println!("{name:<16} unavailable: {}", clean_line(err));
            continue;
        }
        if let Some(c) = e["closed"].as_str() {
            println!("{name:<16} closed: {}", clean_line(c));
            continue;
        }
        let runners = e["runners"].as_array().cloned().unwrap_or_default();
        let online = runners.iter().filter(|r| r["online"] == true && r["approved"] == true).count();
        let approved = runners.iter().filter(|r| r["approved"] == true).count();
        let last = match &e["last_job"] {
            Value::Null => "no jobs yet".to_string(),
            j => format!(
                "last job {} ({})",
                ago(j["created_at_ms"].as_u64().unwrap_or(0)),
                j["status"].as_str().unwrap_or("?")
            ),
        };
        println!("{name:<16} {online}/{approved} online · {last}");
        println!("{:<16} {}", "", e["jobs"].as_str().unwrap_or_default());
        for r in &runners {
            let kinds = r["kinds"]
                .as_array()
                .map(|k| k.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(","))
                .filter(|k| !k.is_empty())
                .unwrap_or_else(|| "kinds unknown".into());
            let kinds = match r["shell"].as_str() {
                Some(sh) => format!("{kinds} ({sh})"),
                None => kinds,
            };
            let mut parts = vec![
                clean_line(r["name"].as_str().unwrap_or_default()),
                if r["online"] == true { "online".into() } else { "offline".into() },
                clean_line(r["state"].as_str().unwrap_or("joined")),
            ];
            if r["approved"] != true {
                parts.push(if r["rejected"] == true {
                    "rejected".into()
                } else {
                    "awaiting approval".into()
                });
            }
            let labels: Vec<&str> = r["labels"]
                .as_array()
                .map(|l| l.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            if !labels.is_empty() {
                parts.push(format!("labels {}", clean_line(&labels.join(","))));
            }
            parts.push(clean_line(&kinds));
            parts.push(format!("{} sandbox", clean_line(r["sandbox"].as_str().unwrap_or("?"))));
            if let Some(i) = r["interpreter"].as_str() {
                parts.push(clean_line(i));
            }
            let jobs: Vec<&str> = r["jobs"]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            if r["slots"].as_u64().unwrap_or(1) > 1 {
                parts.push(format!("{}/{} jobs", jobs.len(), r["slots"]));
            } else if let Some(j) = jobs.first() {
                parts.push(format!("running {}", clean_line(j)));
            }
            println!("{:<16}   {}", "", parts.join(" · "));
        }
        if runners.is_empty() {
            println!("{:<16}   no runner has joined; `airlox machine add {name}` makes a new code", "");
        }
    }
    Ok(())
}

async fn invite(a: InviteArgs) -> Result<()> {
    let (_, s) = a.common.owner(&a.name).await?;
    let invites = s.invites()?;
    let link = invites.get(&a.role).context("no such invite")?;
    if !a.code {
        if a.common.json {
            println!("{}", json!({"machine": a.name, "role": a.role, "invite": link}));
        } else {
            println!("{link}");
            eprintln!(
                "The {} invite to machine {}: whoever holds it can {}. Hand it over as AIRLOX_INVITE, only on a \
                 channel you trust.",
                a.role,
                a.name,
                match a.role.as_str() {
                    "sender" => "submit sandboxed jobs to its approved runners",
                    "observer" => "read its jobs and results",
                    _ => "join as a runner (which still needs your approval)",
                }
            );
        }
        return Ok(());
    }
    let http = client::http()?;
    let code = client::send_code(&http, &s.base_url, link).await?;
    let relay = if s.base_url == crate::runner::DEFAULT_RELAY {
        String::new()
    } else {
        format!(" --relay {}", shell_quote(&s.base_url))
    };
    let to_type = match a.role.as_str() {
        "runner" => format!("airlox runner join --code {}{relay} --name <name> --workspace ...", code.code),
        _ => format!("airlox receive {}{relay}", code.code),
    };
    if a.common.json {
        println!(
            "{}",
            json!({"machine": a.name, "role": a.role, "code": code.code, "expires_at_ms": code.expires_at_ms, "command": to_type})
        );
    } else {
        println!("{}", code.code);
        eprintln!(
            "One-time code for the {} invite to machine {}. On the other side:\n  {to_type}",
            a.role, a.name
        );
        if a.role == "runner" {
            eprintln!("Then approve it: airlox machine approve {} <runner>", a.name);
        }
    }
    Ok(())
}

async fn approve(a: ApproveArgs) -> Result<()> {
    let (mut m, mut s) = a.common.owner(&a.name).await?;
    let which = match &a.runner {
        Some(r) => r.clone(),
        None => {
            let waiting: Vec<Runner> =
                s.runners().await?.into_iter().filter(|r| !r.approved && !r.rejected).collect();
            match waiting.as_slice() {
                [] => bail!("no runner of machine {} is waiting for approval", a.name),
                [one] => one.participant_pub.clone(),
                many => bail!(
                    "{} runners are waiting: {}; name one",
                    many.len(),
                    many.iter()
                        .map(|r| format!("{} ({})", clean_line(&r.name), fingerprint(&r.participant_pub)))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }
        }
    };
    let r = s.approve_runner(&which).await?;
    if m.runner_pub.is_none() {
        m.runner_pub = Some(r.participant_pub.clone());
        m.save(&a.common.root())?;
    }
    if a.common.json {
        println!("{}", json!({"machine": a.name, "approved": r.participant_pub, "name": r.name}));
    } else {
        println!(
            "approved runner {} ({}) on machine {}",
            clean_line(&r.name),
            fingerprint(&r.participant_pub),
            a.name
        );
    }
    Ok(())
}

async fn rm(a: RmArgs) -> Result<()> {
    let root = a.common.root();
    let m = Machine::load(&root, &a.name)?;
    match a.common.owner(&a.name).await {
        Ok((_, mut s)) => {
            if s.closed.is_none() {
                s.close().await?;
            }
        }
        Err(e) => eprintln!("note: could not reach machine {}'s session ({e:#}); removing it here", a.name),
    }
    std::fs::remove_dir_all(m.dir(&root)).with_context(|| format!("removing {}", m.dir(&root).display()))?;
    if a.common.json {
        println!("{}", json!({"removed": a.name, "session_id": m.session_id}));
    } else {
        println!(
            "removed machine {}: its session is closed, its runners exit and drop its workspaces",
            a.name
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_names_a_machine_and_maybe_a_label() {
        assert_eq!(split_on("gpu-box"), ("gpu-box", None));
        assert_eq!(split_on("pool/gpu"), ("pool", Some("gpu")));
        assert_eq!(split_on("pool/"), ("pool", None));
    }

    #[test]
    fn the_join_line_carries_what_the_runner_needs() {
        let a = AddArgs {
            name: "gpu-box".into(),
            relay: "https://airlox.app".into(),
            labels: vec!["gpu".into(), "cuda12".into()],
            kinds: vec![JobKind::Python, JobKind::Shell],
            timeout: Duration::from_secs(1800),
            memory: 4096,
            network: false,
            packages: vec![],
            sandbox: None,
            image: Some("ghcr.io/me/ci:latest".into()),
            concurrency: 1,
            no_wait: false,
            yes: false,
            wait: Duration::from_secs(60),
            common: Common { cache_dir: None, display_name: "owner".into(), json: false },
        };
        assert_eq!(
            join_line(&a, "7-guitar-orbit", "https://airlox.app"),
            "airlox runner join --code 7-guitar-orbit --name gpu-box --labels gpu,cuda12 --sandbox docker \
             --image ghcr.io/me/ci:latest --workspace"
        );
        let local = AddArgs { image: None, labels: vec![], ..a };
        assert_eq!(
            join_line(&local, "7-a-b", "http://127.0.0.1:8080"),
            "airlox runner join --code 7-a-b --relay http://127.0.0.1:8080 --name gpu-box --sandbox local --workspace"
        );
        // Slots go in the command only when there is more than one.
        let shared = AddArgs { concurrency: 4, ..local };
        assert_eq!(
            join_line(&shared, "7-a-b", "https://airlox.app"),
            "airlox runner join --code 7-a-b --name gpu-box --sandbox local --concurrency 4 --workspace"
        );
        // Accepting that a process sandbox cannot keep jobs off the network
        // is for whoever runs the command on the machine, not this one.
        let process = AddArgs { sandbox: Some("process".into()), concurrency: 1, ..shared };
        assert!(join_line(&process, "7-a-b", "https://airlox.app").ends_with("--sandbox process --workspace"));
    }

    #[test]
    fn invites_are_found_by_machine_name() {
        let d = tempfile::tempdir().unwrap();
        assert!(sender_invite(d.path(), "gpu-box").unwrap_err().to_string().contains("machine add gpu-box"));
        assert!(sender_invite(d.path(), "../x").is_err());
        let dir = machines_dir(d.path()).join("gpu-box");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("invite-sender.txt"), "https://airlox.app/s/x#send.y\n").unwrap();
        assert_eq!(sender_invite(d.path(), "gpu-box").unwrap(), "https://airlox.app/s/x#send.y");
    }
}
