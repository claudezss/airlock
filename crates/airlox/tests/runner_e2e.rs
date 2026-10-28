//! A real runner process (`--sandbox process`) against an in-process relay:
//! shell jobs, working trees, workspaces and streamed output, end to end.
//! Skipped where there is no `python3.12` or `sh`.

#![cfg(unix)]

use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use airlox_core::encoding::{hex, sha256};
use airlox_core::invite::Invite;
use airlox_core::item::{ItemEnvelope, ItemKind, ItemRef, SealedItem};
use airlox_core::payload::{
    Event, JobKind, JobProgress, JobResult, JobSpec, JobStatus, Meta, Payload, Stream, Target,
};
use airlox_core::session::{ContentType, JobLimits, Mode, Role, SessionParams, SessionSecrets};
use serde_json::Value;

#[path = "../../airlox-server/tests/common/mod.rs"]
mod common;
use common::*;

fn python312() -> Option<PathBuf> {
    ["/opt/homebrew/bin/python3.12", "/usr/bin/python3.12", "/usr/local/bin/python3.12"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .or_else(|| {
            let out = std::process::Command::new("python3.12")
                .args(["-c", "import sys; print(sys.executable)"])
                .output()
                .ok()?;
            out.status.success().then(|| PathBuf::from(String::from_utf8_lossy(&out.stdout).trim()))
        })
}

struct Rig {
    env: Env,
    s: Sess,
    owner: Member,
    sender: Member,
    cache: tempfile::TempDir,
    _runner: tokio::process::Child,
}

async fn rig(runner_flags: &[&str]) -> Option<Rig> {
    let python = python312()?;
    let sandbox = ["--sandbox", "process", "--accept-network-gap", "--python", python.to_str()?];
    rig_with(&sandbox, runner_flags).await
}

async fn rig_with(sandbox: &[&str], runner_flags: &[&str]) -> Option<Rig> {
    let env = Env::new().await;
    let secrets = SessionSecrets::generate();
    let signed = secrets
        .manifest(&SessionParams {
            mode: Mode::Execute,
            created_at_ms: now_ms(),
            ttl_ms: Some(3_600_000),
            allowed_types: vec![ContentType::Text, ContentType::Py, ContentType::Zip],
            max_item_bytes: 4 * 1024 * 1024,
            job_limits: Some(JobLimits {
                kinds: Some(vec![JobKind::Python, JobKind::Shell]),
                workspace: true,
                memory_mb: 1024,
                timeout_s: 120,
                ..Default::default()
            }),
            insecure_http_host: None,
        })
        .unwrap();
    let s = Sess { id: signed.manifest.session_id.clone(), manifest_json: canon(&signed), secrets };
    assert_eq!(create(&env, &s).await.status(), 201);
    let owner = join(&env, &s, Role::Owner, "owner").await;
    let sender = join(&env, &s, Role::Sender, "agent").await;

    let invite = Invite::member(&env.base, &s.secrets, Role::Runner).unwrap().to_url();
    let cache = tempfile::tempdir().unwrap();
    let runner = tokio::process::Command::new(env!("CARGO_BIN_EXE_airlox"))
        .args(["runner", "join", "--invite", &invite, "--name", "r1"])
        .args(sandbox)
        .arg("--cache-dir")
        .arg(cache.path())
        .args(runner_flags)
        .env_remove("AIRLOX_INVITE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    // Approve it once it has joined: the relay's flag, then the signed event.
    let mut approved = false;
    for _ in 0..200 {
        let r = env
            .http
            .get(env.url(&format!("/v1/sessions/{}/runners", s.id)))
            .bearer_auth(&owner.token)
            .send()
            .await
            .unwrap();
        let v: Value = r.json().await.unwrap();
        if let Some(pubkey) = v["runners"][0]["participant_pub"].as_str() {
            let r = env
                .http
                .post(env.url(&format!("/v1/sessions/{}/runners/{pubkey}/approve", s.id)))
                .bearer_auth(&owner.token)
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), 204);
            let ev = Event::RunnerApprove {
                participant_pub: airlox_core::keys::PublicKey::from_b64(pubkey).unwrap(),
            };
            let item = seal(&s, &owner, ItemKind::Event, None, vec![], Payload::event(ev));
            assert_eq!(post(&env, &s, &owner, frame(&item)).await.status(), 201);
            approved = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(approved, "the runner never joined");
    // And wait for it to take jobs: the relay turns a job away at once otherwise.
    let mut online = false;
    for _ in 0..200 {
        let r = env
            .http
            .get(env.url(&format!("/v1/sessions/{}/runners", s.id)))
            .bearer_auth(&owner.token)
            .send()
            .await
            .unwrap();
        let v: Value = r.json().await.unwrap();
        online = v["runners"][0]["online"] == true && v["runners"][0]["approved"] == true;
        if online {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(online, "the runner never came online");
    Some(Rig { env, s, owner, sender, cache, _runner: runner })
}

fn seal(
    s: &Sess,
    author: &Member,
    kind: ItemKind,
    subkind: Option<ContentType>,
    refs: Vec<ItemRef>,
    p: Payload,
) -> SealedItem {
    use airlox_core::item::{new_item_id, seal, NewItem};
    seal(
        &s.secrets.session_key(),
        &author.kp,
        NewItem { id: new_item_id(), session_id: s.id.clone(), kind, subkind, created_at_ms: now_ms(), refs },
        &p.encode().unwrap(),
    )
    .unwrap()
}

/// A tree zip as the CLI builds it: the files plus `.airlox/tree.json`.
fn tree_zip(head: &str, files: &[(&str, &str, u32)]) -> Vec<u8> {
    delta_zip(head, files, &[])
}

/// A delta tree: every file listed, those in `left_out` not in the zip.
fn delta_zip(head: &str, files: &[(&str, &str, u32)], left_out: &[&str]) -> Vec<u8> {
    let list: Vec<_> = files
        .iter()
        .map(|(p, data, mode)| serde_json::json!({"path": p, "sha256": hex(&sha256(data.as_bytes())), "mode": mode}))
        .collect();
    let json = serde_json::json!({"root_name": "app", "head": head, "branch": "main", "dirty": true,
        "files": list, "count": files.len(), "bytes": 0, "delta": !left_out.is_empty()});
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    for (p, data, _) in files.iter().filter(|f| !left_out.contains(&f.0)) {
        w.start_file(*p, opts).unwrap();
        w.write_all(data.as_bytes()).unwrap();
    }
    w.start_file(".airlox/tree.json", opts).unwrap();
    w.write_all(json.to_string().as_bytes()).unwrap();
    w.finish().unwrap().into_inner()
}

struct Job {
    kind: JobKind,
    code: String,
    cwd: Option<&'static str>,
    tree: Option<Vec<u8>>,
    fresh: bool,
}

fn shell(code: &str) -> Job {
    Job { kind: JobKind::Shell, code: code.into(), cwd: None, tree: None, fresh: false }
}

impl Rig {
    /// Seal the job, posting its tree as `who` first.
    async fn seal_job(&self, who: &Member, job: Job) -> SealedItem {
        let mut files = vec![];
        if let Some(zip) = &job.tree {
            let item = seal(
                &self.s,
                who,
                ItemKind::File,
                Some(ContentType::Zip),
                vec![],
                Payload::file("tree.zip", "application/zip", zip.clone()),
            );
            assert_eq!(post(&self.env, &self.s, who, frame(&item)).await.status(), 201);
            files.push(ItemRef::to(&item));
        }
        let spec = JobSpec {
            kind: (job.kind == JobKind::Shell).then_some(JobKind::Shell),
            filename: if job.kind == JobKind::Shell { "job.sh".into() } else { "job.py".into() },
            code: job.code,
            runtime: "python3.12".into(),
            timeout_s: 60,
            memory_mb: None,
            tree: files.first().cloned(),
            files,
            requirements: vec![],
            target: Target::Any,
            progress_file: None,
            cwd: job.cwd.map(String::from),
            fresh: job.fresh,
        };
        seal(&self.s, who, ItemKind::Job, Some(spec.kind().subkind()), vec![], Payload::job(spec))
    }

    /// Offer a sealed job to the relay once.
    async fn post_job(&self, who: &Member, item: &SealedItem) -> reqwest::Response {
        self.env
            .http
            .post(self.env.url(&format!("/v1/sessions/{}/jobs", self.s.id)))
            .bearer_auth(&who.token)
            .header("Airlox-Target", r#"{"type":"any"}"#)
            .body(frame(item))
            .send()
            .await
            .unwrap()
    }

    /// Post the job (and its tree) as `who`; returns the job's item id.
    async fn submit(&self, who: &Member, job: Job) -> String {
        let item = self.seal_job(who, job).await;
        // A runner that just finished a job is busy for a moment more.
        for _ in 0..100 {
            let r = self.post_job(who, &item).await;
            if r.status() == 201 {
                return item.envelope.header.id.clone();
            }
            let (status, body) = (r.status(), r.text().await.unwrap());
            if status == 409 && body.contains("runner_busy") {
                // Not stored: try the same item again.
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            panic!("the relay refused the job: {status} {body}");
        }
        panic!("the relay never took the job");
    }

    /// Every item of `kind` that replies to `job`, decrypted.
    async fn replies(&self, job: &str, kind: &str) -> Vec<Payload> {
        let mut out = vec![];
        for ev in events(&self.env, &self.s, &self.owner).await {
            if ev["kind"] != "item" {
                continue;
            }
            let env_json = ev["data"]["envelope"].as_str().unwrap();
            let envelope: ItemEnvelope = serde_json::from_str(env_json).unwrap();
            if format!("{:?}", envelope.header.kind).to_lowercase() != kind
                || !envelope.header.refs.iter().any(|r| r.id == job)
            {
                continue;
            }
            let bytes = blob(&self.env, &self.s, &self.owner, &envelope.header.id)
                .await
                .bytes()
                .await
                .unwrap()
                .to_vec();
            let item = SealedItem { envelope, blob: bytes };
            out.push(Payload::decode(&item.open(&self.s.secrets.session_key()).unwrap()).unwrap());
        }
        out
    }

    async fn result(&self, job: &str) -> JobResult {
        for _ in 0..600 {
            if let Some(Payload { meta: Meta::Result(r), .. }) = self.replies(job, "result").await.pop() {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("no result for {job}");
    }

    async fn run(&self, who: &Member, job: Job) -> JobResult {
        let id = self.submit(who, job).await;
        self.result(&id).await
    }

    fn workspace(&self, who: &Member) -> PathBuf {
        self.cache
            .path()
            .join("workspaces")
            .join(&self.s.id)
            .join(hex(&who.kp.public().to_bytes()))
            .join("work")
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_shell_job_syncs_its_tree_into_a_workspace_and_streams() {
    let Some(rig) = rig(&["--workspace"]).await else { return };
    let v1 = tree_zip(
        "abc123",
        &[
            ("src/a.txt", "one\n", 0o100644),
            ("src/b.txt", "two\n", 0o100644),
            ("run.sh", "echo run\n", 0o100755),
        ],
    );
    let job = Job {
        cwd: Some("src"),
        tree: Some(v1.clone()),
        ..shell(
            "pwd | sed 's|.*/||'; cat a.txt; ls ..; echo first; sleep 2.5; echo second >&2; sleep 1.5; \
             mkdir -p ../node_modules/p && echo dep > ../node_modules/p/i.js; echo last\n",
        )
    };
    let id = rig.submit(&rig.sender, job).await;
    let r = rig.result(&id).await;
    assert_eq!(r.status, JobStatus::Completed, "{:?} {}", r.reason, r.stderr);
    assert_eq!(r.stdout, "src\none\nrun.sh\nsrc\nfirst\nlast\n");
    assert_eq!(r.stderr, "second\n");
    let env = r.env.expect("the result says where the job ran");
    assert_eq!(env.kinds, Some(vec![JobKind::Python, JobKind::Shell]));
    assert_eq!(env.shell.as_deref(), Some("sh"));
    let tree = env.tree.expect("and which tree");
    assert_eq!(
        (tree.head.as_deref(), tree.dirty, tree.count, tree.sha256),
        (Some("abc123"), true, 3, hex(&sha256(&v1)))
    );
    // Output arrived while the job ran: the first line after a second, the
    // error line after about three.
    let chunks: Vec<JobProgress> = rig
        .replies(&id, "progress")
        .await
        .into_iter()
        .filter_map(|p| if let Meta::Progress(p) = p.meta { Some(p) } else { None })
        .filter(|p| p.stream.is_some())
        .collect();
    let stdout: Vec<_> = chunks.iter().filter(|c| c.stream == Some(Stream::Stdout)).collect();
    let stderr: Vec<_> = chunks.iter().filter(|c| c.stream == Some(Stream::Stderr)).collect();
    assert!(!stdout.is_empty() && stdout[0].offset == Some(0), "{chunks:?}");
    assert!(stdout[0].data.as_deref().unwrap().starts_with("src\none\n"), "{chunks:?}");
    assert_eq!(stderr.len(), 1, "{chunks:?}");
    assert_eq!((stderr[0].offset, stderr[0].data.as_deref()), (Some(0), Some("second\n")));
    assert!(chunks.iter().all(|c| !c.truncated));

    // Same sender, a changed tree: node_modules survived, b.txt and run.sh
    // (placed before, absent now) are gone, a.txt is updated.
    let v2 = tree_zip("def456", &[("src/a.txt", "uno\n", 0o100644), ("src/c.txt", "tres\n", 0o100644)]);
    let r = rig
        .run(
            &rig.sender,
            Job { tree: Some(v2), ..shell("cat node_modules/p/i.js; ls; ls src; cat src/a.txt\n") },
        )
        .await;
    assert_eq!(r.status, JobStatus::Completed, "{:?} {}", r.reason, r.stderr);
    assert_eq!(r.stdout, "dep\nnode_modules\nsrc\na.txt\nc.txt\nuno\n");
    assert!(rig.workspace(&rig.sender).join("node_modules/p/i.js").is_file());

    // A python job in the same workspace sees it too, and its entry file is
    // written over the last one's.
    for _ in 0..2 {
        let py = Job {
            kind: JobKind::Python,
            code: "import os\nprint(open('src/a.txt').read().strip(), sorted(f for f in os.listdir('.') if f[0] != '.'))\n".into(),
            cwd: None,
            tree: None,
            fresh: false,
        };
        let r = rig.run(&rig.sender, py).await;
        assert_eq!(r.status, JobStatus::Completed, "{:?} {}", r.reason, r.stderr);
        assert_eq!(r.stdout, "uno ['job.py', 'node_modules', 'src']\n");
    }

    // Another sender has a workspace of their own.
    let other = join(&rig.env, &rig.s, Role::Sender, "agent-2").await;
    let r = rig.run(&other, Job { tree: Some(v1), ..shell("ls\n") }).await;
    assert_eq!(r.stdout, "run.sh\nsrc\n", "{:?} {}", r.reason, r.stderr);
    assert_ne!(rig.workspace(&other), rig.workspace(&rig.sender));

    // A script that cannot start in its cwd says so; nothing else is harmed.
    let r = rig.run(&rig.sender, Job { cwd: Some("nowhere"), ..shell("echo hi\n") }).await;
    assert_eq!(r.status, JobStatus::Failed);
    let why = r.reason.unwrap();
    assert!(why.contains("cwd 'nowhere' does not exist"), "{why}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_workspace_over_its_limit_is_emptied_when_the_job_ends() {
    let Some(rig) = rig(&["--workspace", "--workspace-max-mb", "1"]).await else { return };
    let other = join(&rig.env, &rig.s, Role::Sender, "agent-2").await;
    assert_eq!(rig.run(&other, shell("echo kept > mine; echo ok\n")).await.stdout, "ok\n");
    let r = rig.run(&rig.sender, shell("head -c 2000000 /dev/zero > big; echo wrote\n")).await;
    assert_eq!((r.status, r.stdout.as_str()), (JobStatus::Completed, "wrote\n"), "{:?}", r.reason);
    assert!(r.stderr.contains("over its 1 MB limit, so the runner emptied it"), "{}", r.stderr);
    // Gone at once, not held until the next job; another sender's is untouched.
    let r = rig.run(&rig.sender, shell("ls | wc -l | tr -d ' '\n")).await;
    assert_eq!((r.status, r.stdout.as_str()), (JobStatus::Completed, "0\n"), "{:?}", r.reason);
    assert_eq!(rig.run(&other, shell("cat mine\n")).await.stdout, "kept\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_delta_tree_sends_only_what_changed_and_is_refused_when_the_workspace_differs() {
    let Some(rig) = rig(&["--workspace"]).await else { return };
    let v1 = [("a.txt", "one\n", 0o100644), ("b.txt", "two\n", 0o100644)];
    let r = rig
        .run(&rig.sender, Job { tree: Some(tree_zip("abc", &v1)), ..shell("echo edited > b.txt\n") })
        .await;
    assert_eq!(r.status, JobStatus::Completed, "{:?} {}", r.reason, r.stderr);
    // The job changed b.txt, and the result says so.
    assert_eq!(r.env.unwrap().tree.unwrap().changed, Some(vec!["b.txt".to_string()]));

    // a.txt is left out (it is there as listed); c.txt is new.
    let v2 = [("a.txt", "one\n", 0o100644), ("b.txt", "two\n", 0o100644), ("c.txt", "three\n", 0o100644)];
    let r = rig
        .run(
            &rig.sender,
            Job { tree: Some(delta_zip("abc", &v2, &["a.txt"])), ..shell("cat a.txt b.txt c.txt\n") },
        )
        .await;
    assert_eq!(
        (r.status, r.stdout.as_str()),
        (JobStatus::Completed, "one\ntwo\nthree\n"),
        "{:?} {}",
        r.reason,
        r.stderr
    );
    assert_eq!(r.env.unwrap().tree.unwrap().changed, Some(vec![]));

    // A delta that leaves out a file the workspace does not hold is refused
    // before anything runs, and a new sender has no workspace to rely on.
    rig.run(&rig.sender, shell("rm c.txt\n")).await;
    let r = rig
        .run(
            &rig.sender,
            Job { tree: Some(delta_zip("abc", &v2, &["a.txt", "c.txt"])), ..shell("echo ran\n") },
        )
        .await;
    assert_eq!((r.status, r.stdout.as_str()), (JobStatus::Refused, ""));
    let why = r.reason.unwrap();
    assert!(why.starts_with("tree_stale: ") && why.contains("c.txt"), "{why}");
    assert!(r.env.is_none(), "a refused job reports no env");
    let other = join(&rig.env, &rig.s, Role::Sender, "agent-2").await;
    let r =
        rig.run(&other, Job { tree: Some(delta_zip("abc", &v2, &["a.txt"])), ..shell("echo ran\n") }).await;
    assert_eq!(r.status, JobStatus::Refused);
    assert!(r.reason.unwrap().starts_with("tree_stale: "));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_delta_tree_without_a_workspace_is_refused() {
    let Some(rig) = rig(&[]).await else { return };
    let files = [("a.txt", "one\n", 0o100644), ("b.txt", "two\n", 0o100644)];
    let r = rig
        .run(&rig.sender, Job { tree: Some(delta_zip("abc", &files, &["a.txt"])), ..shell("echo ran\n") })
        .await;
    assert_eq!(r.status, JobStatus::Refused);
    assert!(r.reason.unwrap().starts_with("tree_stale: "));
}

#[tokio::test(flavor = "multi_thread")]
async fn without_workspace_each_job_starts_empty_and_a_tree_is_unpacked() {
    let Some(rig) = rig(&[]).await else { return };
    let zip = tree_zip("abc", &[("src/a.txt", "one\n", 0o100644)]);
    let r = rig.run(&rig.sender, Job { tree: Some(zip), ..shell("ls; cat src/a.txt; touch kept\n") }).await;
    assert_eq!(r.stdout, "src\none\n", "{:?} {}", r.reason, r.stderr);
    assert_eq!(r.env.unwrap().tree.unwrap().count, 1, "env.tree is reported without a workspace too");
    let r = rig.run(&rig.sender, shell("ls | wc -l | tr -d ' '\n")).await;
    assert_eq!(r.stdout, "0\n");
    assert!(!rig.cache.path().join("workspaces").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn output_past_the_cap_is_cut_off_with_a_truncated_chunk() {
    let Some(rig) = rig(&["--stream-max-mb", "1"]).await else { return };
    let id = rig.submit(&rig.sender, shell("yes 0123456789abcdef | head -c 3000000; sleep 1.5\n")).await;
    let r = rig.result(&id).await;
    assert_eq!(r.status, JobStatus::Completed, "{:?}", r.reason);
    let chunks: Vec<JobProgress> = rig
        .replies(&id, "progress")
        .await
        .into_iter()
        .filter_map(|p| if let Meta::Progress(p) = p.meta { Some(p) } else { None })
        .filter(|p| p.stream.is_some())
        .collect();
    let streamed: usize = chunks.iter().map(|c| c.data.as_deref().unwrap().len()).sum();
    assert_eq!(streamed, 1 << 20, "streamed exactly the cap");
    assert!(chunks.last().unwrap().truncated, "and said it stopped");
    assert_eq!(chunks.iter().filter(|c| c.truncated).count(), 1);
    // Offsets run on without a gap.
    let mut next = 0;
    for c in chunks.iter().filter(|c| !c.truncated) {
        assert_eq!(c.offset, Some(next));
        next += c.data.as_deref().unwrap().len() as u64;
    }
    // The signed result still has the (capped) output itself.
    assert!(r.stdout.len() >= (1 << 20) - 1);
}

/// Unprivileged user namespaces are on (Ubuntu's AppArmor can turn them off).
#[cfg(target_os = "linux")]
fn userns_allowed() -> bool {
    let read = |p: &str| std::fs::read_to_string(p).map(|s| s.trim().to_string()).ok();
    read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref() != Some("1")
        && read("/proc/sys/user/max_user_namespaces").as_deref() != Some("0")
}

/// `--sandbox local` on Linux, the one platform where it is a boundary: a
/// shell job runs the host's tools in namespaces of its own, with no network,
/// none of the runner's processes, no host files but the system's, and only
/// its work dir writable; its tree, cwd, exit code and workspace work as under
/// `process`. Skipped where user namespaces are off, except on CI.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn the_linux_sandbox_runs_shell_jobs_confined() {
    if !userns_allowed() {
        assert!(std::env::var_os("CI").is_none(), "CI must allow unprivileged user namespaces");
        eprintln!("skipped: unprivileged user namespaces are off");
        return;
    }
    let Some(python) = python312() else { return };
    let sandbox = ["--sandbox", "local", "--python", python.to_str().unwrap()];
    let Some(rig) = rig_with(&sandbox, &["--workspace"]).await else { return };
    let host = tempfile::tempdir().unwrap();
    std::fs::write(host.path().join("secret"), "s3cret\n").unwrap();
    let runner_pid = rig._runner.id().unwrap();
    let zip = tree_zip("abc", &[("t/test.sh", "echo from-tree\n", 0o100755)]);
    let job = Job {
        cwd: Some("t"),
        tree: Some(zip),
        ..shell(&format!(
            "./test.sh; uname -s\n\
             tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' '\n\
             test -e /proc/{runner_pid} && echo runner-seen || echo runner-hidden\n\
             cat '{dir}/secret' 2>/dev/null || echo secret-hidden\n\
             touch '{dir}/escaped' 2>/dev/null && echo escaped || echo confined\n\
             echo cached > ../cache\n\
             exit 3\n",
            dir = host.path().display()
        ))
    };
    let r = rig.run(&rig.sender, job).await;
    assert_eq!((r.status, r.exit_code), (JobStatus::Completed, Some(3)), "{:?} {}", r.reason, r.stderr);
    assert_eq!(r.stdout, "from-tree\nLinux\nlo\nrunner-hidden\nsecret-hidden\nconfined\n", "{}", r.stderr);
    assert!(!host.path().join("escaped").exists());
    let env = r.env.unwrap();
    assert_eq!((env.kinds, env.shell.as_deref()), (Some(vec![JobKind::Python, JobKind::Shell]), Some("sh")));
    // The workspace outlives the job; --fresh empties it.
    let r = rig.run(&rig.sender, shell("cat cache; ls t\n")).await;
    assert_eq!(r.stdout, "cached\ntest.sh\n", "{:?} {}", r.reason, r.stderr);
    let r = rig.run(&rig.sender, Job { fresh: true, ..shell("ls\n") }).await;
    assert_eq!((r.status, r.stdout.as_str()), (JobStatus::Completed, ""), "{:?} {}", r.reason, r.stderr);
}

/// With a Docker daemon and an image that has python3, named by
/// AIRLOX_TEST_DOCKER_IMAGE (any local one will do): shell jobs run in it,
/// the result names it by digest, and a workspace is bind-mounted.
#[tokio::test(flavor = "multi_thread")]
async fn docker_runs_shell_jobs_in_the_operators_image() {
    let Ok(image) = std::env::var("AIRLOX_TEST_DOCKER_IMAGE") else { return };
    let Some(rig) = rig_with(&["--sandbox", "docker", "--image", &image], &["--workspace"]).await else {
        return;
    };
    let zip = tree_zip("abc", &[("t/test.sh", "echo from-tree\n", 0o100755)]);
    let job = Job {
        cwd: Some("t"),
        tree: Some(zip),
        ..shell("uname -s; ./test.sh; echo cached > ../cache; pwd\n")
    };
    let r = rig.run(&rig.sender, job).await;
    assert_eq!(r.status, JobStatus::Completed, "{:?} {}", r.reason, r.stderr);
    assert_eq!(r.stdout, "Linux\nfrom-tree\n/work/t\n");
    let env = r.env.unwrap();
    assert!(
        env.interpreter.starts_with("docker:") && env.interpreter.contains("@sha256:"),
        "{}",
        env.interpreter
    );
    assert_eq!((env.kinds, env.shell.as_deref()), (Some(vec![JobKind::Python, JobKind::Shell]), Some("sh")));
    let r = rig.run(&rig.sender, shell("cat cache; ls t\n")).await;
    assert_eq!(r.stdout, "cached\ntest.sh\n", "{:?} {}", r.reason, r.stderr);
}

/// Docker without `--image` runs Python jobs from the image it builds, and
/// turns shell jobs away saying why (set AIRLOX_TEST_DOCKER to run it; it
/// builds the runtime image if it is not there).
#[tokio::test(flavor = "multi_thread")]
async fn docker_without_an_image_refuses_shell_jobs() {
    if std::env::var("AIRLOX_TEST_DOCKER").is_err() {
        return;
    }
    let Some(rig) = rig_with(&["--sandbox", "docker"], &[]).await else { return };
    let r = rig.run(&rig.sender, shell("echo hi\n")).await;
    assert_eq!(r.status, JobStatus::Refused);
    let why = r.reason.unwrap();
    assert!(why.starts_with("kind_not_supported: this runner does not run shell jobs"), "{why}");
    assert!(why.contains("--image"), "{why}");
    let py = Job { kind: JobKind::Python, code: "print(1)\n".into(), cwd: None, tree: None, fresh: false };
    let r = rig.run(&rig.sender, py).await;
    assert_eq!((r.status, r.stdout.as_str()), (JobStatus::Completed, "1\n"), "{:?} {}", r.reason, r.stderr);
    assert_eq!(r.env.unwrap().kinds, Some(vec![JobKind::Python]));
}

/// A shell job that waits, up to 20 s, for `wait` to exist in `dir`, after
/// creating `mark` there.
fn rendezvous(dir: &std::path::Path, mark: &str, wait: &str) -> Job {
    rendezvous_all(dir, mark, &[wait])
}

/// `rendezvous`, waiting for each of `waits` in turn (up to 20 s each).
fn rendezvous_all(dir: &std::path::Path, mark: &str, waits: &[&str]) -> Job {
    let dir = dir.display();
    let waits: String = waits
        .iter()
        .map(|w| {
            format!(
                "i=0; while [ ! -e '{dir}/{w}' ]; do i=$((i+1)); [ $i -gt 200 ] && echo alone && exit 1; \
                 sleep 0.1; done; "
            )
        })
        .collect();
    shell(&format!("touch '{dir}/{mark}'; {waits}echo met\n"))
}

async fn wait_for_file(path: &std::path::Path) {
    for _ in 0..300 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{} never appeared", path.display());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_runner_with_two_slots_runs_two_jobs_at_once_and_refuses_a_third() {
    let Some(rig) = rig(&["--concurrency", "2"]).await else { return };
    let signal = tempfile::tempdir().unwrap();
    let dir = signal.path();
    let runners = || async {
        let r = rig
            .env
            .http
            .get(rig.env.url(&format!("/v1/sessions/{}/runners", rig.s.id)))
            .bearer_auth(&rig.owner.token)
            .send()
            .await
            .unwrap();
        r.json::<Value>().await.unwrap()["runners"][0].clone()
    };
    // The join says how many slots there are.
    assert_eq!(runners().await["slots"], 2);
    assert_eq!(runners().await["runner"]["slots"], 2);

    // Each job waits for the other's mark: only jobs that overlap finish.
    // Then both hold their slots until released, so neither has ended
    // before the checks below.
    let a = rig.submit(&rig.sender, rendezvous_all(dir, "a", &["b", "release"])).await;
    let b = rig.submit(&rig.sender, rendezvous_all(dir, "b", &["a", "release"])).await;
    wait_for_file(&dir.join("a")).await;
    wait_for_file(&dir.join("b")).await;
    let row = runners().await;
    assert_eq!((row["jobs"].as_array().map(Vec::len), row["busy"].as_bool()), (Some(2), Some(true)));

    // Both slots are taken: a third is refused at once, not queued.
    let third = rig.seal_job(&rig.sender, shell("echo third\n")).await;
    let r = rig.post_job(&rig.sender, &third).await;
    assert_eq!(r.status(), 409);
    assert_eq!(r.json::<Value>().await.unwrap()["error"], "runner_busy");

    std::fs::write(dir.join("release"), "").unwrap();
    for id in [&a, &b] {
        let r = rig.result(id).await;
        assert_eq!(
            (r.status, r.stdout.as_str()),
            (JobStatus::Completed, "met\n"),
            "{:?} {}",
            r.reason,
            r.stderr
        );
    }
    // Free again: the same job goes through now.
    let r = rig.run(&rig.sender, shell("echo third\n")).await;
    assert_eq!(r.stdout, "third\n");
    let row = runners().await;
    assert_eq!((row["jobs"].as_array().map(Vec::len), row["busy"].as_bool()), (Some(0), Some(false)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_workspace_serves_one_job_at_a_time_but_other_senders_run_beside_it() {
    let Some(rig) = rig(&["--concurrency", "2", "--workspace"]).await else { return };
    let signal = tempfile::tempdir().unwrap();
    let dir = signal.path();
    let other = join(&rig.env, &rig.s, Role::Sender, "agent-2").await;

    // The first holds the sender's workspace until released.
    let first = rig.submit(&rig.sender, rendezvous(dir, "first", "release")).await;
    wait_for_file(&dir.join("first")).await;

    // A second job of the same sender finds it in use: the runner refuses it
    // as a busy runner would (a signed result, so the sender is told).
    let second = rig.submit(&rig.sender, shell("echo should not run\n")).await;
    let r = rig.result(&second).await;
    assert_eq!(r.status, JobStatus::Refused);
    assert_eq!(r.stdout, "");
    let why = r.reason.unwrap();
    assert!(why.starts_with("runner_busy: "), "{why}");

    // Another sender has a workspace of its own and runs beside the first.
    let r = rig.run(&other, shell("echo beside\n")).await;
    assert_eq!((r.status, r.stdout.as_str()), (JobStatus::Completed, "beside\n"), "{:?}", r.reason);
    assert!(rig.replies(&first, "result").await.is_empty(), "the first is still running");

    // Once it is done the workspace is free for the sender's next job.
    std::fs::write(dir.join("release"), "").unwrap();
    let r = rig.result(&first).await;
    assert_eq!((r.status, r.stdout.as_str()), (JobStatus::Completed, "met\n"), "{:?} {}", r.reason, r.stderr);
    let r = rig.run(&rig.sender, shell("echo again\n")).await;
    assert_eq!((r.status, r.stdout.as_str()), (JobStatus::Completed, "again\n"), "{:?}", r.reason);
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelling_one_of_two_running_jobs_leaves_the_other_alone() {
    let Some(rig) = rig(&["--concurrency", "2"]).await else { return };
    let signal = tempfile::tempdir().unwrap();
    let dir = signal.path();
    let doomed = rig.submit(&rig.sender, rendezvous(dir, "doomed", "never")).await;
    let kept = rig.submit(&rig.sender, rendezvous(dir, "kept", "release")).await;
    wait_for_file(&dir.join("doomed")).await;
    wait_for_file(&dir.join("kept")).await;

    let r = rig
        .env
        .http
        .post(rig.env.url(&format!("/v1/sessions/{}/jobs/{doomed}/cancel", rig.s.id)))
        .bearer_auth(&rig.sender.token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 202);
    let r = rig.result(&doomed).await;
    assert_eq!(r.status, JobStatus::Cancelled, "{:?}", r.reason);

    // Its slot is free for a new job while the other keeps running.
    let r = rig.run(&rig.sender, shell("echo next\n")).await;
    assert_eq!((r.status, r.stdout.as_str()), (JobStatus::Completed, "next\n"), "{:?}", r.reason);
    assert!(rig.replies(&kept, "result").await.is_empty(), "the other job was not touched");
    std::fs::write(dir.join("release"), "").unwrap();
    let r = rig.result(&kept).await;
    assert_eq!((r.status, r.stdout.as_str()), (JobStatus::Completed, "met\n"), "{:?} {}", r.reason, r.stderr);
}
