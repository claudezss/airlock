//! Execute mode against a real server: approval, routing, claims,
//! heartbeats, results and cancels.

use std::pin::Pin;
use std::time::Duration;

use airlox_core::cert::{issue_cert, sign_join, ClientKind, JoinRequest, RunnerInfo, SandboxKind};
use airlox_core::item::{new_item_id, seal, ItemKind, ItemRef, NewItem, SealedItem};
use airlox_core::keys::Keypair;
use airlox_core::payload::{
    Event, JobKind, JobProgress, JobResult, JobSpec, JobStatus, Meta, Payload, Stream as OutStream, Target,
};
use airlox_core::session::{ContentType, JobLimits, Mode, Role};
use airlox_server::Config;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use reqwest::StatusCode;
use serde_json::{json, Value};

mod common;
use common::*;

async fn execute_env(f: impl FnOnce(&mut Config)) -> (Env, Sess, Member, Member) {
    let env = Env::with(f).await;
    let s = new_session(Mode::Execute, 3_600_000);
    assert_eq!(create(&env, &s).await.status(), StatusCode::CREATED);
    let owner = join(&env, &s, Role::Owner, "owner").await;
    let sender = join(&env, &s, Role::Sender, "planner-agent").await;
    (env, s, owner, sender)
}

async fn join_runner(env: &Env, s: &Sess, name: &str, labels: &[&str]) -> Member {
    join_runner_slots(env, s, name, labels, 1).await
}

async fn join_runner_slots(env: &Env, s: &Sess, name: &str, labels: &[&str], slots: u32) -> Member {
    join_runner_kinds(env, s, name, labels, slots, &[JobKind::Python]).await
}

async fn join_runner_kinds(
    env: &Env,
    s: &Sess,
    name: &str,
    labels: &[&str],
    slots: u32,
    kinds: &[JobKind],
) -> Member {
    let (kp, body) = runner_join_body(s, name, labels, slots, kinds);
    let r = post_join(env, s, body).await;
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().await.unwrap());
    let v: Value = r.json().await.unwrap();
    Member { kp, token: v["token"].as_str().unwrap().to_string() }
}

fn runner_join_body(
    s: &Sess,
    name: &str,
    labels: &[&str],
    slots: u32,
    kinds: &[JobKind],
) -> (Keypair, String) {
    let kp = Keypair::generate();
    let cert = issue_cert(&s.secrets.role_keypair(Role::Runner), &s.id, Role::Runner, kp.public(), now_ms())
        .unwrap();
    let j = sign_join(
        &kp,
        JoinRequest {
            v: 1,
            session_id: s.id.clone(),
            cert,
            display_name: name.into(),
            description: None,
            kind: ClientKind::Runner,
            runner: Some(RunnerInfo {
                name: name.into(),
                labels: labels.iter().map(|l| l.to_string()).collect(),
                host: "test-host".into(),
                sandbox: SandboxKind::Docker,
                network_unblocked: false,
                version: None,
                python: None,
                kinds: kinds.to_vec(),
                shell: kinds.contains(&JobKind::Shell).then(|| "sh".into()),
                slots,
            }),
            created_at_ms: now_ms(),
        },
    )
    .unwrap();
    (kp, canon(&j))
}

fn pk(m: &Member) -> String {
    m.kp.public().to_b64()
}

fn seal_job(s: &Sess, author: &Member, target: &Target) -> SealedItem {
    let spec = JobSpec {
        kind: None,
        cwd: None,
        tree: None,
        fresh: false,
        filename: "summarize.py".into(),
        code: "print('hi')".into(),
        runtime: "python3.12".into(),
        timeout_s: 30,
        memory_mb: None,
        files: vec![],
        requirements: vec![],
        target: target.clone(),
        progress_file: None,
    };
    seal_kind(s, author, ItemKind::Job, Some(ContentType::Py), vec![], Payload::job(spec))
}

fn seal_kind(
    s: &Sess,
    author: &Member,
    kind: ItemKind,
    subkind: Option<ContentType>,
    refs: Vec<ItemRef>,
    p: Payload,
) -> SealedItem {
    seal(
        &s.secrets.session_key(),
        &author.kp,
        NewItem { id: new_item_id(), session_id: s.id.clone(), kind, subkind, created_at_ms: now_ms(), refs },
        &p.encode().unwrap(),
    )
    .unwrap()
}

fn seal_result(s: &Sess, runner: &Member, job: &SealedItem) -> SealedItem {
    let job_ref = ItemRef::to(job);
    let r = JobResult {
        job: job_ref.clone(),
        exit_code: Some(0),
        status: JobStatus::Completed,
        reason: None,
        wall_ms: 10,
        peak_mem_mb: 1,
        stdout: "hi\n".into(),
        stderr: String::new(),
        stdout_truncated: false,
        stderr_truncated: false,
        out_files: vec![],
        code_sha256: "a".repeat(64),
        input_sha256: "b".repeat(64),
        env: None,
    };
    seal_kind(s, runner, ItemKind::Result, None, vec![job_ref], Payload::result(r))
}

fn target_json(t: &Target) -> String {
    serde_json::to_string(t).unwrap()
}

async fn submit(env: &Env, s: &Sess, m: &Member, job: &SealedItem) -> reqwest::Response {
    let Payload { meta: airlox_core::payload::Meta::Job(spec), .. } =
        Payload::decode(&job.open(&s.secrets.session_key()).unwrap()).unwrap()
    else {
        unreachable!()
    };
    env.http
        .post(env.url(&format!("/v1/sessions/{}/jobs", s.id)))
        .bearer_auth(&m.token)
        .header("Airlox-Target", target_json(&spec.target))
        .body(frame(job))
        .send()
        .await
        .unwrap()
}

async fn call(env: &Env, m: &Member, method: reqwest::Method, path: String) -> reqwest::Response {
    env.http.request(method, env.url(&path)).bearer_auth(&m.token).send().await.unwrap()
}

async fn job_state(env: &Env, s: &Sess, m: &Member, job: &str) -> Value {
    let r = call(env, m, reqwest::Method::GET, format!("/v1/sessions/{}/jobs/{job}", s.id)).await;
    assert_eq!(r.status(), StatusCode::OK);
    r.json().await.unwrap()
}

async fn runners(env: &Env, s: &Sess, m: &Member) -> Vec<Value> {
    let r = call(env, m, reqwest::Method::GET, format!("/v1/sessions/{}/runners", s.id)).await;
    let v: Value = r.json().await.unwrap();
    v["runners"].as_array().unwrap().clone()
}

async fn approve(env: &Env, s: &Sess, owner: &Member, runner: &Member) -> StatusCode {
    call(env, owner, reqwest::Method::POST, format!("/v1/sessions/{}/runners/{}/approve", s.id, pk(runner)))
        .await
        .status()
}

async fn claim(env: &Env, s: &Sess, runner: &Member, job: &str) -> StatusCode {
    call(env, runner, reqwest::Method::POST, format!("/v1/sessions/{}/jobs/{job}/claim", s.id)).await.status()
}

async fn heartbeat_jobs(env: &Env, s: &Sess, runner: &Member, jobs: &[&str]) -> reqwest::Response {
    env.http
        .post(env.url(&format!("/v1/sessions/{}/runners/me/heartbeat", s.id)))
        .bearer_auth(&runner.token)
        .body(serde_json::json!({ "jobs": jobs }).to_string())
        .send()
        .await
        .unwrap()
}

async fn heartbeat(env: &Env, s: &Sess, runner: &Member, job: Option<&str>) -> reqwest::Response {
    heartbeat_jobs(env, s, runner, job.as_slice()).await
}

/// An open runner stream: holding it is what makes the runner online.
struct RunnerStream {
    stream: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>>,
    text: String,
}

impl RunnerStream {
    async fn open(env: &Env, s: &Sess, runner: &Member) -> RunnerStream {
        let r =
            call(env, runner, reqwest::Method::GET, format!("/v1/sessions/{}/runners/me/stream", s.id)).await;
        assert_eq!(r.status(), StatusCode::OK);
        RunnerStream { stream: Box::pin(r.bytes_stream()), text: String::new() }
    }

    /// Wait for the next `event: <kind>` and return its data.
    async fn next(&mut self, kind: &str) -> Value {
        let marker = format!("event: {kind}\ndata: ");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(i) = self.text.find(&marker) {
                let rest = &self.text[i + marker.len()..];
                if let Some(end) = rest.find('\n') {
                    let v = serde_json::from_str(&rest[..end]).unwrap();
                    self.text = rest[end..].to_string();
                    return v;
                }
            }
            let chunk = tokio::time::timeout_at(deadline, self.stream.next())
                .await
                .expect("runner stream timeout")
                .expect("runner stream ended")
                .unwrap();
            self.text.push_str(&String::from_utf8_lossy(&chunk));
        }
    }

    /// True once the server has ended the stream.
    async fn ended(&mut self) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match tokio::time::timeout_at(deadline, self.stream.next()).await {
                Err(_) => return false,
                Ok(None) | Ok(Some(Err(_))) => return true,
                Ok(Some(Ok(chunk))) => self.text.push_str(&String::from_utf8_lossy(&chunk)),
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn no_runner_fails_at_once_and_is_not_queued() {
    let (env, s, owner, sender) = execute_env(|_| {}).await;
    let job = seal_job(&s, &sender, &Target::Any);
    let id = job.envelope.header.id.clone();
    let r = submit(&env, &s, &sender, &job).await;
    assert_eq!(error_code(r).await, (StatusCode::CONFLICT, "no_runner_available".into()));

    // The job item is kept so the timeline can show it as failed.
    let st = job_state(&env, &s, &owner, &id).await;
    assert_eq!((st["state"].as_str(), st["reason"].as_str()), (Some("failed"), Some("not_available")));
    let evs = events(&env, &s, &owner).await;
    assert!(evs.iter().any(|e| e["kind"] == "item" && e["data"]["envelope"].as_str().unwrap().contains(&id)));
    assert!(evs.iter().any(|e| e["kind"] == "job" && e["data"]["job"] == id.as_str()));
}

#[tokio::test(flavor = "multi_thread")]
async fn approve_route_claim_and_complete() {
    let (env, s, owner, sender) = execute_env(|_| {}).await;
    let runner = join_runner(&env, &s, "runner-01", &["cpu"]).await;
    let mut stream = RunnerStream::open(&env, &s, &runner).await;

    // Online but not approved: not a candidate, and not a recipient either.
    let r = submit(&env, &s, &sender, &seal_job(&s, &sender, &Target::Any)).await;
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let list = runners(&env, &s, &owner).await;
    assert_eq!(list.len(), 1);
    assert_eq!((list[0]["approved"].as_bool(), list[0]["online"].as_bool()), (Some(false), Some(true)));

    // Only the owner approves.
    assert_eq!(approve(&env, &s, &sender, &runner).await, StatusCode::FORBIDDEN);
    assert_eq!(approve(&env, &s, &owner, &runner).await, StatusCode::NO_CONTENT);
    assert!(events(&env, &s, &owner)
        .await
        .iter()
        .any(|e| e["kind"] == "runner" && e["data"]["status"] == "approved"));

    let job = seal_job(&s, &sender, &Target::Any);
    let id = job.envelope.header.id.clone();
    let r = submit(&env, &s, &sender, &job).await;
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().await.unwrap());
    let assigned = stream.next("job_assigned").await;
    assert_eq!(assigned["job"], id.as_str());
    assert_eq!(assigned["envelope"].as_str().unwrap(), canon(&job.envelope));

    // Busy runners take nothing else.
    let r = submit(&env, &s, &sender, &seal_job(&s, &sender, &Target::Any)).await;
    assert_eq!(r.status(), StatusCode::CONFLICT);

    // Someone else cannot claim it; the runner can, twice.
    assert_eq!(claim(&env, &s, &sender, &id).await, StatusCode::FORBIDDEN);
    assert_eq!(claim(&env, &s, &runner, &id).await, StatusCode::NO_CONTENT);
    assert_eq!(claim(&env, &s, &runner, &id).await, StatusCode::NO_CONTENT);
    assert_eq!(job_state(&env, &s, &owner, &id).await["state"], "running");

    // Runners post results through /items, and may not post jobs at all.
    let r = post(&env, &s, &runner, frame(&seal_result(&s, &runner, &job))).await;
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().await.unwrap());
    assert_eq!(job_state(&env, &s, &owner, &id).await["state"], "done");
    assert!(runners(&env, &s, &owner).await[0]["job"].is_null());

    // Idle again: the next job goes through.
    let r = submit(&env, &s, &sender, &seal_job(&s, &sender, &Target::Any)).await;
    assert_eq!(r.status(), StatusCode::CREATED);
}

#[tokio::test(flavor = "multi_thread")]
async fn targets_route_by_label_and_key() {
    let (env, s, owner, sender) = execute_env(|_| {}).await;
    let cpu = join_runner(&env, &s, "runner-01", &["cpu"]).await;
    let gpu = join_runner(&env, &s, "runner-02", &["cpu", "gpu"]).await;
    let _cpu_stream = RunnerStream::open(&env, &s, &cpu).await;
    let _gpu_stream = RunnerStream::open(&env, &s, &gpu).await;
    approve(&env, &s, &owner, &cpu).await;
    approve(&env, &s, &owner, &gpu).await;

    let labels = Target::Labels { labels: vec!["gpu".into()] };
    let r: Value = submit(&env, &s, &sender, &seal_job(&s, &sender, &labels)).await.json().await.unwrap();
    assert_eq!(r["runner"], pk(&gpu));

    // gpu is busy now; a pinned job for it fails rather than going elsewhere.
    let pinned = Target::Runner { participant_pub: gpu.kp.public(), name: "runner-02".into() };
    let r = submit(&env, &s, &sender, &seal_job(&s, &sender, &pinned)).await;
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let r: Value =
        submit(&env, &s, &sender, &seal_job(&s, &sender, &Target::Any)).await.json().await.unwrap();
    assert_eq!(r["runner"], pk(&cpu));

    // An observer cannot submit; a malformed target is refused.
    let observer = join(&env, &s, Role::Observer, "watcher").await;
    let job = seal_job(&s, &sender, &Target::Any);
    assert_eq!(submit(&env, &s, &observer, &job).await.status(), StatusCode::FORBIDDEN);
    let r = env
        .http
        .post(env.url(&format!("/v1/sessions/{}/jobs", s.id)))
        .bearer_auth(&sender.token)
        .header("Airlox-Target", r#"{"type":"labels","labels":["Not Valid"]}"#)
        .body(frame(&job))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    // Jobs cannot skip routing through /items.
    assert_eq!(post(&env, &s, &sender, frame(&job)).await.status(), StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread")]
async fn unclaimed_jobs_fail_and_quiet_runners_are_lost() {
    let (env, s, owner, sender) = execute_env(|c| {
        c.claim_timeout_ms = 200;
        c.runner_timeout_ms = 600;
        c.job_reconnect_grace_ms = 600;
    })
    .await;
    let runner = join_runner(&env, &s, "runner-01", &[]).await;
    let _stream = RunnerStream::open(&env, &s, &runner).await;
    approve(&env, &s, &owner, &runner).await;

    // Not claimed in time: fails, and the runner is offline until it heartbeats.
    let job = seal_job(&s, &sender, &Target::Any);
    let id = job.envelope.header.id.clone();
    assert_eq!(submit(&env, &s, &sender, &job).await.status(), StatusCode::CREATED);
    assert!(
        eventually(|| async { job_state(&env, &s, &owner, &id).await["reason"] == "runner_unresponsive" })
            .await
    );
    assert_eq!(runners(&env, &s, &owner).await[0]["online"], false);
    assert_eq!(claim(&env, &s, &runner, &id).await, StatusCode::CONFLICT);

    // Back online after a heartbeat; claimed, then silent: lost.
    assert_eq!(heartbeat(&env, &s, &runner, None).await.status(), StatusCode::OK);
    let job = seal_job(&s, &sender, &Target::Any);
    let id = job.envelope.header.id.clone();
    assert_eq!(submit(&env, &s, &sender, &job).await.status(), StatusCode::CREATED);
    assert_eq!(claim(&env, &s, &runner, &id).await, StatusCode::NO_CONTENT);
    let lost = || async { job_state(&env, &s, &owner, &id).await["reason"] == "runner_lost" };
    let mut ok = false;
    for _ in 0..40 {
        if lost().await {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ok, "a running job whose runner stops heartbeating fails");

    // A heartbeat that reports idle while the relay has the runner on a job
    // also fails that job.
    heartbeat(&env, &s, &runner, None).await;
    let job = seal_job(&s, &sender, &Target::Any);
    let id = job.envelope.header.id.clone();
    assert_eq!(submit(&env, &s, &sender, &job).await.status(), StatusCode::CREATED);
    assert_eq!(claim(&env, &s, &runner, &id).await, StatusCode::NO_CONTENT);
    let hb: Value = heartbeat(&env, &s, &runner, Some(&id)).await.json().await.unwrap();
    assert_eq!(hb["jobs"], json!([id]));
    heartbeat(&env, &s, &runner, None).await;
    assert_eq!(job_state(&env, &s, &owner, &id).await["reason"], "runner_lost");
}

fn seal_progress(s: &Sess, runner: &Member, job: &SealedItem, tail: &str) -> SealedItem {
    let job_ref = ItemRef::to(job);
    let p = JobProgress {
        job: job_ref.clone(),
        elapsed_ms: 1000,
        tail: Some(tail.into()),
        tail_truncated: false,
        stream: None,
        offset: None,
        data: None,
        truncated: false,
    };
    seal_kind(s, runner, ItemKind::Progress, None, vec![job_ref], Payload::progress(p))
}

fn seal_chunk(
    s: &Sess,
    runner: &Member,
    job: &SealedItem,
    stream: OutStream,
    offset: u64,
    data: &str,
) -> SealedItem {
    let job_ref = ItemRef::to(job);
    let p = JobProgress {
        job: job_ref.clone(),
        elapsed_ms: 1000,
        tail: None,
        tail_truncated: false,
        stream: Some(stream),
        offset: Some(offset),
        data: Some(data.into()),
        truncated: false,
    };
    seal_kind(s, runner, ItemKind::Progress, None, vec![job_ref], Payload::progress(p))
}

/// A runner that is online, approved and running a job.
async fn running_job(
    env: &Env,
    s: &Sess,
    owner: &Member,
    sender: &Member,
) -> (Member, SealedItem, RunnerStream) {
    let runner = join_runner(env, s, "runner-01", &[]).await;
    let stream = RunnerStream::open(env, s, &runner).await;
    approve(env, s, owner, &runner).await;
    let job = seal_job(s, sender, &Target::Any);
    assert_eq!(submit(env, s, sender, &job).await.status(), StatusCode::CREATED);
    assert_eq!(claim(env, s, &runner, &job.envelope.header.id).await, StatusCode::NO_CONTENT);
    (runner, job, stream)
}

/// Post an output chunk; returns its item id and event id.
async fn post_chunk(
    env: &Env,
    s: &Sess,
    runner: &Member,
    job: &SealedItem,
    offset: u64,
    data: &str,
) -> (String, u64) {
    let chunk = seal_chunk(s, runner, job, OutStream::Stdout, offset, data);
    let r = post(env, s, runner, frame(&chunk)).await;
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().await.unwrap());
    let v: Value = r.json().await.unwrap();
    (chunk.envelope.header.id.clone(), v["seq"].as_u64().unwrap())
}

fn mentions(evs: &[Value], id: &str) -> bool {
    evs.iter().any(|e| e.to_string().contains(id))
}

#[tokio::test(flavor = "multi_thread")]
async fn progress_is_not_history_and_leaves_no_trace() {
    let (env, s, owner, sender) = execute_env(|c| {
        c.max_items = 6;
        c.blob_hold_ms = 1500;
    })
    .await;
    let (runner, job, _stream) = running_job(&env, &s, &owner, &sender).await;
    let mut ids = vec![];
    for i in 0..5 {
        ids.push(post_chunk(&env, &s, &runner, &job, i * 4, "out\n").await.0);
    }

    // Five chunks and the job: they do not fill a six-item session, which
    // still takes five more items; the sixth is the session's limit.
    for i in 0..5 {
        let r = post(&env, &s, &sender, frame(&seal_text(&s, &sender, &format!("note {i}")))).await;
        assert_eq!(r.status(), StatusCode::CREATED, "note {i}: {}", r.text().await.unwrap());
    }
    let r = post(&env, &s, &sender, frame(&seal_text(&s, &sender, "one too many"))).await;
    assert_eq!(error_code(r).await, (StatusCode::TOO_MANY_REQUESTS, "session_full".into()));

    // Held and listed like any item until delivered.
    let evs = events(&env, &s, &owner).await;
    assert!(ids.iter().all(|id| mentions(&evs, id)));
    assert_eq!(blob(&env, &s, &sender, &ids[1]).await.status(), StatusCode::OK);

    // Once every recipient has fetched one it goes at once (no grace
    // period), and the live ones are told; nobody keeps its envelope.
    let live = call(&env, &owner, reqwest::Method::GET, format!("/v1/sessions/{}/stream", s.id)).await;
    ack(&env, &s, &sender, &ids[0]).await;
    assert_eq!(blob(&env, &s, &owner, &ids[0]).await.status(), StatusCode::OK);
    ack(&env, &s, &owner, &ids[0]).await;
    let told = read_sse_until(live, "event: evicted").await;
    assert!(told.contains(&ids[0]));
    assert_eq!(blob(&env, &s, &owner, &ids[0]).await.status(), StatusCode::NOT_FOUND);
    let evs = events(&env, &s, &owner).await;
    assert!(!mentions(&evs, &ids[0]), "a delivered chunk left an event behind");
    let on_disk = env.dir.path().join("sessions").join(&s.id).join("blobs");
    assert!(!on_disk.join(&ids[0]).exists());
    // Asking for it, or acking it late, is a plain "no such item".
    assert_eq!(want(&env, &s, &owner, &ids[0]).await.status(), StatusCode::NOT_FOUND);
    let late =
        call(&env, &owner, reqwest::Method::POST, format!("/v1/sessions/{}/items/{}/ack", s.id, ids[0]));
    assert_eq!(late.await.status(), StatusCode::NOT_FOUND);

    // The others nobody fetched go when the blob hold ends.
    assert!(
        eventually(|| async { blob(&env, &s, &owner, &ids[4]).await.status() == StatusCode::NOT_FOUND })
            .await
    );
    let evs = events(&env, &s, &owner).await;
    assert!(ids.iter().all(|id| !mentions(&evs, id)));
    assert!(ids.iter().all(|id| !on_disk.join(id).exists()));
    // Everything else stays: the job and the notes.
    assert!(mentions(&evs, &job.envelope.header.id));
    assert_eq!(evs.iter().filter(|e| e["kind"] == "item").count(), 6);
    let trail = audit(&env, &s, &owner).await;
    assert_eq!(trail.status(), StatusCode::OK);
    let trail = trail.text().await.unwrap();
    assert!(ids.iter().all(|id| !trail.contains(id)), "progress is not in the audit trail");
}

#[tokio::test(flavor = "multi_thread")]
async fn held_progress_has_its_own_limit() {
    let (env, s, owner, sender) = execute_env(|c| c.max_items = 4).await;
    let (runner, job, _stream) = running_job(&env, &s, &owner, &sender).await;
    for i in 0..4 {
        post_chunk(&env, &s, &runner, &job, i, "x").await;
    }
    let chunk = seal_chunk(&s, &runner, &job, OutStream::Stdout, 4, "x");
    let r = post(&env, &s, &runner, frame(&chunk)).await;
    assert_eq!(error_code(r).await, (StatusCode::TOO_MANY_REQUESTS, "session_full".into()));
    // The session's history is untouched: the sender can still post.
    let r = post(&env, &s, &sender, frame(&seal_text(&s, &sender, "hello"))).await;
    assert_eq!(r.status(), StatusCode::CREATED);
}

#[tokio::test(flavor = "multi_thread")]
async fn progress_event_ids_are_not_reused_after_a_restart() {
    let (mut env, s, owner, sender) = execute_env(|_| {}).await;
    let (runner, job, stream) = running_job(&env, &s, &owner, &sender).await;
    let mut last = 0;
    let mut ids = vec![];
    for i in 0..3 {
        let (id, seq) = post_chunk(&env, &s, &runner, &job, i, "x").await;
        ids.push(id);
        last = seq;
    }
    drop(stream);

    // Chunks are not in the log, so a restart forgets them, but it must not
    // hand their event ids out again.
    env.restart(|_| {}).await;
    let blobs = env.dir.path().join("sessions").join(&s.id).join("blobs");
    assert!(ids.iter().all(|id| !blobs.join(id).exists()), "an orphaned chunk survived the restart");
    let note = seal_text(&s, &sender, "after the restart");
    let r = post(&env, &s, &sender, frame(&note)).await;
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().await.unwrap());
    let seq = r.json::<Value>().await.unwrap()["seq"].as_u64().unwrap();
    assert!(seq > last, "event id {seq} was already used by a chunk ({last})");
    let evs = events(&env, &s, &owner).await;
    let seqs: Vec<u64> = evs.iter().map(|e| e["seq"].as_u64().unwrap()).collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]), "{seqs:?}");
    assert_eq!(seqs.last(), Some(&seq));
    // The job is still the runner's, and its chunks flow on after the restart.
    let (_, next) = post_chunk(&env, &s, &runner, &job, 3, "x").await;
    assert!(next > seq);
    // Reserving ids is bookkeeping, not part of the trail.
    let trail = audit(&env, &s, &owner).await.text().await.unwrap();
    assert!(!trail.contains("reserve"));
    // And another restart, now with the reserved block in the log, loads.
    env.restart(|_| {}).await;
    assert!(events(&env, &s, &owner).await.len() >= evs.len());
}

fn seal_shell_job(s: &Sess, author: &Member, code: &str) -> SealedItem {
    let spec = JobSpec {
        kind: Some(JobKind::Shell),
        cwd: None,
        tree: None,
        fresh: false,
        filename: "job.sh".into(),
        code: code.into(),
        runtime: "python3.12".into(),
        timeout_s: 30,
        memory_mb: None,
        files: vec![],
        requirements: vec![],
        target: Target::Any,
        progress_file: None,
    };
    seal_kind(s, author, ItemKind::Job, Some(ContentType::Sh), vec![], Payload::job(spec))
}

#[tokio::test(flavor = "multi_thread")]
async fn shell_jobs_route_like_python_ones() {
    let env = Env::new().await;
    let s = new_session_with(Mode::Execute, Some(3_600_000), |p| {
        let limits = JobLimits { kinds: Some(vec![JobKind::Python, JobKind::Shell]), ..Default::default() };
        p.job_limits = Some(limits);
    });
    assert_eq!(create(&env, &s).await.status(), StatusCode::CREATED);
    let owner = join(&env, &s, Role::Owner, "owner").await;
    let sender = join(&env, &s, Role::Sender, "planner-agent").await;
    // A python-only runner, joined first, is passed over for shell jobs.
    let py_only = join_runner(&env, &s, "runner-00", &["cpu"]).await;
    let _py_stream = RunnerStream::open(&env, &s, &py_only).await;
    approve(&env, &s, &owner, &py_only).await;
    let r = submit(&env, &s, &sender, &seal_shell_job(&s, &sender, "true")).await;
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let why = r.text().await.unwrap();
    assert!(why.contains("no_runner_available") && why.contains("runs shell jobs"), "{why}");
    let runner =
        join_runner_kinds(&env, &s, "runner-01", &["cpu"], 1, &[JobKind::Python, JobKind::Shell]).await;
    let mut stream = RunnerStream::open(&env, &s, &runner).await;
    approve(&env, &s, &owner, &runner).await;

    let job = seal_shell_job(&s, &sender, "echo hi\n");
    let id = job.envelope.header.id.clone();
    let r = submit(&env, &s, &sender, &job).await;
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().await.unwrap());
    let assigned = stream.next("job_assigned").await;
    assert_eq!(assigned["job"], id.as_str());
    assert_eq!(assigned["envelope"].as_str().unwrap(), canon(&job.envelope));
    assert_eq!(claim(&env, &s, &runner, &id).await, StatusCode::NO_CONTENT);
    assert_eq!(job_state(&env, &s, &owner, &id).await["state"], "running");

    let (chunk_id, _) = post_chunk(&env, &s, &runner, &job, 0, "hi\n").await;
    assert_eq!(blob(&env, &s, &sender, &chunk_id).await.status(), StatusCode::OK);
    let r = post(&env, &s, &runner, frame(&seal_result(&s, &runner, &job))).await;
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().await.unwrap());
    assert_eq!(job_state(&env, &s, &owner, &id).await["state"], "done");

    // The relay learns the kind from the header, as it learns `py`.
    let evs = events(&env, &s, &owner).await;
    let ev = evs.iter().find(|e| e["kind"] == "item" && e["data"]["envelope"].to_string().contains(&id));
    let env_json: Value = serde_json::from_str(ev.unwrap()["data"]["envelope"].as_str().unwrap()).unwrap();
    assert_eq!(env_json["header"]["subkind"], "sh");

    // Python jobs still go through, and a python-only session refuses shell.
    let r = submit(&env, &s, &sender, &seal_job(&s, &sender, &Target::Any)).await;
    assert_eq!(r.status(), StatusCode::CREATED);
    let (env2, s2, _owner2, sender2) = execute_env(|_| {}).await;
    let r = submit(&env2, &s2, &sender2, &seal_shell_job(&s2, &sender2, "true")).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread")]
async fn busy_runners_refuse_and_lost_jobs_come_back() {
    let (env, s, owner, sender) = execute_env(|c| {
        c.runner_timeout_ms = 400;
        c.job_reconnect_grace_ms = 1600;
    })
    .await;
    let runner = join_runner(&env, &s, "runner-01", &[]).await;
    let _stream = RunnerStream::open(&env, &s, &runner).await;
    approve(&env, &s, &owner, &runner).await;
    assert_eq!(runners(&env, &s, &owner).await[0]["busy"], false);

    let job = seal_job(&s, &sender, &Target::Any);
    let id = job.envelope.header.id.clone();
    assert_eq!(submit(&env, &s, &sender, &job).await.status(), StatusCode::CREATED);
    assert_eq!(claim(&env, &s, &runner, &id).await, StatusCode::NO_CONTENT);
    assert_eq!(runners(&env, &s, &owner).await[0]["busy"], true);

    // Busy: refused at once with its own code, never queued.
    let other = seal_job(&s, &sender, &Target::Any);
    let r = submit(&env, &s, &sender, &other).await;
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(r.json::<Value>().await.unwrap()["error"], "runner_busy");
    let other_id = other.envelope.header.id.clone();
    assert_eq!(job_state(&env, &s, &owner, &other_id).await["reason"], "runner_busy");

    // Progress only for the job it runs.
    let p = seal_progress(&s, &runner, &job, "step 3 of 10");
    assert_eq!(post(&env, &s, &runner, frame(&p)).await.status(), StatusCode::CREATED);
    let p = seal_progress(&s, &runner, &other, "not mine");
    assert_eq!(post(&env, &s, &runner, frame(&p)).await.status(), StatusCode::FORBIDDEN);
    let p = seal_progress(&s, &sender, &job, "senders do not report progress");
    assert_eq!(post(&env, &s, &sender, frame(&p)).await.status(), StatusCode::FORBIDDEN);

    // Silent past the runner timeout: offline, but the job keeps running
    // through the grace period.
    tokio::time::sleep(Duration::from_millis(550)).await;
    assert_eq!(runners(&env, &s, &owner).await[0]["online"], false);
    assert_eq!(job_state(&env, &s, &owner, &id).await["state"], "running");
    // Past the grace: lost.
    assert!(eventually(|| async { job_state(&env, &s, &owner, &id).await["reason"] == "runner_lost" }).await);

    // The runner reconnects still working on it: it is running again.
    let hb: Value = heartbeat(&env, &s, &runner, Some(&id)).await.json().await.unwrap();
    assert_eq!(hb["jobs"], json!([id]));
    assert_eq!(job_state(&env, &s, &owner, &id).await["state"], "running");

    // Lost again, and the result arrives later: it still finishes the job.
    assert!(eventually(|| async { job_state(&env, &s, &owner, &id).await["reason"] == "runner_lost" }).await);
    let res = seal_result(&s, &runner, &job);
    assert_eq!(post(&env, &s, &runner, frame(&res)).await.status(), StatusCode::CREATED);
    assert_eq!(job_state(&env, &s, &owner, &id).await["state"], "done");
    assert_eq!(runners(&env, &s, &owner).await[0]["busy"], false);
}

/// A runner with `slots` slots that is online and approved.
async fn pool_runner(
    env: &Env,
    s: &Sess,
    owner: &Member,
    name: &str,
    labels: &[&str],
    slots: u32,
) -> (Member, RunnerStream) {
    let runner = join_runner_slots(env, s, name, labels, slots).await;
    let stream = RunnerStream::open(env, s, &runner).await;
    approve(env, s, owner, &runner).await;
    (runner, stream)
}

/// Submit a job that must be routed; returns it and the runner it went to.
async fn submit_ok(env: &Env, s: &Sess, sender: &Member, target: &Target) -> (SealedItem, String) {
    let job = seal_job(s, sender, target);
    let r = submit(env, s, sender, &job).await;
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().await.unwrap());
    let runner = r.json::<Value>().await.unwrap()["runner"].as_str().unwrap().to_string();
    (job, runner)
}

fn runner_row<'a>(list: &'a [Value], m: &Member) -> &'a Value {
    list.iter().find(|r| r["participant_pub"] == pk(m).as_str()).expect("runner is listed")
}

/// (slots, active jobs, busy) of a runner in a listing.
fn load(list: &[Value], m: &Member) -> (u64, usize, bool) {
    let r = runner_row(list, m);
    (r["slots"].as_u64().unwrap(), r["jobs"].as_array().unwrap().len(), r["busy"].as_bool().unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn jobs_go_to_the_least_loaded_runner_and_busy_means_every_slot_is_taken() {
    let (mut env, s, owner, sender) = execute_env(|_| {}).await;
    // Joined first, two slots; then one slot.
    let (wide, _w) = pool_runner(&env, &s, &owner, "runner-01", &["cpu"], 2).await;
    let (narrow, _n) = pool_runner(&env, &s, &owner, "runner-02", &["cpu"], 1).await;
    let any = Target::Any;

    // Both empty: the earliest joined. Then the one with the lower load
    // (1/2 against 0/1), then the one that still has room.
    let (j1, r1) = submit_ok(&env, &s, &sender, &any).await;
    let (_, r2) = submit_ok(&env, &s, &sender, &any).await;
    let (_, r3) = submit_ok(&env, &s, &sender, &any).await;
    assert_eq!((r1, r2, r3), (pk(&wide), pk(&narrow), pk(&wide)));

    // Every slot is taken: not queued, and named as busy rather than absent.
    let full = seal_job(&s, &sender, &any);
    let r = submit(&env, &s, &sender, &full).await;
    assert_eq!(error_code(r).await, (StatusCode::CONFLICT, "runner_busy".into()));
    assert_eq!(job_state(&env, &s, &owner, &full.envelope.header.id).await["reason"], "runner_busy");
    let pinned = Target::Runner { participant_pub: wide.kp.public(), name: "runner-01".into() };
    let r = submit(&env, &s, &sender, &seal_job(&s, &sender, &pinned)).await;
    assert_eq!(error_code(r).await, (StatusCode::CONFLICT, "runner_busy".into()));
    let gpu = Target::Labels { labels: vec!["gpu".into()] };
    let r = submit(&env, &s, &sender, &seal_job(&s, &sender, &gpu)).await;
    assert_eq!(error_code(r).await, (StatusCode::CONFLICT, "no_runner_available".into()));

    // The listing says how loaded each runner is; `busy` is "no free slot".
    let list = runners(&env, &s, &owner).await;
    assert_eq!(load(&list, &wide), (2, 2, true));
    assert_eq!(load(&list, &narrow), (1, 1, true));
    assert!(!runner_row(&list, &wide)["job"].is_null(), "older clients read `job` as busy");

    // The loads are rebuilt from the log when the relay restarts; the
    // runners then reconnect.
    drop((_w, _n));
    env.restart(|_| {}).await;
    let list = runners(&env, &s, &owner).await;
    assert_eq!(load(&list, &wide), (2, 2, true));
    assert_eq!(load(&list, &narrow), (1, 1, true));
    let _w = RunnerStream::open(&env, &s, &wide).await;
    let _n = RunnerStream::open(&env, &s, &narrow).await;

    // One slot frees when a job ends; only that runner takes the next job,
    // and the one after that is refused again.
    assert_eq!(claim(&env, &s, &wide, &j1.envelope.header.id).await, StatusCode::NO_CONTENT);
    let r = post(&env, &s, &wide, frame(&seal_result(&s, &wide, &j1))).await;
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().await.unwrap());
    let list = runners(&env, &s, &owner).await;
    assert_eq!(load(&list, &wide), (2, 1, false));
    assert!(runner_row(&list, &wide)["job"].is_null());
    let (_, r4) = submit_ok(&env, &s, &sender, &any).await;
    assert_eq!(r4, pk(&wide));
    let r = submit(&env, &s, &sender, &seal_job(&s, &sender, &any)).await;
    assert_eq!(error_code(r).await, (StatusCode::CONFLICT, "runner_busy".into()));
}

#[tokio::test(flavor = "multi_thread")]
async fn heartbeats_name_every_running_job_and_a_lost_one_is_lost_alone() {
    let (env, s, owner, sender) = execute_env(|_| {}).await;
    let (runner, _stream) = pool_runner(&env, &s, &owner, "runner-01", &[], 3).await;
    let mut jobs = vec![];
    for _ in 0..3 {
        let (job, _) = submit_ok(&env, &s, &sender, &Target::Any).await;
        assert_eq!(claim(&env, &s, &runner, &job.envelope.header.id).await, StatusCode::NO_CONTENT);
        jobs.push(job);
    }
    let ids: Vec<String> = jobs.iter().map(|j| j.envelope.header.id.clone()).collect();
    let [a, b, c] = [ids[0].as_str(), ids[1].as_str(), ids[2].as_str()];

    // All three named: nothing is lost, and the answer lists them.
    let hb: Value = heartbeat_jobs(&env, &s, &runner, &[a, b, c]).await.json().await.unwrap();
    let mut named: Vec<&str> = hb["jobs"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    named.sort();
    let mut want = vec![a, b, c];
    want.sort();
    assert_eq!(named, want);
    for id in [a, b, c] {
        assert_eq!(job_state(&env, &s, &owner, id).await["state"], "running");
    }

    // One left out: only that job is lost, and its slot is free again.
    heartbeat_jobs(&env, &s, &runner, &[a, c]).await;
    assert_eq!(job_state(&env, &s, &owner, b).await["reason"], "runner_lost");
    for id in [a, c] {
        assert_eq!(job_state(&env, &s, &owner, id).await["state"], "running");
    }
    assert_eq!(load(&runners(&env, &s, &owner).await, &runner), (3, 2, false));

    // Named again, it comes back, and the runner is full once more.
    heartbeat_jobs(&env, &s, &runner, &[a, b, c]).await;
    assert_eq!(job_state(&env, &s, &owner, b).await["state"], "running");
    assert_eq!(load(&runners(&env, &s, &owner).await, &runner), (3, 3, true));

    // Idle: all three are lost.
    heartbeat_jobs(&env, &s, &runner, &[]).await;
    for id in [a, b, c] {
        assert_eq!(job_state(&env, &s, &owner, id).await["reason"], "runner_lost");
    }
    assert_eq!(load(&runners(&env, &s, &owner).await, &runner), (3, 0, false));

    // Three newer jobs take the slots. A lost job does not push into a full
    // runner, but its result, when it comes, still finishes it.
    for _ in 0..3 {
        submit_ok(&env, &s, &sender, &Target::Any).await;
    }
    heartbeat_jobs(&env, &s, &runner, &[a]).await;
    let st = job_state(&env, &s, &owner, a).await;
    assert_eq!((st["state"].as_str(), st["reason"].as_str()), (Some("failed"), Some("runner_lost")));
    assert_eq!(load(&runners(&env, &s, &owner).await, &runner), (3, 3, true));
    let r = post(&env, &s, &runner, frame(&seal_result(&s, &runner, &jobs[0]))).await;
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().await.unwrap());
    assert_eq!(job_state(&env, &s, &owner, a).await["state"], "done");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reconnecting_runner_gets_every_assignment_and_cancel_again() {
    let (env, s, owner, sender) = execute_env(|_| {}).await;
    let (runner, stream) = pool_runner(&env, &s, &owner, "runner-01", &[], 3).await;
    let mut ids = vec![];
    for _ in 0..3 {
        let (job, _) = submit_ok(&env, &s, &sender, &Target::Any).await;
        ids.push(job.envelope.header.id.clone());
        // The backlog is oldest first: give each job its own millisecond.
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    for id in &ids[..2] {
        assert_eq!(claim(&env, &s, &runner, id).await, StatusCode::NO_CONTENT);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // The second is cancelled while it runs.
    let path = format!("/v1/sessions/{}/jobs/{}/cancel", s.id, ids[1]);
    assert_eq!(call(&env, &sender, reqwest::Method::POST, path).await.status(), StatusCode::ACCEPTED);
    drop(stream);

    let mut again = RunnerStream::open(&env, &s, &runner).await;
    let mut got = vec![];
    for _ in 0..3 {
        let assigned = again.next("job_assigned").await;
        assert!(assigned["envelope"].is_string());
        got.push(assigned["job"].as_str().unwrap().to_string());
    }
    // Oldest first, by when each entered its current state: the one still
    // unclaimed, then the two claimed in order.
    assert_eq!(got, [ids[2].clone(), ids[0].clone(), ids[1].clone()]);
    // The pending cancel repeats with its job; nothing else was cancelled.
    assert_eq!(again.next("job_cancel").await["job"], ids[1].as_str());
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_rules_and_forwarding() {
    let (env, s, owner, sender) = execute_env(|_| {}).await;
    let other = join(&env, &s, Role::Sender, "other-agent").await;
    let runner = join_runner(&env, &s, "runner-01", &[]).await;
    let mut stream = RunnerStream::open(&env, &s, &runner).await;
    approve(&env, &s, &owner, &runner).await;

    let job = seal_job(&s, &sender, &Target::Any);
    let id = job.envelope.header.id.clone();
    assert_eq!(submit(&env, &s, &sender, &job).await.status(), StatusCode::CREATED);
    stream.next("job_assigned").await;
    claim(&env, &s, &runner, &id).await;

    let path = format!("/v1/sessions/{}/jobs/{id}/cancel", s.id);
    let post_ = reqwest::Method::POST;
    assert_eq!(call(&env, &other, post_.clone(), path.clone()).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(call(&env, &runner, post_.clone(), path.clone()).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(call(&env, &sender, post_.clone(), path.clone()).await.status(), StatusCode::ACCEPTED);
    assert_eq!(stream.next("job_cancel").await["job"], id.as_str());
    // Running jobs end with the runner's result.
    assert_eq!(job_state(&env, &s, &owner, &id).await["state"], "running");
    post(&env, &s, &runner, frame(&seal_result(&s, &runner, &job))).await;
    assert_eq!(call(&env, &owner, post_, path).await.status(), StatusCode::CONFLICT);

    // An unclaimed job fails as soon as it is cancelled.
    let job = seal_job(&s, &sender, &Target::Any);
    let id2 = job.envelope.header.id.clone();
    assert_eq!(submit(&env, &s, &sender, &job).await.status(), StatusCode::CREATED);
    let r =
        call(&env, &owner, reqwest::Method::POST, format!("/v1/sessions/{}/jobs/{id2}/cancel", s.id)).await;
    assert_eq!(r.status(), StatusCode::ACCEPTED);
    let st = job_state(&env, &s, &owner, &id2).await;
    assert_eq!((st["state"].as_str(), st["reason"].as_str()), (Some("failed"), Some("cancelled")));
    assert_eq!(claim(&env, &s, &runner, &id2).await, StatusCode::CONFLICT);
}

#[tokio::test(flavor = "multi_thread")]
async fn rejected_runners_are_cut_off() {
    let (env, s, owner, sender) = execute_env(|_| {}).await;
    let runner = join_runner(&env, &s, "runner-01", &[]).await;
    let mut stream = RunnerStream::open(&env, &s, &runner).await;
    approve(&env, &s, &owner, &runner).await;
    let job = seal_job(&s, &sender, &Target::Any);
    let id = job.envelope.header.id.clone();
    assert_eq!(submit(&env, &s, &sender, &job).await.status(), StatusCode::CREATED);

    let r = call(
        &env,
        &owner,
        reqwest::Method::POST,
        format!("/v1/sessions/{}/runners/{}/reject", s.id, pk(&runner)),
    )
    .await;
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    stream.next("rejected").await;
    assert!(stream.ended().await);
    assert_eq!(job_state(&env, &s, &owner, &id).await["reason"], "runner_rejected");
    assert_eq!(claim(&env, &s, &runner, &id).await, StatusCode::UNAUTHORIZED);
    assert_eq!(approve(&env, &s, &owner, &runner).await, StatusCode::CONFLICT);
    assert_eq!(runners(&env, &s, &owner).await[0]["rejected"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn runners_need_execute_mode_and_approval_survives_restart() {
    // Relay sessions refuse the execute endpoints.
    let env = Env::new().await;
    let relay = new_session(Mode::Relay, 3_600_000);
    create(&env, &relay).await;
    let sender = join(&env, &relay, Role::Sender, "a").await;
    let r = submit(&env, &relay, &sender, &seal_job(&relay, &sender, &Target::Any)).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    drop(env);

    let (mut env, s, owner, sender) = execute_env(|_| {}).await;
    let runner = join_runner(&env, &s, "runner-01", &[]).await;
    approve(&env, &s, &owner, &runner).await;
    let stream = RunnerStream::open(&env, &s, &runner).await;
    let job = seal_job(&s, &sender, &Target::Any);
    let id = job.envelope.header.id.clone();
    assert_eq!(submit(&env, &s, &sender, &job).await.status(), StatusCode::CREATED);
    claim(&env, &s, &runner, &id).await;
    drop(stream);

    env.restart(|_| {}).await;
    let list = runners(&env, &s, &owner).await;
    assert_eq!((list[0]["approved"].as_bool(), list[0]["online"].as_bool()), (Some(true), Some(false)));
    assert_eq!(job_state(&env, &s, &owner, &id).await["state"], "running");
    // Reconnecting repeats the active assignment.
    let mut stream = RunnerStream::open(&env, &s, &runner).await;
    assert_eq!(stream.next("job_assigned").await["job"], id.as_str());
}

#[tokio::test(flavor = "multi_thread")]
async fn only_the_assigned_approved_runner_posts_results() {
    let (env, s, owner, sender) = execute_env(|_| {}).await;
    let runner = join_runner(&env, &s, "runner-01", &[]).await;
    let other = join_runner(&env, &s, "runner-02", &[]).await;
    let _stream = RunnerStream::open(&env, &s, &runner).await;
    approve(&env, &s, &owner, &runner).await;
    let job = seal_job(&s, &sender, &Target::Any);
    assert_eq!(submit(&env, &s, &sender, &job).await.status(), StatusCode::CREATED);

    // Unapproved: no results, no files.
    let forged = seal_result(&s, &other, &job);
    assert_eq!(post(&env, &s, &other, frame(&forged)).await.status(), StatusCode::FORBIDDEN);
    // Approved but not assigned this job: no result for it.
    approve(&env, &s, &owner, &other).await;
    let forged = seal_result(&s, &other, &job);
    assert_eq!(post(&env, &s, &other, frame(&forged)).await.status(), StatusCode::FORBIDDEN);
    // The assigned runner may.
    let real = seal_result(&s, &runner, &job);
    assert_eq!(post(&env, &s, &runner, frame(&real)).await.status(), StatusCode::CREATED);
}

#[tokio::test(flavor = "multi_thread")]
async fn cancels_survive_a_reconnect_and_leaving_fails_the_job() {
    let (env, s, owner, sender) = execute_env(|_| {}).await;
    let runner = join_runner(&env, &s, "runner-01", &[]).await;
    let stream = RunnerStream::open(&env, &s, &runner).await;
    approve(&env, &s, &owner, &runner).await;
    let job = seal_job(&s, &sender, &Target::Any);
    let id = job.envelope.header.id.clone();
    assert_eq!(submit(&env, &s, &sender, &job).await.status(), StatusCode::CREATED);
    claim(&env, &s, &runner, &id).await;

    // The cancel arrives while the runner's stream is down.
    drop(stream);
    let r =
        call(&env, &sender, reqwest::Method::POST, format!("/v1/sessions/{}/jobs/{id}/cancel", s.id)).await;
    assert_eq!(r.status(), StatusCode::ACCEPTED);
    let mut stream = RunnerStream::open(&env, &s, &runner).await;
    assert_eq!(stream.next("job_assigned").await["job"], id.as_str());
    assert_eq!(stream.next("job_cancel").await["job"], id.as_str());

    // Leaving with a job in hand fails it.
    let r = call(&env, &runner, reqwest::Method::POST, format!("/v1/sessions/{}/leave", s.id)).await;
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let st = job_state(&env, &s, &owner, &id).await;
    assert_eq!((st["state"].as_str(), st["reason"].as_str()), (Some("failed"), Some("runner_left")));
}

#[tokio::test(flavor = "multi_thread")]
async fn revoking_runners_fails_their_jobs_and_ends_their_streams() {
    let (env, s, owner, sender) = execute_env(|_| {}).await;
    let runner = join_runner(&env, &s, "runner-01", &[]).await;
    let mut stream = RunnerStream::open(&env, &s, &runner).await;
    approve(&env, &s, &owner, &runner).await;
    let job = seal_job(&s, &sender, &Target::Any);
    let id = job.envelope.header.id.clone();
    assert_eq!(submit(&env, &s, &sender, &job).await.status(), StatusCode::CREATED);
    stream.next("job_assigned").await;

    assert_eq!(revoke(&env, &s, &owner, "runner").await.status(), StatusCode::NO_CONTENT);
    assert_eq!(job_state(&env, &s, &owner, &id).await["reason"], "runner_revoked");
    assert!(stream.ended().await);
    assert_eq!(claim(&env, &s, &runner, &id).await, StatusCode::UNAUTHORIZED);
    // No runner can join to take its place.
    let (_, body) = runner_join_body(&s, "runner-02", &[], 1, &[JobKind::Python]);
    assert_eq!(error_code(post_join(&env, &s, body).await).await, (StatusCode::FORBIDDEN, "revoked".into()));
}

#[tokio::test(flavor = "multi_thread")]
async fn revoking_senders_fails_their_jobs_and_spares_rejected_runners() {
    let (env, s, owner, sender) = execute_env(|_| {}).await;
    let runner = join_runner(&env, &s, "runner-01", &[]).await;
    let mut stream = RunnerStream::open(&env, &s, &runner).await;
    approve(&env, &s, &owner, &runner).await;
    let job = seal_job(&s, &sender, &Target::Any);
    let id = job.envelope.header.id.clone();
    assert_eq!(submit(&env, &s, &sender, &job).await.status(), StatusCode::CREATED);
    stream.next("job_assigned").await;
    assert_eq!(claim(&env, &s, &runner, &id).await, StatusCode::NO_CONTENT);

    // The sender's running job fails and its runner is told to stop.
    assert_eq!(revoke(&env, &s, &owner, "sender").await.status(), StatusCode::NO_CONTENT);
    let st = job_state(&env, &s, &owner, &id).await;
    assert_eq!((st["state"].as_str(), st["reason"].as_str()), (Some("failed"), Some("author_revoked")));
    stream.next("job_cancel").await;

    // A runner rejected earlier is not cut off again: the revoked event and
    // the audit trail agree on who the revocation reached.
    let rejected = join_runner(&env, &s, "runner-02", &[]).await;
    let r = call(
        &env,
        &owner,
        reqwest::Method::POST,
        format!("/v1/sessions/{}/runners/{}/reject", s.id, pk(&rejected)),
    )
    .await;
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert_eq!(revoke(&env, &s, &owner, "runner").await.status(), StatusCode::NO_CONTENT);
    let evs = events(&env, &s, &owner).await;
    let ev = evs.iter().find(|e| e["kind"] == "revoked" && e["data"]["role"] == "runner").unwrap();
    assert_eq!(ev["data"]["participants"], json!([pk(&runner)]));
    let text = audit(&env, &s, &owner).await.text().await.unwrap();
    let line: Value = text
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|l| l["action"] == "revoke" && l["role"] == "runner")
        .unwrap();
    assert_eq!(line["participants"], ev["data"]["participants"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn owner_approvals_stay_for_late_joiners_and_unapproved_runners_cannot_ask() {
    let (env, s, owner, sender) = execute_env(|_| {}).await;
    let runner = join_runner(&env, &s, "runner-01", &[]).await;
    let waiting = join_runner(&env, &s, "runner-02", &[]).await;
    approve(&env, &s, &owner, &runner).await;
    let approval = seal_kind(
        &s,
        &owner,
        ItemKind::Event,
        None,
        vec![],
        Payload {
            meta: Meta::Event(Event::RunnerApprove { participant_pub: runner.kp.public() }),
            body: vec![],
        },
    );
    let approval_id = approval.envelope.header.id.clone();
    let note = seal_text(&s, &sender, "goes once delivered");
    let note_id = note.envelope.header.id.clone();
    assert_eq!(post(&env, &s, &owner, frame(&approval)).await.status(), StatusCode::CREATED);
    assert_eq!(post(&env, &s, &sender, frame(&note)).await.status(), StatusCode::CREATED);
    for m in [&sender, &runner] {
        ack(&env, &s, m, &approval_id).await;
    }
    for m in [&owner, &runner] {
        ack(&env, &s, m, &note_id).await;
    }
    assert!(
        eventually(|| async { blob(&env, &s, &owner, &note_id).await.status() == StatusCode::GONE }).await
    );
    // The owner's signed approval is still there for whoever joins later.
    let late = join(&env, &s, Role::Observer, "late").await;
    assert_eq!(blob(&env, &s, &late, &approval_id).await.status(), StatusCode::OK);
    // A runner the owner has not approved cannot pull evicted history.
    assert_eq!(want(&env, &s, &waiting, &note_id).await.status(), StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_runners_event_stream_ends() {
    let (env, s, owner, _sender) = execute_env(|_| {}).await;
    let runner = join_runner(&env, &s, "runner-01", &[]).await;
    let stream = env
        .http
        .get(env.url(&format!("/v1/sessions/{}/stream", s.id)))
        .bearer_auth(&runner.token)
        .send()
        .await
        .unwrap();
    let r = call(
        &env,
        &owner,
        reqwest::Method::POST,
        format!("/v1/sessions/{}/runners/{}/reject", s.id, pk(&runner)),
    )
    .await;
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    // The body ends after the rejection instead of staying open.
    let body =
        tokio::time::timeout(Duration::from_secs(5), stream.text()).await.expect("stream ended").unwrap();
    assert!(body.contains("\"rejected\""));
}

#[tokio::test(flavor = "multi_thread")]
async fn runners_report_their_setup() {
    let (env, s, owner, _sender) = execute_env(|_| {}).await;
    let runner = join_runner(&env, &s, "runner-01", &[]).await;
    let report = |body: Value| {
        env.http
            .post(env.url(&format!("/v1/sessions/{}/runners/me/heartbeat", s.id)))
            .bearer_auth(&runner.token)
            .body(body.to_string())
            .send()
    };
    let setup = || async {
        let [r] = runners(&env, &s, &owner).await.try_into().unwrap();
        (r["state"].clone(), r["detail"].clone())
    };
    // Runners that never say have no state.
    assert_eq!(setup().await, (Value::Null, Value::Null));
    let ok = report(serde_json::json!({"state": "failed", "detail": "no docker"})).await.unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(setup().await, (serde_json::json!("failed"), serde_json::json!("no docker")));
    // A plain heartbeat keeps the last report; a new one replaces it.
    assert_eq!(heartbeat(&env, &s, &runner, None).await.status(), StatusCode::OK);
    assert_eq!(setup().await.0, serde_json::json!("failed"));
    report(serde_json::json!({"state": "ready"})).await.unwrap();
    assert_eq!(setup().await, (serde_json::json!("ready"), Value::Null));
    for bad in [
        serde_json::json!({"state": "busy"}),
        serde_json::json!({"state": "failed", "detail": "x".repeat(301)}),
    ] {
        assert_eq!(report(bad).await.unwrap().status(), StatusCode::BAD_REQUEST);
    }
}
