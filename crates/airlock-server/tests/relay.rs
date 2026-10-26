//! End-to-end tests against a real server on a random port.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use airlock_core::cert::{issue_cert, sign_join, ClientKind, JoinRequest};
use airlock_core::encoding::canonical_json;
use airlock_core::item::{new_item_id, seal, ItemKind, NewItem, SealedItem};
use airlock_core::keys::Keypair;
use airlock_core::payload::Payload;
use airlock_core::session::{ContentType, Mode, Role, SessionParams, SessionSecrets};
use airlock_server::{start, Config, Running};
use futures_util::StreamExt;
use reqwest::StatusCode;
use serde_json::Value;

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn canon<T: serde::Serialize>(v: &T) -> String {
    String::from_utf8(canonical_json(v).unwrap()).unwrap()
}

struct Env {
    dir: tempfile::TempDir,
    running: Option<Running>,
    base: String,
    http: reqwest::Client,
}

fn test_config(dir: &std::path::Path) -> Config {
    let mut c = Config::with_data(dir);
    c.listen = "127.0.0.1:0".parse().unwrap();
    c.sweep_interval_ms = 50;
    c.blob_grace_ms = 200;
    c
}

impl Env {
    async fn new() -> Env {
        Self::with(|_| {}).await
    }

    async fn with(f: impl FnOnce(&mut Config)) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let mut c = test_config(dir.path());
        f(&mut c);
        let running = start(c).await.unwrap();
        let base = format!("http://{}", running.addr);
        Env { dir, running: Some(running), base, http: reqwest::Client::new() }
    }

    async fn restart(&mut self, f: impl FnOnce(&mut Config)) {
        self.running.take().unwrap().stop().await.unwrap();
        let mut c = test_config(self.dir.path());
        f(&mut c);
        let running = start(c).await.unwrap();
        self.base = format!("http://{}", running.addr);
        self.running = Some(running);
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }
}

struct Sess {
    secrets: SessionSecrets,
    id: String,
    manifest_json: String,
}

fn new_session(mode: Mode, ttl_ms: u64) -> Sess {
    let secrets = SessionSecrets::generate();
    let params = SessionParams {
        mode,
        created_at_ms: now_ms(),
        ttl_ms,
        allowed_types: vec![ContentType::Text, ContentType::Md, ContentType::Py],
        max_item_bytes: 1024 * 1024,
        job_limits: (mode == Mode::Execute).then(Default::default),
    };
    let signed = secrets.manifest(&params).unwrap();
    Sess { id: signed.manifest.session_id.clone(), manifest_json: canon(&signed), secrets }
}

async fn create(env: &Env, s: &Sess) -> reqwest::Response {
    env.http.post(env.url("/v1/sessions")).body(s.manifest_json.clone()).send().await.unwrap()
}

struct Member {
    kp: Keypair,
    token: String,
}

async fn join(env: &Env, s: &Sess, role: Role, name: &str) -> Member {
    let kp = Keypair::generate();
    let cert = issue_cert(&s.secrets.role_keypair(role), &s.id, role, kp.public(), now_ms()).unwrap();
    let j = sign_join(
        &kp,
        JoinRequest {
            v: 1,
            session_id: s.id.clone(),
            cert,
            display_name: name.into(),
            kind: ClientKind::Sdk,
            runner: None,
            created_at_ms: now_ms(),
        },
    )
    .unwrap();
    let r = env
        .http
        .post(env.url(&format!("/v1/sessions/{}/participants", s.id)))
        .body(canon(&j))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().await.unwrap());
    let v: Value = r.json().await.unwrap();
    Member { kp, token: v["token"].as_str().unwrap().to_string() }
}

fn seal_text(s: &Sess, author: &Member, text: &str) -> SealedItem {
    seal(
        &s.secrets.session_key(),
        &author.kp,
        NewItem {
            id: new_item_id(),
            session_id: s.id.clone(),
            kind: ItemKind::Text,
            subkind: None,
            created_at_ms: now_ms(),
            refs: vec![],
        },
        &Payload::text(text).encode().unwrap(),
    )
    .unwrap()
}

fn frame(item: &SealedItem) -> Vec<u8> {
    let env = canon(&item.envelope);
    let mut b = (env.len() as u32).to_be_bytes().to_vec();
    b.extend_from_slice(env.as_bytes());
    b.extend_from_slice(&item.blob);
    b
}

async fn post(env: &Env, s: &Sess, m: &Member, body: Vec<u8>) -> reqwest::Response {
    env.http
        .post(env.url(&format!("/v1/sessions/{}/items", s.id)))
        .bearer_auth(&m.token)
        .body(body)
        .send()
        .await
        .unwrap()
}

async fn events(env: &Env, s: &Sess, m: &Member) -> Vec<Value> {
    let r = env
        .http
        .get(env.url(&format!("/v1/sessions/{}/events", s.id)))
        .bearer_auth(&m.token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v: Value = r.json().await.unwrap();
    v["events"].as_array().unwrap().clone()
}

async fn blob(env: &Env, s: &Sess, m: &Member, item: &str) -> reqwest::Response {
    env.http
        .get(env.url(&format!("/v1/sessions/{}/items/{item}/blob", s.id)))
        .bearer_auth(&m.token)
        .send()
        .await
        .unwrap()
}

async fn ack(env: &Env, s: &Sess, m: &Member, item: &str) {
    let r = env
        .http
        .post(env.url(&format!("/v1/sessions/{}/items/{item}/ack", s.id)))
        .bearer_auth(&m.token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
}

async fn eventually<F: std::future::Future<Output = bool>>(mut f: impl FnMut() -> F) -> bool {
    for _ in 0..60 {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread")]
async fn deliver_ack_and_evict() {
    let env = Env::new().await;
    let s = new_session(Mode::Relay, 3_600_000);
    assert_eq!(create(&env, &s).await.status(), StatusCode::CREATED);
    let owner = join(&env, &s, Role::Owner, "owner").await;
    let sender = join(&env, &s, Role::Sender, "planner-agent").await;

    let item = seal_text(&s, &sender, "Cleaned dataset attached.");
    let id = item.envelope.header.id.clone();
    let r = post(&env, &s, &sender, frame(&item)).await;
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().await.unwrap());

    // The owner sees the envelope, downloads and decrypts the blob.
    let evs = events(&env, &s, &owner).await;
    let item_ev = evs.iter().find(|e| e["kind"] == "item").unwrap();
    let env_json = item_ev["data"]["envelope"].as_str().unwrap();
    assert_eq!(env_json, canon(&item.envelope));
    let bytes = blob(&env, &s, &owner, &id).await.bytes().await.unwrap().to_vec();
    let got = SealedItem { envelope: item.envelope.clone(), blob: bytes };
    let pt = got.open(&s.secrets.session_key()).unwrap();
    assert_eq!(Payload::decode(&pt).unwrap(), Payload::text("Cleaned dataset attached."));

    // The only recipient acks; after the grace period the blob is evicted.
    ack(&env, &s, &owner, &id).await;
    assert!(eventually(|| async { blob(&env, &s, &owner, &id).await.status() == StatusCode::GONE }).await);
    let evs = events(&env, &s, &owner).await;
    assert!(evs.iter().any(|e| e["kind"] == "evicted" && e["data"]["item"] == id.as_str()));
    // The envelope stays.
    assert!(evs.iter().any(|e| e["kind"] == "item"));
    let on_disk = env.dir.path().join("sessions").join(&s.id).join("blobs").join(&id);
    assert!(!on_disk.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn hold_limit_evicts_without_acks() {
    let env = Env::with(|c| c.blob_hold_ms = 300).await;
    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    let owner = join(&env, &s, Role::Owner, "owner").await;
    let sender = join(&env, &s, Role::Sender, "sender").await;
    let item = seal_text(&s, &sender, "nobody acks this");
    let id = item.envelope.header.id.clone();
    post(&env, &s, &sender, frame(&item)).await;
    assert_eq!(blob(&env, &s, &owner, &id).await.status(), StatusCode::OK);
    assert!(eventually(|| async { blob(&env, &s, &owner, &id).await.status() == StatusCode::GONE }).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_and_policy_are_enforced() {
    let env = Env::new().await;
    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    let sender = join(&env, &s, Role::Sender, "sender").await;
    let observer = join(&env, &s, Role::Observer, "observer").await;

    // No token.
    let r = env.http.get(env.url(&format!("/v1/sessions/{}/events", s.id))).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    // Observers cannot post.
    let item = seal_text(&s, &observer, "hi");
    assert_eq!(post(&env, &s, &observer, frame(&item)).await.status(), StatusCode::FORBIDDEN);
    // An item signed by someone else cannot be posted with the sender's token.
    let item = seal_text(&s, &observer, "impersonation");
    assert_eq!(post(&env, &s, &sender, frame(&item)).await.status(), StatusCode::FORBIDDEN);
    // A tampered blob fails the signature check and leaves nothing behind.
    let mut item = seal_text(&s, &sender, "tampered");
    *item.blob.last_mut().unwrap() ^= 1;
    let r = post(&env, &s, &sender, frame(&item)).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let blobs = env.dir.path().join("sessions").join(&s.id).join("blobs");
    assert_eq!(std::fs::read_dir(&blobs).unwrap().count(), 0, "rejected upload left files");
    // Truncated and over-long bodies.
    let item = seal_text(&s, &sender, "short");
    let mut body = frame(&item);
    body.pop();
    assert_eq!(post(&env, &s, &sender, body).await.status(), StatusCode::BAD_REQUEST);
    let mut body = frame(&item);
    body.push(0);
    assert_eq!(post(&env, &s, &sender, body).await.status(), StatusCode::BAD_REQUEST);
    // Non-canonical envelope.
    let pretty = serde_json::to_string_pretty(&item.envelope).unwrap();
    let mut body = (pretty.len() as u32).to_be_bytes().to_vec();
    body.extend_from_slice(pretty.as_bytes());
    body.extend_from_slice(&item.blob);
    assert_eq!(post(&env, &s, &sender, body).await.status(), StatusCode::BAD_REQUEST);
    // Duplicate id.
    assert_eq!(post(&env, &s, &sender, frame(&item)).await.status(), StatusCode::CREATED);
    assert_eq!(post(&env, &s, &sender, frame(&item)).await.status(), StatusCode::CONFLICT);
    // Runners cannot join relay sessions.
    let kp = Keypair::generate();
    let cert = issue_cert(&s.secrets.role_keypair(Role::Runner), &s.id, Role::Runner, kp.public(), now_ms())
        .unwrap();
    let j = sign_join(
        &kp,
        JoinRequest {
            v: 1,
            session_id: s.id.clone(),
            cert,
            display_name: "r".into(),
            kind: ClientKind::Runner,
            runner: Some(airlock_core::cert::RunnerInfo {
                name: "r".into(),
                labels: vec![],
                host: "h".into(),
                sandbox: airlock_core::cert::SandboxKind::Docker,
                network_unblocked: false,
            }),
            created_at_ms: now_ms(),
        },
    )
    .unwrap();
    let r = env
        .http
        .post(env.url(&format!("/v1/sessions/{}/participants", s.id)))
        .body(canon(&j))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread")]
async fn session_storage_and_transfer_limits() {
    let env = Env::with(|c| {
        c.max_session_bytes = 200;
        c.max_session_transfer = 400;
    })
    .await;
    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    let owner = join(&env, &s, Role::Owner, "owner").await;
    let sender = join(&env, &s, Role::Sender, "sender").await;
    let a = seal_text(&s, &sender, &"a".repeat(100));
    assert_eq!(post(&env, &s, &sender, frame(&a)).await.status(), StatusCode::CREATED);
    let b = seal_text(&s, &sender, &"b".repeat(100));
    assert_eq!(post(&env, &s, &sender, frame(&b)).await.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // Download counts against transfer: 136 up + 136 down + 136 down > 400.
    let id = a.envelope.header.id.clone();
    assert_eq!(blob(&env, &s, &owner, &id).await.status(), StatusCode::OK);
    assert_eq!(blob(&env, &s, &owner, &id).await.status(), StatusCode::TOO_MANY_REQUESTS);
}

async fn read_sse_until(resp: reqwest::Response, want: &str) -> String {
    let mut stream = resp.bytes_stream();
    let mut text = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !text.contains(want) {
        let chunk =
            tokio::time::timeout_at(deadline, stream.next()).await.expect("sse timeout").unwrap().unwrap();
        text.push_str(&String::from_utf8_lossy(&chunk));
    }
    text
}

#[tokio::test(flavor = "multi_thread")]
async fn sse_streams_and_resumes() {
    let env = Env::new().await;
    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    let owner = join(&env, &s, Role::Owner, "owner").await;
    let sender = join(&env, &s, Role::Sender, "sender").await;
    let stream_url = env.url(&format!("/v1/sessions/{}/stream", s.id));

    let live = env.http.get(&stream_url).bearer_auth(&owner.token).send().await.unwrap();
    assert_eq!(live.status(), StatusCode::OK);
    let item = seal_text(&s, &sender, "live");
    post(&env, &s, &sender, frame(&item)).await;
    let text = read_sse_until(live, "event: item").await;
    assert!(text.contains("event: participant"), "backlog replayed first");

    // Resume after the item: only later events arrive.
    let evs = events(&env, &s, &owner).await;
    let item_seq = evs.iter().find(|e| e["kind"] == "item").unwrap()["seq"].as_u64().unwrap();
    let resumed = env
        .http
        .get(&stream_url)
        .bearer_auth(&owner.token)
        .header("Last-Event-ID", item_seq.to_string())
        .send()
        .await
        .unwrap();
    let second = seal_text(&s, &sender, "second");
    post(&env, &s, &sender, frame(&second)).await;
    let text = read_sse_until(resumed, &second.envelope.header.id).await;
    assert!(!text.contains(&item.envelope.header.id), "resumed stream replayed an old item");
}

#[tokio::test(flavor = "multi_thread")]
async fn survives_restart() {
    let mut env = Env::new().await;
    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    let owner = join(&env, &s, Role::Owner, "owner").await;
    let sender = join(&env, &s, Role::Sender, "sender").await;
    let item = seal_text(&s, &sender, "persisted");
    let id = item.envelope.header.id.clone();
    post(&env, &s, &sender, frame(&item)).await;

    env.restart(|_| {}).await;
    // Tokens, envelopes and blobs come back from the log.
    assert_eq!(events(&env, &s, &owner).await.iter().filter(|e| e["kind"] == "item").count(), 1);
    let bytes = blob(&env, &s, &owner, &id).await.bytes().await.unwrap().to_vec();
    assert_eq!(bytes, item.blob);
    // Eviction state is rebuilt too.
    ack(&env, &s, &owner, &id).await;
    env.restart(|_| {}).await;
    assert!(eventually(|| async { blob(&env, &s, &owner, &id).await.status() == StatusCode::GONE }).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn ephemeral_mode_wipes_on_start() {
    let mut env = Env::new().await;
    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    env.restart(|c| c.ephemeral = true).await;
    let r = env.http.get(env.url(&format!("/v1/sessions/{}", s.id))).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn expiry_and_owner_close_purge() {
    let env = Env::new().await;
    let short = new_session(Mode::Relay, 400);
    assert_eq!(create(&env, &short).await.status(), StatusCode::CREATED);
    let dir = env.dir.path().join("sessions").join(&short.id);
    assert!(dir.exists());
    assert!(
        eventually(|| async {
            env.http.get(env.url(&format!("/v1/sessions/{}", short.id))).send().await.unwrap().status()
                == StatusCode::NOT_FOUND
        })
        .await
    );
    assert!(eventually(|| async { !dir.exists() }).await);

    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    let owner = join(&env, &s, Role::Owner, "owner").await;
    let sender = join(&env, &s, Role::Sender, "sender").await;
    let stream = env
        .http
        .get(env.url(&format!("/v1/sessions/{}/stream", s.id)))
        .bearer_auth(&sender.token)
        .send()
        .await
        .unwrap();
    let close = |m: &Member| {
        env.http.post(env.url(&format!("/v1/sessions/{}/close", s.id))).bearer_auth(m.token.clone()).send()
    };
    assert_eq!(close(&sender).await.unwrap().status(), StatusCode::FORBIDDEN);
    assert_eq!(close(&owner).await.unwrap().status(), StatusCode::NO_CONTENT);
    let text = read_sse_until(stream, "event: closed").await;
    assert!(text.contains("closed by owner"));
}

#[tokio::test(flavor = "multi_thread")]
async fn creation_limits() {
    let env = Env::with(|c| {
        c.max_sessions_per_ip = 1;
        c.max_ttl_ms = 60_000;
    })
    .await;
    let too_long = new_session(Mode::Relay, 120_000);
    assert_eq!(create(&env, &too_long).await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(create(&env, &new_session(Mode::Relay, 30_000)).await.status(), StatusCode::CREATED);
    assert_eq!(create(&env, &new_session(Mode::Relay, 30_000)).await.status(), StatusCode::TOO_MANY_REQUESTS);
    // A non-canonical manifest is rejected before anything else.
    let s = new_session(Mode::Relay, 30_000);
    let pretty: Value = serde_json::from_str(&s.manifest_json).unwrap();
    let r = env
        .http
        .post(env.url("/v1/sessions"))
        .body(serde_json::to_string_pretty(&pretty).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn data_dir_is_locked() {
    let env = Env::new().await;
    let mut c = test_config(env.dir.path());
    c.listen = "127.0.0.1:0".parse().unwrap();
    let err = start(c).await.err().expect("second server must not start");
    assert!(err.to_string().contains("in use"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn partial_log_line_is_dropped_on_load() {
    let mut env = Env::new().await;
    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    let owner = join(&env, &s, Role::Owner, "owner").await;
    env.running.take().unwrap().stop().await.unwrap();
    let log = env.dir.path().join("sessions").join(&s.id).join("log.jsonl");
    let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
    std::io::Write::write_all(&mut f, br#"{"seq":99,"ts_ms":1,"type":"ev"#).unwrap();
    drop(f);
    let running = start(test_config(env.dir.path())).await.unwrap();
    env.base = format!("http://{}", running.addr);
    env.running = Some(running);
    assert_eq!(events(&env, &s, &owner).await.len(), 1);
    let sender = join(&env, &s, Role::Sender, "after-recovery").await;
    let item = seal_text(&s, &sender, "appends still line up");
    assert_eq!(post(&env, &s, &sender, frame(&item)).await.status(), StatusCode::CREATED);
    env.restart(|_| {}).await;
    assert_eq!(events(&env, &s, &owner).await.len(), 3);
}
