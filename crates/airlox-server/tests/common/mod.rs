//! Helpers shared by the relay and execute-mode tests.
#![allow(dead_code)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use airlox_core::cert::{issue_cert, sign_join, ClientKind, JoinRequest};
use airlox_core::encoding::canonical_json;
use airlox_core::item::{new_item_id, seal, ItemKind, NewItem, SealedItem};
use airlox_core::keys::Keypair;
use airlox_core::payload::Payload;
use airlox_core::session::{ContentType, Mode, Role, SessionParams, SessionSecrets};
use airlox_server::{start, Config, Running};
use futures_util::StreamExt;
use reqwest::StatusCode;
use serde_json::Value;

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

pub fn canon<T: serde::Serialize>(v: &T) -> String {
    String::from_utf8(canonical_json(v).unwrap()).unwrap()
}

pub struct Env {
    pub dir: tempfile::TempDir,
    pub running: Option<Running>,
    pub base: String,
    pub http: reqwest::Client,
}

pub fn test_config(dir: &std::path::Path) -> Config {
    let mut c = Config::with_data(dir);
    c.listen = "127.0.0.1:0".parse().unwrap();
    c.sweep_interval_ms = 50;
    c.blob_grace_ms = 200;
    c
}

impl Env {
    pub async fn new() -> Env {
        Self::with(|_| {}).await
    }

    pub async fn with(f: impl FnOnce(&mut Config)) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let mut c = test_config(dir.path());
        f(&mut c);
        let running = start(c).await.unwrap();
        let base = format!("http://{}", running.addr);
        Env { dir, running: Some(running), base, http: reqwest::Client::new() }
    }

    pub async fn restart(&mut self, f: impl FnOnce(&mut Config)) {
        self.running.take().unwrap().stop().await.unwrap();
        let mut c = test_config(self.dir.path());
        f(&mut c);
        let running = start(c).await.unwrap();
        self.base = format!("http://{}", running.addr);
        self.running = Some(running);
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }
}

pub struct Sess {
    pub secrets: SessionSecrets,
    pub id: String,
    pub manifest_json: String,
}

pub fn new_session(mode: Mode, ttl_ms: u64) -> Sess {
    new_session_ttl(mode, Some(ttl_ms))
}

/// `None`: a session that never expires.
pub fn new_session_ttl(mode: Mode, ttl_ms: Option<u64>) -> Sess {
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

pub async fn create(env: &Env, s: &Sess) -> reqwest::Response {
    env.http.post(env.url("/v1/sessions")).body(s.manifest_json.clone()).send().await.unwrap()
}

pub struct Member {
    pub kp: Keypair,
    pub token: String,
}

pub fn join_body(s: &Sess, role: Role, name: &str) -> (Keypair, String) {
    let kp = Keypair::generate();
    let cert = issue_cert(&s.secrets.role_keypair(role), &s.id, role, kp.public(), now_ms()).unwrap();
    let j = sign_join(
        &kp,
        JoinRequest {
            v: 1,
            session_id: s.id.clone(),
            cert,
            display_name: name.into(),
            description: None,
            kind: ClientKind::Sdk,
            runner: None,
            created_at_ms: now_ms(),
        },
    )
    .unwrap();
    (kp, canon(&j))
}

pub async fn post_join(env: &Env, s: &Sess, body: String) -> reqwest::Response {
    env.http.post(env.url(&format!("/v1/sessions/{}/participants", s.id))).body(body).send().await.unwrap()
}

pub async fn join(env: &Env, s: &Sess, role: Role, name: &str) -> Member {
    let (kp, body) = join_body(s, role, name);
    let r = post_join(env, s, body).await;
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().await.unwrap());
    let v: Value = r.json().await.unwrap();
    Member { kp, token: v["token"].as_str().unwrap().to_string() }
}

pub fn seal_text(s: &Sess, author: &Member, text: &str) -> SealedItem {
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

pub fn frame(item: &SealedItem) -> Vec<u8> {
    let env = canon(&item.envelope);
    let mut b = (env.len() as u32).to_be_bytes().to_vec();
    b.extend_from_slice(env.as_bytes());
    b.extend_from_slice(&item.blob);
    b
}

pub async fn post(env: &Env, s: &Sess, m: &Member, body: Vec<u8>) -> reqwest::Response {
    env.http
        .post(env.url(&format!("/v1/sessions/{}/items", s.id)))
        .bearer_auth(&m.token)
        .body(body)
        .send()
        .await
        .unwrap()
}

pub async fn events(env: &Env, s: &Sess, m: &Member) -> Vec<Value> {
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

pub async fn blob(env: &Env, s: &Sess, m: &Member, item: &str) -> reqwest::Response {
    env.http
        .get(env.url(&format!("/v1/sessions/{}/items/{item}/blob", s.id)))
        .bearer_auth(&m.token)
        .send()
        .await
        .unwrap()
}

pub async fn ack(env: &Env, s: &Sess, m: &Member, item: &str) {
    let r = env
        .http
        .post(env.url(&format!("/v1/sessions/{}/items/{item}/ack", s.id)))
        .bearer_auth(&m.token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
}

pub async fn eventually<F: std::future::Future<Output = bool>>(mut f: impl FnMut() -> F) -> bool {
    for _ in 0..60 {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

pub async fn read_sse_until(resp: reqwest::Response, want: &str) -> String {
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

pub async fn error_code(r: reqwest::Response) -> (StatusCode, String) {
    let status = r.status();
    let v: Value = r.json().await.expect("error bodies are JSON");
    (status, v["error"].as_str().unwrap_or_default().to_string())
}

pub async fn want(env: &Env, s: &Sess, m: &Member, item: &str) -> reqwest::Response {
    env.http
        .post(env.url(&format!("/v1/sessions/{}/items/{item}/want", s.id)))
        .bearer_auth(&m.token)
        .send()
        .await
        .unwrap()
}

pub async fn reseed(env: &Env, s: &Sess, m: &Member, item: &str, blob: Vec<u8>) -> reqwest::Response {
    env.http
        .put(env.url(&format!("/v1/sessions/{}/items/{item}/blob", s.id)))
        .bearer_auth(&m.token)
        .body(blob)
        .send()
        .await
        .unwrap()
}

pub async fn revoke(env: &Env, s: &Sess, m: &Member, role: &str) -> reqwest::Response {
    env.http
        .post(env.url(&format!("/v1/sessions/{}/roles/{role}/revoke", s.id)))
        .bearer_auth(&m.token)
        .send()
        .await
        .unwrap()
}

pub async fn audit(env: &Env, s: &Sess, m: &Member) -> reqwest::Response {
    env.http
        .get(env.url(&format!("/v1/sessions/{}/audit.jsonl", s.id)))
        .bearer_auth(&m.token)
        .send()
        .await
        .unwrap()
}

/// A re-seed `PUT` whose body is sent in pieces through the returned
/// channel; dropping the sender ends the body.
#[allow(clippy::type_complexity)]
pub fn stalled_put(
    env: &Env,
    s: &Sess,
    m: &Member,
    item: &str,
) -> (
    tokio::sync::mpsc::Sender<Result<Vec<u8>, std::io::Error>>,
    tokio::task::JoinHandle<reqwest::Result<reqwest::Response>>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, std::io::Error>>(1);
    let stream = futures_util::stream::unfold(rx, |mut rx| async { rx.recv().await.map(|c| (c, rx)) });
    let req = env
        .http
        .put(env.url(&format!("/v1/sessions/{}/items/{item}/blob", s.id)))
        .bearer_auth(&m.token)
        .body(reqwest::Body::wrap_stream(stream))
        .send();
    (tx, tokio::spawn(req))
}
