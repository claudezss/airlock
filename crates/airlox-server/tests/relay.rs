//! End-to-end tests against a real server on a random port.

use std::time::Duration;

use airlox_core::cert::{issue_cert, sign_join, ClientKind, JoinRequest};
use airlox_core::item::SealedItem;
use airlox_core::keys::Keypair;
use airlox_core::payload::Payload;
use airlox_core::session::{JobKind, Mode, Role};
use airlox_server::start;
use reqwest::StatusCode;
use serde_json::{json, Value};

mod common;
use common::*;

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
    let r = post(&env, &s, &sender, frame(&item)).await;
    assert_eq!(error_code(r).await, (StatusCode::CONFLICT, "duplicate".into()));
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
            description: None,
            kind: ClientKind::Runner,
            runner: Some(airlox_core::cert::RunnerInfo {
                name: "r".into(),
                labels: vec![],
                host: "h".into(),
                sandbox: airlox_core::cert::SandboxKind::Docker,
                network_unblocked: false,
                version: None,
                python: None,
                kinds: vec![JobKind::Python],
                shell: None,
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
    // A relay with a lifetime limit takes no session that never expires.
    let forever = new_session_ttl(Mode::Relay, None);
    assert_eq!(error_code(create(&env, &forever).await).await, (StatusCode::BAD_REQUEST, "ttl".into()));
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

#[tokio::test(flavor = "multi_thread")]
async fn a_signed_join_cannot_be_replayed() {
    let env = Env::new().await;
    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    let (_, owner_join) = join_body(&s, Role::Owner, "owner");
    assert_eq!(post_join(&env, &s, owner_join.clone()).await.status(), StatusCode::CREATED);
    let observer = join(&env, &s, Role::Observer, "observer").await;
    // The owner's signed join is public to every participant.
    let evs = events(&env, &s, &observer).await;
    let published = evs.iter().find(|e| e["data"]["role"] == "owner").unwrap()["data"]["signed_join"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(published, owner_join);
    let r = post_join(&env, &s, published).await;
    assert_eq!(error_code(r).await, (StatusCode::CONFLICT, "conflict".into()));
    // No extra log line or event was written.
    assert_eq!(events(&env, &s, &observer).await.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn leaving_revokes_the_token_and_releases_deliveries() {
    let env = Env::new().await;
    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    let owner = join(&env, &s, Role::Owner, "owner").await;
    let stale = join(&env, &s, Role::Observer, "old browser").await;
    let sender = join(&env, &s, Role::Sender, "sender").await;
    let item = seal_text(&s, &sender, "for owner and the stale observer");
    let id = item.envelope.header.id.clone();
    assert_eq!(post(&env, &s, &sender, frame(&item)).await.status(), StatusCode::CREATED);
    ack(&env, &s, &owner, &id).await;
    // The stale observer never acks, so the blob is held...
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(blob(&env, &s, &owner, &id).await.status(), StatusCode::OK);
    // ...until it leaves.
    let r = env
        .http
        .post(env.url(&format!("/v1/sessions/{}/leave", s.id)))
        .bearer_auth(&stale.token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert!(eventually(|| async { blob(&env, &s, &owner, &id).await.status() == StatusCode::GONE }).await);
    let r = env
        .http
        .get(env.url(&format!("/v1/sessions/{}/events", s.id)))
        .bearer_auth(&stale.token)
        .send()
        .await;
    assert_eq!(r.unwrap().status(), StatusCode::UNAUTHORIZED);
    assert!(events(&env, &s, &owner).await.iter().any(|e| e["kind"] == "left"));
}

#[tokio::test(flavor = "multi_thread")]
async fn closed_sessions_cannot_be_recreated() {
    let mut env = Env::new().await;
    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    let owner = join(&env, &s, Role::Owner, "owner").await;
    let r = env
        .http
        .post(env.url(&format!("/v1/sessions/{}/close", s.id)))
        .bearer_auth(&owner.token)
        .send()
        .await;
    assert_eq!(r.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(error_code(create(&env, &s).await).await, (StatusCode::GONE, "closed".into()));
    env.restart(|_| {}).await;
    assert_eq!(create(&env, &s).await.status(), StatusCode::GONE);
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_uploads_still_count_against_transfer() {
    let env = Env::with(|c| c.max_session_transfer = 500).await;
    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    let sender = join(&env, &s, Role::Sender, "sender").await;
    let blob_len = seal_text(&s, &sender, &"x".repeat(150)).blob.len();
    assert!(blob_len * 2 <= 500 && blob_len * 3 > 500, "{blob_len}");
    for _ in 0..2 {
        let mut item = seal_text(&s, &sender, &"x".repeat(150));
        let last = item.blob.len() - 1;
        item.blob[last] ^= 1;
        assert_eq!(post(&env, &s, &sender, frame(&item)).await.status(), StatusCode::BAD_REQUEST);
    }
    // Two failed uploads were charged; a third, valid one would pass the cap.
    let ok = seal_text(&s, &sender, &"y".repeat(150));
    assert_eq!(post(&env, &s, &sender, frame(&ok)).await.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test(flavor = "multi_thread")]
async fn session_history_and_item_size_limits() {
    let env = Env::with(|c| c.max_log_bytes = 6000).await;
    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    let sender = join(&env, &s, Role::Sender, "sender").await;
    let mut accepted = 0;
    let last = loop {
        let r = post(&env, &s, &sender, frame(&seal_text(&s, &sender, "hi"))).await;
        if r.status() != StatusCode::CREATED {
            break r;
        }
        accepted += 1;
        assert!(accepted < 50, "log cap never applied");
    };
    assert!(accepted > 0);
    assert_eq!(error_code(last).await, (StatusCode::PAYLOAD_TOO_LARGE, "session_full".into()));
    let (_, body) = join_body(&s, Role::Observer, "late");
    assert_eq!(post_join(&env, &s, body).await.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // An item over the manifest's max_item_bytes is 413, not 403.
    let s2 = new_session(Mode::Relay, 3_600_000);
    create(&env, &s2).await;
    let sender2 = join(&env, &s2, Role::Sender, "sender").await;
    // The relay decides from the signed header alone, so send just the envelope.
    let big = seal_text(&s2, &sender2, &"z".repeat(1024 * 1024 + 1));
    let mut head_only = frame(&big);
    head_only.truncate(head_only.len() - big.blob.len());
    assert_eq!(error_code(post(&env, &s2, &sender2, head_only).await).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    // Oversized JSON bodies get the JSON error shape.
    let r = env.http.post(env.url("/v1/sessions")).body("x".repeat(300 * 1024)).send().await.unwrap();
    assert_eq!(error_code(r).await, (StatusCode::PAYLOAD_TOO_LARGE, "too_large".into()));
}

#[tokio::test(flavor = "multi_thread")]
async fn streams_per_participant_are_capped() {
    let env = Env::new().await;
    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    let m = join(&env, &s, Role::Observer, "observer").await;
    let open = || {
        env.http.get(env.url(&format!("/v1/sessions/{}/stream", s.id))).bearer_auth(m.token.clone()).send()
    };
    let mut held = Vec::new();
    for _ in 0..4 {
        let r = open().await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        held.push(r);
    }
    assert_eq!(open().await.unwrap().status(), StatusCode::TOO_MANY_REQUESTS);
    held.pop();
    assert!(eventually(|| async { open().await.unwrap().status() == StatusCode::OK }).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn per_address_limit_uses_the_proxy_hop() {
    let env = Env::with(|c| {
        c.trust_proxy = true;
        c.max_sessions_per_ip = 1;
    })
    .await;
    let send = |s: &Sess, xff: &str| {
        env.http
            .post(env.url("/v1/sessions"))
            .header("x-forwarded-for", xff)
            .body(s.manifest_json.clone())
            .send()
    };
    // The client controls the left entries; the proxy appends the real address.
    let a = new_session(Mode::Relay, 60_000);
    assert_eq!(send(&a, "1.1.1.1, 203.0.113.7").await.unwrap().status(), StatusCode::CREATED);
    let b = new_session(Mode::Relay, 60_000);
    assert_eq!(send(&b, "2.2.2.2, 203.0.113.7").await.unwrap().status(), StatusCode::TOO_MANY_REQUESTS);
    // IPv6 addresses in one /64 share a bucket.
    let c = new_session(Mode::Relay, 60_000);
    assert_eq!(send(&c, "2001:db8:1:2::1").await.unwrap().status(), StatusCode::CREATED);
    let d = new_session(Mode::Relay, 60_000);
    assert_eq!(send(&d, "2001:db8:1:2:ffff::9").await.unwrap().status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test(flavor = "multi_thread")]
async fn evicted_blobs_are_reseeded_for_late_joiners() {
    let mut env = Env::new().await;
    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    let owner = join(&env, &s, Role::Owner, "owner").await;
    let sender = join(&env, &s, Role::Sender, "sender").await;
    let item = seal_text(&s, &sender, "for whoever comes later");
    let id = item.envelope.header.id.clone();
    post(&env, &s, &sender, frame(&item)).await;
    ack(&env, &s, &owner, &id).await;
    assert!(eventually(|| async { blob(&env, &s, &owner, &id).await.status() == StatusCode::GONE }).await);

    let late = join(&env, &s, Role::Observer, "late").await;
    let gone = blob(&env, &s, &late, &id).await;
    assert_eq!(gone.status(), StatusCode::GONE);
    // A 410 is cacheable by default; this one must not be, since it can change.
    assert_eq!(gone.headers()["cache-control"], "no-store");
    // Nobody asked yet, so a holder cannot push the blob back.
    let r = reseed(&env, &s, &sender, &id, item.blob.clone()).await;
    assert_eq!(error_code(r).await, (StatusCode::CONFLICT, "not_wanted".into()));
    // Only a participant that never received the item may ask.
    assert_eq!(want(&env, &s, &owner, &id).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(want(&env, &s, &late, &id).await.status(), StatusCode::ACCEPTED);
    assert_eq!(want(&env, &s, &late, &id).await.status(), StatusCode::ACCEPTED);
    let wants: Vec<Value> =
        events(&env, &s, &sender).await.into_iter().filter(|e| e["kind"] == "want").collect();
    assert_eq!(wants.len(), 1, "asking again while open adds no event");
    assert_eq!(wants[0]["data"]["item"], id.as_str());

    // The want survives a restart.
    env.restart(|_| {}).await;
    // Bytes that do not match the author's signed hash are refused.
    let mut forged = item.blob.clone();
    forged[0] ^= 1;
    assert_eq!(reseed(&env, &s, &sender, &id, forged).await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        reseed(&env, &s, &sender, &id, item.blob[1..].to_vec()).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(blob(&env, &s, &late, &id).await.status(), StatusCode::GONE);
    // The asker cannot answer its own want.
    let r = reseed(&env, &s, &late, &id, item.blob.clone()).await;
    assert_eq!(error_code(r).await, (StatusCode::CONFLICT, "not_wanted".into()));

    let r = reseed(&env, &s, &sender, &id, item.blob.clone()).await;
    assert_eq!(r.status(), StatusCode::NO_CONTENT, "{}", r.text().await.unwrap());
    let evs = events(&env, &s, &late).await;
    assert!(evs.iter().any(|e| e["kind"] == "reseeded" && e["data"]["item"] == id.as_str()));
    assert_eq!(blob(&env, &s, &late, &id).await.bytes().await.unwrap().to_vec(), item.blob);
    // A restart replays the re-seed: the blob and its recipients come back.
    env.restart(|_| {}).await;
    assert_eq!(blob(&env, &s, &late, &id).await.status(), StatusCode::OK);
    // The first upload closed the want.
    let r = reseed(&env, &s, &sender, &id, item.blob.clone()).await;
    assert_eq!(error_code(r).await, (StatusCode::CONFLICT, "present".into()));
    let r = want(&env, &s, &late, &id).await;
    assert_eq!(error_code(r).await, (StatusCode::CONFLICT, "present".into()));

    // Once the asker acks, the re-seeded blob goes again.
    ack(&env, &s, &late, &id).await;
    assert!(eventually(|| async { blob(&env, &s, &late, &id).await.status() == StatusCode::GONE }).await);
    assert_eq!(want(&env, &s, &late, &id).await.status(), StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread")]
async fn wants_are_rate_limited() {
    let env = Env::with(|c| c.blob_hold_ms = 200).await;
    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    let _owner = join(&env, &s, Role::Owner, "owner").await;
    let sender = join(&env, &s, Role::Sender, "sender").await;
    let mut ids = Vec::new();
    for n in 0..17 {
        let item = seal_text(&s, &sender, &format!("note {n}"));
        ids.push(item.envelope.header.id.clone());
        post(&env, &s, &sender, frame(&item)).await;
    }
    let late = join(&env, &s, Role::Observer, "late").await;
    let last = ids.last().unwrap().clone();
    assert!(eventually(|| async { blob(&env, &s, &late, &last).await.status() == StatusCode::GONE }).await);
    for id in &ids[..16] {
        assert_eq!(want(&env, &s, &late, id).await.status(), StatusCode::ACCEPTED);
    }
    assert_eq!(want(&env, &s, &late, &last).await.status(), StatusCode::TOO_MANY_REQUESTS);
    // Leaving drops a participant's wants, so nobody can answer them.
    let r = env
        .http
        .post(env.url(&format!("/v1/sessions/{}/leave", s.id)))
        .bearer_auth(&late.token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let r = reseed(&env, &s, &sender, &ids[0], vec![0; 4]).await;
    assert_eq!(error_code(r).await, (StatusCode::CONFLICT, "not_wanted".into()));
}

#[tokio::test(flavor = "multi_thread")]
async fn revoking_a_role_cuts_off_its_participants_and_invite() {
    let mut env = Env::new().await;
    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    let owner = join(&env, &s, Role::Owner, "owner").await;
    let sender = join(&env, &s, Role::Sender, "sender").await;
    let viewer = join(&env, &s, Role::Observer, "viewer").await;
    let stream = env
        .http
        .get(env.url(&format!("/v1/sessions/{}/stream", s.id)))
        .bearer_auth(&sender.token)
        .send()
        .await
        .unwrap();

    // Only the owner revokes, and never the owner role.
    assert_eq!(revoke(&env, &s, &sender, "observer").await.status(), StatusCode::FORBIDDEN);
    assert_eq!(revoke(&env, &s, &owner, "owner").await.status(), StatusCode::NOT_FOUND);
    assert_eq!(revoke(&env, &s, &owner, "sender").await.status(), StatusCode::NO_CONTENT);
    assert_eq!(revoke(&env, &s, &owner, "sender").await.status(), StatusCode::NO_CONTENT);

    // The sender's open stream ends with the revocation; its token is dead.
    let text = read_sse_until(stream, "event: revoked").await;
    assert!(text.contains(&sender.kp.public().to_b64()));
    let r = env
        .http
        .get(env.url(&format!("/v1/sessions/{}/events", s.id)))
        .bearer_auth(&sender.token)
        .send()
        .await;
    assert_eq!(r.unwrap().status(), StatusCode::UNAUTHORIZED);
    // The sender invite admits no one, now or after a restart.
    let (_, body) = join_body(&s, Role::Sender, "again");
    assert_eq!(error_code(post_join(&env, &s, body).await).await, (StatusCode::FORBIDDEN, "revoked".into()));
    env.restart(|_| {}).await;
    let (_, body) = join_body(&s, Role::Sender, "again");
    assert_eq!(error_code(post_join(&env, &s, body).await).await, (StatusCode::FORBIDDEN, "revoked".into()));

    // Other roles carry on, and see one revocation.
    let evs = events(&env, &s, &viewer).await;
    let revoked: Vec<&Value> = evs.iter().filter(|e| e["kind"] == "revoked").collect();
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0]["data"]["role"], "sender");
    assert_eq!(revoked[0]["data"]["participants"][0], sender.kp.public().to_b64().as_str());
    join(&env, &s, Role::Observer, "another viewer").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_export_is_verifiable_and_holds_no_secrets() {
    let env = Env::new().await;
    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    let owner = join(&env, &s, Role::Owner, "owner").await;
    let sender = join(&env, &s, Role::Sender, "sender").await;
    let viewer = join(&env, &s, Role::Observer, "viewer").await;
    let item = seal_text(&s, &sender, "audited");
    let id = item.envelope.header.id.clone();
    post(&env, &s, &sender, frame(&item)).await;
    ack(&env, &s, &owner, &id).await;
    revoke(&env, &s, &owner, "sender").await;

    assert_eq!(audit(&env, &s, &sender).await.status(), StatusCode::UNAUTHORIZED);
    join(&env, &s, Role::Observer, "late").await;
    let r = audit(&env, &s, &viewer).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["content-type"], "application/x-ndjson");
    let text = r.text().await.unwrap();
    // No bearer-token hashes, no address hash.
    assert!(!text.contains("token") && !text.contains("ip_hash"), "{text}");
    let lines: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let actions: Vec<&str> = lines.iter().map(|l| l["action"].as_str().unwrap()).collect();
    assert_eq!(actions, ["create", "join", "join", "join", "item", "ack", "revoke", "join"]);
    assert!(lines.windows(2).all(|w| w[0]["seq"].as_u64() < w[1]["seq"].as_u64()));
    // The item line carries what the author signed: the envelope and the blob hash.
    let it = &lines[4];
    assert_eq!(
        (it["actor"].as_str(), it["item"].as_str()),
        (Some(sender.kp.public().to_b64().as_str()), Some(id.as_str()))
    );
    let env_json: airlox_core::item::ItemEnvelope =
        serde_json::from_str(it["envelope"].as_str().unwrap()).unwrap();
    let digest: [u8; 32] =
        airlox_core::encoding::b64d(it["blob_sha256"].as_str().unwrap()).unwrap().try_into().unwrap();
    env_json.verify_blob_digest(it["blob_len"].as_u64().unwrap(), &digest).unwrap();
    assert_eq!(lines[6]["participants"][0], sender.kp.public().to_b64().as_str());
    // Owners may export too; senders and runners may not.
    assert_eq!(audit(&env, &s, &owner).await.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upload_in_flight_when_its_author_is_revoked_is_refused() {
    let env = Env::new().await;
    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    let owner = join(&env, &s, Role::Owner, "owner").await;
    let sender = join(&env, &s, Role::Sender, "sender").await;
    let item = seal_text(&s, &sender, "sent after the revoke");
    let body = frame(&item);
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, std::io::Error>>(1);
    let stream = futures_util::stream::unfold(rx, |mut rx| async { rx.recv().await.map(|c| (c, rx)) });
    let upload = tokio::spawn(
        env.http
            .post(env.url(&format!("/v1/sessions/{}/items", s.id)))
            .bearer_auth(&sender.token)
            .body(reqwest::Body::wrap_stream(stream))
            .send(),
    );
    // Half the frame, so the relay has checked the token and is reading the blob.
    let half = body.len() / 2;
    tx.send(Ok(body[..half].to_vec())).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(revoke(&env, &s, &owner, "sender").await.status(), StatusCode::NO_CONTENT);
    tx.send(Ok(body[half..].to_vec())).await.unwrap();
    drop(tx);
    let r = upload.await.unwrap().unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let evs = events(&env, &s, &owner).await;
    assert!(!evs.iter().any(|e| e["kind"] == "item"), "the item must not land");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_reseed_does_not_hold_off_other_holders() {
    let env = Env::new().await;
    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    let owner = join(&env, &s, Role::Owner, "owner").await;
    let sender = join(&env, &s, Role::Sender, "sender").await;
    let item = seal_text(&s, &sender, &"x".repeat(4096));
    let id = item.envelope.header.id.clone();
    post(&env, &s, &sender, frame(&item)).await;
    ack(&env, &s, &owner, &id).await;
    assert!(eventually(|| async { blob(&env, &s, &owner, &id).await.status() == StatusCode::GONE }).await);
    let late = join(&env, &s, Role::Observer, "late").await;
    assert_eq!(want(&env, &s, &late, &id).await.status(), StatusCode::ACCEPTED);

    // The sender starts an upload and stalls halfway.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, std::io::Error>>(1);
    let stream = futures_util::stream::unfold(rx, |mut rx| async { rx.recv().await.map(|c| (c, rx)) });
    let stalled = tokio::spawn(
        env.http
            .put(env.url(&format!("/v1/sessions/{}/items/{id}/blob", s.id)))
            .bearer_auth(&sender.token)
            .body(reqwest::Body::wrap_stream(stream))
            .send(),
    );
    let half = item.blob.len() / 2;
    tx.send(Ok(item.blob[..half].to_vec())).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    // While the want stays open, and the owner's upload wins.
    assert_eq!(want(&env, &s, &late, &id).await.status(), StatusCode::ACCEPTED);
    let r = reseed(&env, &s, &owner, &id, item.blob.clone()).await;
    assert_eq!(r.status(), StatusCode::NO_CONTENT, "{}", r.text().await.unwrap());
    tx.send(Ok(item.blob[half..].to_vec())).await.unwrap();
    drop(tx);
    let r = stalled.await.unwrap().unwrap();
    assert_eq!(error_code(r).await, (StatusCode::CONFLICT, "present".into()));
    assert_eq!(blob(&env, &s, &late, &id).await.bytes().await.unwrap().to_vec(), item.blob);
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_that_never_expire_have_their_own_idle_limit() {
    let mut env = Env::with(|c| {
        c.idle_ttl_ms = 300;
        c.idle_ttl_unexpiring_ms = 1_500;
    })
    .await;
    let brief = new_session(Mode::Relay, 3_600_000);
    let forever = new_session_ttl(Mode::Relay, None);
    assert_eq!(create(&env, &brief).await.status(), StatusCode::CREATED);
    let r = create(&env, &forever).await;
    assert_eq!(r.status(), StatusCode::CREATED);
    assert_eq!(r.json::<Value>().await.unwrap()["expires_at_ms"], Value::Null);
    async fn info(env: &Env, id: &str) -> StatusCode {
        env.http.get(env.url(&format!("/v1/sessions/{id}"))).send().await.unwrap().status()
    }
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(info(&env, &brief.id).await, StatusCode::NOT_FOUND);
    assert_eq!(info(&env, &forever.id).await, StatusCode::OK);
    // It survives a restart, and goes once idle for its own, longer limit.
    env.restart(|c| {
        c.idle_ttl_ms = 300;
        c.idle_ttl_unexpiring_ms = 1_500;
    })
    .await;
    assert_eq!(info(&env, &forever.id).await, StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(info(&env, &forever.id).await, StatusCode::NOT_FOUND);
    // A closed or purged session that never expires cannot be re-created.
    assert_eq!(create(&env, &forever).await.status(), StatusCode::GONE);
}

#[tokio::test(flavor = "multi_thread")]
async fn uploads_from_one_address_share_a_storage_cap_across_sessions() {
    let mut env = Env::with(|c| c.max_bytes_per_ip = 6_000).await;
    let a = new_session(Mode::Relay, 3_600_000);
    let b = new_session_ttl(Mode::Relay, None);
    create(&env, &a).await;
    create(&env, &b).await;
    let a_owner = join(&env, &a, Role::Owner, "owner").await;
    let a_sender = join(&env, &a, Role::Sender, "sender").await;
    let b_owner = join(&env, &b, Role::Owner, "owner").await;
    let b_sender = join(&env, &b, Role::Sender, "sender").await;
    let first = seal_text(&a, &a_sender, &"a".repeat(4_000));
    let first_id = first.envelope.header.id.clone();
    assert_eq!(post(&env, &a, &a_sender, frame(&first)).await.status(), StatusCode::CREATED);
    // The same address, another session: over the cap while the first is held.
    let second = seal_text(&b, &b_sender, &"b".repeat(4_000));
    let r = post(&env, &b, &b_sender, frame(&second)).await;
    assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE, "{}", r.text().await.unwrap());
    // The count survives a restart.
    env.restart(|c| c.max_bytes_per_ip = 6_000).await;
    let r = post(&env, &b, &b_sender, frame(&second)).await;
    assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // Once the first is delivered and evicted, there is room again.
    ack(&env, &a, &a_owner, &first_id).await;
    assert!(
        eventually(|| async { blob(&env, &a, &a_owner, &first_id).await.status() == StatusCode::GONE }).await
    );
    assert_eq!(post(&env, &b, &b_sender, frame(&second)).await.status(), StatusCode::CREATED);
    // Closing a session gives back what it held.
    let c = new_session(Mode::Relay, 3_600_000);
    create(&env, &c).await;
    let c_sender = join(&env, &c, Role::Sender, "sender").await;
    let third = seal_text(&c, &c_sender, &"c".repeat(4_000));
    assert_eq!(post(&env, &c, &c_sender, frame(&third)).await.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let r = env
        .http
        .post(env.url(&format!("/v1/sessions/{}/close", b.id)))
        .bearer_auth(&b_owner.token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert!(
        eventually(|| async {
            post(&env, &c, &c_sender, frame(&third)).await.status() == StatusCode::CREATED
        })
        .await
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_reseeds_are_capped_and_losers_are_not_charged() {
    let env = Env::with(|c| c.max_session_transfer = 20_000).await;
    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    let owner = join(&env, &s, Role::Owner, "owner").await;
    let sender = join(&env, &s, Role::Sender, "sender").await;
    let obs = join(&env, &s, Role::Observer, "obs").await;
    let obs2 = join(&env, &s, Role::Observer, "obs2").await;
    let item = seal_text(&s, &sender, &"x".repeat(4096));
    let id = item.envelope.header.id.clone();
    post(&env, &s, &sender, frame(&item)).await;
    for m in [&owner, &obs, &obs2] {
        ack(&env, &s, m, &id).await;
    }
    // Polling the blob would charge transfer: watch for the event instead.
    assert!(
        eventually(|| async { events(&env, &s, &owner).await.iter().any(|e| e["kind"] == "evicted") }).await
    );
    let late = join(&env, &s, Role::Observer, "late").await;
    assert_eq!(want(&env, &s, &late, &id).await.status(), StatusCode::ACCEPTED);

    // Three holders upload at once; a fourth is turned away.
    let half = item.blob.len() / 2;
    let mut ups = vec![];
    for m in [&sender, &owner, &obs] {
        let (tx, h) = stalled_put(&env, &s, m, &id);
        tx.send(Ok(item.blob[..half].to_vec())).await.unwrap();
        ups.push((tx, h));
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let r = reseed(&env, &s, &obs2, &id, item.blob.clone()).await;
    assert_eq!(error_code(r).await, (StatusCode::CONFLICT, "uploading".into()));
    let mut codes = vec![];
    for (tx, h) in ups {
        tx.send(Ok(item.blob[half..].to_vec())).await.unwrap();
        drop(tx);
        codes.push(h.await.unwrap().unwrap().status());
    }
    codes.sort();
    assert_eq!(codes, [StatusCode::NO_CONTENT, StatusCode::CONFLICT, StatusCode::CONFLICT]);
    // Only the winner counted against the transfer cap: the wanter can
    // still download (one upload, one download, plus the first round trip).
    assert_eq!(blob(&env, &s, &late, &id).await.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn asking_again_writes_nothing_and_needs_a_live_participant() {
    let env = Env::new().await;
    let s = new_session(Mode::Relay, 3_600_000);
    create(&env, &s).await;
    let owner = join(&env, &s, Role::Owner, "owner").await;
    let sender = join(&env, &s, Role::Sender, "sender").await;
    let item = seal_text(&s, &sender, "x");
    let id = item.envelope.header.id.clone();
    post(&env, &s, &sender, frame(&item)).await;
    ack(&env, &s, &owner, &id).await;
    assert!(eventually(|| async { blob(&env, &s, &owner, &id).await.status() == StatusCode::GONE }).await);
    let late = join(&env, &s, Role::Observer, "late").await;
    for _ in 0..5 {
        assert_eq!(want(&env, &s, &late, &id).await.status(), StatusCode::ACCEPTED);
    }
    let audit_wants = |text: String| text.lines().filter(|l| l.contains(r#""action":"want""#)).count();
    assert_eq!(audit_wants(audit(&env, &s, &owner).await.text().await.unwrap()), 1);
    let evs = events(&env, &s, &sender).await;
    assert_eq!(evs.iter().filter(|e| e["kind"] == "want").count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn delivery_reports_who_stored_the_authors_items() {
    let env = Env::new().await;
    let s = new_session(Mode::Relay, 3_600_000);
    assert_eq!(create(&env, &s).await.status(), StatusCode::CREATED);
    let owner = join(&env, &s, Role::Owner, "owner").await;
    let sender = join(&env, &s, Role::Sender, "planner-agent").await;
    let observer = join(&env, &s, Role::Observer, "lead").await;
    let item = seal_text(&s, &sender, "status?");
    let id = item.envelope.header.id.clone();
    assert_eq!(post(&env, &s, &sender, frame(&item)).await.status(), StatusCode::CREATED);
    let delivery = |m: &Member| {
        let req = env.http.get(env.url(&format!("/v1/sessions/{}/delivery", s.id))).bearer_auth(&m.token);
        async move {
            let r = req.send().await.unwrap();
            assert_eq!(r.status(), StatusCode::OK);
            r.json::<Value>().await.unwrap()["items"].clone()
        }
    };
    let pk = |m: &Member| m.kp.public().to_b64();

    let d = delivery(&sender).await;
    assert_eq!(d[&id]["delivered"], json!([]));
    let mut waiting = vec![pk(&owner), pk(&observer)];
    waiting.sort();
    assert_eq!(d[&id]["waiting"], json!(waiting));

    ack(&env, &s, &owner, &id).await;
    let d = delivery(&sender).await;
    assert_eq!(d[&id]["delivered"], json!([pk(&owner)]));
    assert_eq!(d[&id]["waiting"], json!([pk(&observer)]));
    // Only the author learns this.
    assert_eq!(delivery(&owner).await, json!({}));
}
