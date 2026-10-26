//! End-to-end tests against a real server on a random port.

use std::time::Duration;

use airlox_core::cert::{issue_cert, sign_join, ClientKind, JoinRequest};
use airlox_core::item::SealedItem;
use airlox_core::keys::Keypair;
use airlox_core::payload::Payload;
use airlox_core::session::{Mode, Role};
use airlox_server::start;
use reqwest::StatusCode;
use serde_json::Value;

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
            description: None,
            kind: ClientKind::Runner,
            runner: Some(airlox_core::cert::RunnerInfo {
                name: "r".into(),
                labels: vec![],
                host: "h".into(),
                sandbox: airlox_core::cert::SandboxKind::Docker,
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
    assert_eq!(error_code(last).await, (StatusCode::PAYLOAD_TOO_LARGE, "too_large".into()));
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
