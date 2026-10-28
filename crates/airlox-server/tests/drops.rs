//! One-time transfer codes: `/v1/drops`.

mod common;

use airlox_core::transfer::{seal, Code};
use common::Env;
use reqwest::StatusCode;
use serde_json::{json, Value};

const INVITE: &str = "https://airlox.app/s/ax_abc#v=1&r=run&k=AAAA&rk=BBBB";

async fn post_drop(env: &Env) -> (reqwest::Response, String) {
    let s = seal(INVITE).unwrap();
    let r = env
        .http
        .post(env.url("/v1/drops"))
        .json(&json!({"claim_hash": s.claim_hash, "box": s.sealed_box}))
        .send()
        .await
        .unwrap();
    (r, s.secret)
}

/// Park a sealed invite; returns `(code, token)`.
async fn park(env: &Env) -> (Code, String) {
    let (r, secret) = post_drop(env).await;
    assert_eq!(r.status(), StatusCode::CREATED);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["ttl_ms"], 600_000);
    let code = Code::parse(&format!("{}-{secret}", v["nameplate"])).unwrap();
    (code, v["token"].as_str().unwrap().to_string())
}

async fn claim(env: &Env, n: u32, claim: &str) -> reqwest::Response {
    claim_as(env, n, json!({"claim": claim})).await
}

async fn claim_as(env: &Env, n: u32, body: Value) -> reqwest::Response {
    env.http.post(env.url(&format!("/v1/drops/{n}/claim"))).json(&body).send().await.unwrap()
}

/// The status and error code of a claim.
async fn claim_err(env: &Env, n: u32, c: &str) -> (StatusCode, String) {
    let r = claim(env, n, c).await;
    let s = r.status();
    let v: Value = r.json().await.unwrap_or(Value::Null);
    (s, v["error"].as_str().unwrap_or("").to_string())
}

async fn state(env: &Env, n: u32, token: &str) -> Value {
    let r = env.http.get(env.url(&format!("/v1/drops/{n}"))).bearer_auth(token).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    r.json().await.unwrap()
}

fn wrong() -> String {
    airlox_core::encoding::b64e(&[9u8; 32])
}

#[tokio::test]
async fn claims_once_and_tells_the_sender() {
    let env = Env::new().await;
    let (code, token) = park(&env).await;
    let n = code.nameplate;
    assert!((1..=100).contains(&n));
    assert_eq!(state(&env, n, &token).await["state"], "waiting");

    let r = claim(&env, n, &code.claim()).await;
    assert_eq!(r.status(), StatusCode::OK);
    let v: Value = r.json().await.unwrap();
    assert_eq!(code.open(v["box"].as_str().unwrap()).unwrap(), INVITE);

    let s = state(&env, n, &token).await;
    assert_eq!(s["state"], "picked_up");
    assert!(s["picked_up_at_ms"].as_u64().is_some());
    assert_eq!(claim_err(&env, n, &code.claim()).await, (StatusCode::GONE, "used".into()));
}

#[tokio::test]
async fn claims_report_the_key_they_will_join_with() {
    let env = Env::with(|c| c.max_drops_per_ip = 100).await;
    let key = airlox_core::keys::Keypair::generate().public().to_b64();

    // With a key: the creator learns it, and the invite comes out as usual.
    let (code, token) = park(&env).await;
    let n = code.nameplate;
    assert_eq!(state(&env, n, &token).await["participant_pub"], Value::Null);
    let r = claim_as(&env, n, json!({"claim": code.claim(), "participant_pub": key})).await;
    assert_eq!(r.status(), StatusCode::OK);
    let v: Value = r.json().await.unwrap();
    assert_eq!(code.open(v["box"].as_str().unwrap()).unwrap(), INVITE);
    let s = state(&env, n, &token).await;
    assert_eq!((s["state"].as_str(), s["participant_pub"].as_str()), (Some("picked_up"), Some(key.as_str())));

    // Without one, or with a null: as before, and nothing is reported.
    for with_null in [false, true] {
        let (code, token) = park(&env).await;
        let mut body = json!({"claim": code.claim()});
        if with_null {
            body["participant_pub"] = Value::Null;
        }
        assert_eq!(claim_as(&env, code.nameplate, body).await.status(), StatusCode::OK);
        let s = state(&env, code.nameplate, &token).await;
        assert_eq!((s["state"].as_str(), &s["participant_pub"]), (Some("picked_up"), &Value::Null));
    }
}

#[tokio::test]
async fn a_malformed_key_is_refused_without_spending_the_code() {
    let env = Env::new().await;
    let (code, token) = park(&env).await;
    let n = code.nameplate;
    let short = airlox_core::encoding::b64e(&[1u8; 16]);
    for bad in [json!("not base64!"), json!(short), json!(""), json!(7)] {
        let r = claim_as(&env, n, json!({"claim": code.claim(), "participant_pub": bad})).await;
        let status = r.status();
        let v: Value = r.json().await.unwrap_or(Value::Null);
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
        if !bad.is_number() {
            assert_eq!(v["error"], "invalid", "{bad}");
        }
    }
    // Still waiting, no wrong claim counted: the right claim with a good key works.
    assert_eq!(state(&env, n, &token).await["state"], "waiting");
    let key = airlox_core::keys::Keypair::generate().public().to_b64();
    let r = claim_as(&env, n, json!({"claim": code.claim(), "participant_pub": key})).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(state(&env, n, &token).await["participant_pub"], key.as_str());
}

#[tokio::test]
async fn wrong_claims_burn_the_drop() {
    let env = Env::new().await;
    let (code, token) = park(&env).await;
    let n = code.nameplate;
    assert_eq!(claim(&env, n, &wrong()).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(claim(&env, n, &wrong()).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(claim_err(&env, n, &wrong()).await, (StatusCode::GONE, "burned".into()));
    // Burned: even the right words get nothing, and it keeps saying why.
    assert_eq!(claim_err(&env, n, &code.claim()).await, (StatusCode::GONE, "burned".into()));
    assert_eq!(state(&env, n, &token).await["state"], "burned");
}

#[tokio::test]
async fn one_address_cannot_try_every_code() {
    let env = Env::new().await;
    let codes = [park(&env).await.0, park(&env).await.0, park(&env).await.0, park(&env).await.0];
    // Ten wrong claims spread over drops and unknown numbers use up the address.
    let mut spent = 0;
    'outer: for c in &codes[..3] {
        for _ in 0..3 {
            claim(&env, c.nameplate, &wrong()).await;
            spent += 1;
            if spent == 9 {
                break 'outer;
            }
        }
    }
    let unknown = (1..1000).find(|n| codes.iter().all(|c| c.nameplate != *n)).unwrap();
    assert_eq!(claim(&env, unknown, &wrong()).await.status(), StatusCode::NOT_FOUND);
    // Now even the right words for an untouched code are refused from here.
    let last = &codes[3];
    assert_eq!(claim(&env, last.nameplate, &last.claim()).await.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn cancel_keeps_the_number_and_needs_the_token() {
    let env = Env::with(|c| c.max_drops_per_ip = 100).await;
    let (a, token) = park(&env).await;
    let n = a.nameplate;
    let del = |t: &str| env.http.delete(env.url(&format!("/v1/drops/{n}"))).bearer_auth(t.to_string()).send();
    assert_eq!(del("not-the-token").await.unwrap().status(), StatusCode::NOT_FOUND);
    let r = env.http.get(env.url(&format!("/v1/drops/{n}"))).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(del(&token).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(claim_err(&env, n, &a.claim()).await, (StatusCode::GONE, "cancelled".into()));
    assert_eq!(state(&env, n, &token).await["state"], "cancelled");
    // The number is not handed out again while it is reserved.
    for _ in 0..30 {
        assert_ne!(park(&env).await.0.nameplate, n);
    }
}

#[tokio::test]
async fn expired_codes_say_so_then_are_forgotten() {
    let env = Env::with(|c| c.drop_ttl_ms = 150).await;
    let (a, token) = park_short(&env).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(claim_err(&env, a.nameplate, &a.claim()).await, (StatusCode::GONE, "expired".into()));
    assert_eq!(state(&env, a.nameplate, &token).await["state"], "expired");
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert_eq!(claim(&env, a.nameplate, &a.claim()).await.status(), StatusCode::NOT_FOUND);
}

async fn park_short(env: &Env) -> (Code, String) {
    let (r, secret) = post_drop(env).await;
    assert_eq!(r.status(), StatusCode::CREATED);
    let v: Value = r.json().await.unwrap();
    (Code::parse(&format!("{}-{secret}", v["nameplate"])).unwrap(), v["token"].as_str().unwrap().into())
}

#[tokio::test]
async fn limits_count_open_codes_only() {
    let env = Env::with(|c| {
        c.max_drops_per_ip = 2;
        c.max_drops = 3;
    })
    .await;
    let (a, token) = park_short(&env).await;
    park_short(&env).await;
    assert_eq!(post_drop(&env).await.0.status(), StatusCode::TOO_MANY_REQUESTS);
    // A finished code frees its place.
    env.http.delete(env.url(&format!("/v1/drops/{}", a.nameplate))).bearer_auth(&token).send().await.unwrap();
    park_short(&env).await;
}

#[tokio::test]
async fn rejects_malformed_drops() {
    let env = Env::new().await;
    for body in [
        json!({"claim_hash": "xyz", "box": "AAAA"}),
        json!({"claim_hash": "a".repeat(64), "box": "AAAA"}),
        json!({"claim_hash": "a".repeat(64), "box": "A".repeat(6000)}),
        json!({"box": "AAAA"}),
    ] {
        let r = env.http.post(env.url("/v1/drops")).json(&body).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{body}");
    }
    for n in ["0", "x", "-1"] {
        let r = env.http.post(env.url(&format!("/v1/drops/{n}/claim"))).json(&json!({"claim": "AA"})).send();
        assert_eq!(r.await.unwrap().status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn receive_page_is_served() {
    let env = Env::new().await;
    let r = env.http.get(env.url("/receive")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}
