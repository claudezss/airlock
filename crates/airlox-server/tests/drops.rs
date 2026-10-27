//! One-time transfer codes: `/v1/drops`.

mod common;

use airlox_core::transfer::{seal, Code};
use common::Env;
use reqwest::StatusCode;
use serde_json::{json, Value};

const INVITE: &str = "https://airlox.app/s/ax_abc#v=1&r=run&k=AAAA&rk=BBBB";

/// Park a sealed invite; returns `(code, token)`.
async fn park(env: &Env) -> (Code, String) {
    let s = seal(INVITE).unwrap();
    let r = env
        .http
        .post(env.url("/v1/drops"))
        .json(&json!({"claim_hash": s.claim_hash, "box": s.sealed_box}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let v: Value = r.json().await.unwrap();
    let code = Code::parse(&format!("{}-{}", v["nameplate"], s.secret)).unwrap();
    (code, v["token"].as_str().unwrap().to_string())
}

async fn claim(env: &Env, n: u32, claim: &str) -> reqwest::Response {
    env.http
        .post(env.url(&format!("/v1/drops/{n}/claim")))
        .json(&json!({"claim": claim}))
        .send()
        .await
        .unwrap()
}

async fn state(env: &Env, n: u32, token: &str) -> Value {
    let r = env.http.get(env.url(&format!("/v1/drops/{n}"))).bearer_auth(token).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    r.json().await.unwrap()
}

#[tokio::test]
async fn claims_once_and_tells_the_sender() {
    let env = Env::new().await;
    let (code, token) = park(&env).await;
    assert_eq!(code.nameplate, 1);
    assert_eq!(state(&env, 1, &token).await["state"], "waiting");

    let r = claim(&env, 1, &code.claim()).await;
    assert_eq!(r.status(), StatusCode::OK);
    let v: Value = r.json().await.unwrap();
    assert_eq!(code.open(v["box"].as_str().unwrap()).unwrap(), INVITE);

    let s = state(&env, 1, &token).await;
    assert_eq!(s["state"], "picked_up");
    assert!(s["picked_up_at_ms"].as_u64().is_some());
    assert_eq!(claim(&env, 1, &code.claim()).await.status(), StatusCode::GONE);
}

#[tokio::test]
async fn wrong_claims_burn_the_drop() {
    let env = Env::new().await;
    let (code, token) = park(&env).await;
    let wrong = airlox_core::encoding::b64e(&[9u8; 32]);
    assert_eq!(claim(&env, 1, &wrong).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(claim(&env, 1, &wrong).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(claim(&env, 1, &wrong).await.status(), StatusCode::GONE);
    // Burned: even the right words get nothing now.
    assert_eq!(claim(&env, 1, &code.claim()).await.status(), StatusCode::GONE);
    assert_eq!(state(&env, 1, &token).await["state"], "burned");
}

#[tokio::test]
async fn nameplates_are_reused_after_cancel_and_need_the_token() {
    let env = Env::new().await;
    let (a, token_a) = park(&env).await;
    let (b, _) = park(&env).await;
    assert_eq!((a.nameplate, b.nameplate), (1, 2));

    let del = |t: &str| env.http.delete(env.url("/v1/drops/1")).bearer_auth(t.to_string()).send();
    assert_eq!(del("not-the-token").await.unwrap().status(), StatusCode::NOT_FOUND);
    let r = env.http.get(env.url("/v1/drops/1")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(del(&token_a).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(claim(&env, 1, &a.claim()).await.status(), StatusCode::NOT_FOUND);
    assert_eq!(park(&env).await.0.nameplate, 1);
}

#[tokio::test]
async fn expire_and_limits() {
    let env = Env::with(|c| {
        c.drop_ttl_ms = 100;
        c.max_drops_per_ip = 2;
    })
    .await;
    let (a, _) = park(&env).await;
    park(&env).await;
    let s = seal(INVITE).unwrap();
    let r = env
        .http
        .post(env.url("/v1/drops"))
        .json(&json!({"claim_hash": s.claim_hash, "box": s.sealed_box}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert_eq!(claim(&env, a.nameplate, &a.claim()).await.status(), StatusCode::NOT_FOUND);
    park(&env).await;
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
