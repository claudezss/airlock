//! The web UI pages and assets are served with the strict CSP.

use reqwest::header::{CONTENT_SECURITY_POLICY, REFERRER_POLICY};
use reqwest::StatusCode;

mod common;
use common::*;

#[tokio::test(flavor = "multi_thread")]
async fn pages_and_assets_carry_the_strict_csp() {
    let env = Env::new().await;
    for path in ["/", "/new", "/s/ax_abcdefghijklmnopqrstuvwxyz", "/assets/app.js", "/assets/style.css"] {
        let r = env.http.get(format!("{}{path}", env.base)).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{path}");
        assert_eq!(r.headers()[REFERRER_POLICY], "no-referrer", "{path}");
        let csp = r.headers()[CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert!(csp.contains("script-src 'self' 'wasm-unsafe-eval';"), "{path}: {csp}");
        assert!(csp.contains("connect-src 'self';"), "{path}: {csp}");
        assert!(!csp.contains("http"), "{path}: {csp}");
    }
}
