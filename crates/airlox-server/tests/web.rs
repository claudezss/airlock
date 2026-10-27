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

#[tokio::test(flavor = "multi_thread")]
async fn assets_are_gzipped_with_etags_and_revalidate() {
    use reqwest::header::{ACCEPT_ENCODING, CONTENT_ENCODING, ETAG, IF_NONE_MATCH, VARY};
    let env = Env::new().await;
    let url = format!("{}/assets/app.js", env.base);
    let plain = env.http.get(&url).send().await.unwrap();
    assert!(plain.headers().get(CONTENT_ENCODING).is_none());
    let plain_tag = plain.headers()[ETAG].to_str().unwrap().to_string();
    let plain_body = plain.bytes().await.unwrap();

    let gz = env.http.get(&url).header(ACCEPT_ENCODING, "br, gzip").send().await.unwrap();
    assert_eq!(gz.headers()[CONTENT_ENCODING], "gzip");
    assert_eq!(gz.headers()[VARY], "Accept-Encoding");
    let gz_tag = gz.headers()[ETAG].to_str().unwrap().to_string();
    assert_ne!(gz_tag, plain_tag);
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&gz.bytes().await.unwrap()[..]), &mut out)
        .unwrap();
    assert_eq!(out, plain_body);

    for refuse in ["gzip;q=0", "gzip; Q=0", "gzip;q=0, *", "identity", "br"] {
        let r = env.http.get(&url).header(ACCEPT_ENCODING, refuse).send().await.unwrap();
        assert!(r.headers().get(CONTENT_ENCODING).is_none(), "{refuse}");
    }
    let star = env.http.get(&url).header(ACCEPT_ENCODING, "br;q=0.5, *").send().await.unwrap();
    assert_eq!(star.headers()[CONTENT_ENCODING], "gzip");

    let again = env.http.get(&url).header(IF_NONE_MATCH, &plain_tag).send().await.unwrap();
    assert_eq!(again.status(), StatusCode::NOT_MODIFIED);
    assert!(again.bytes().await.unwrap().is_empty());

    // The API stays uncompressed so event streams are never buffered.
    let api =
        env.http.get(format!("{}/v1/health", env.base)).header(ACCEPT_ENCODING, "gzip").send().await.unwrap();
    assert!(api.headers().get(CONTENT_ENCODING).is_none());
}
