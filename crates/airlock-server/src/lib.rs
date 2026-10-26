//! Airlock relay server.
//!
//! A transit buffer for end-to-end encrypted sessions: it stores signed
//! envelopes and ciphertext on local disk, evicts each blob once its
//! recipients have it, and never sees plaintext. No database.

pub mod api;
pub mod config;
pub mod error;
pub mod store;
mod util;
mod web;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub use config::Config;
use store::Store;

/// Request body limit for JSON endpoints. Item uploads stream and are
/// bounded by the manifest and relay limits instead.
const JSON_BODY_LIMIT: usize = 256 * 1024;

pub fn router(state: api::AppState) -> Router {
    let json_routes = Router::new()
        .route("/v1/sessions", post(api::create_session))
        .route("/v1/sessions/{id}/participants", post(api::join).get(api::participants))
        .layer(DefaultBodyLimit::max(JSON_BODY_LIMIT));
    Router::new()
        .route("/v1/health", get(api::health))
        .route("/v1/sessions/{id}", get(api::get_session))
        .route("/v1/sessions/{id}/close", post(api::close_session))
        .route("/v1/sessions/{id}/events", get(api::events))
        .route("/v1/sessions/{id}/stream", get(api::stream))
        .route("/v1/sessions/{id}/items", post(api::post_item))
        .route("/v1/sessions/{id}/items/{item}/blob", get(api::get_blob))
        .route("/v1/sessions/{id}/items/{item}/ack", post(api::ack))
        .route("/", get(web::index))
        .route("/s/{id}", get(web::session_page))
        .route("/assets/{*path}", get(web::asset))
        .merge(json_routes)
        .with_state(state)
}

/// A running server.
pub struct Running {
    pub addr: SocketAddr,
    pub store: Arc<Store>,
    shutdown: watch::Sender<bool>,
    server: JoinHandle<std::io::Result<()>>,
    sweeper: JoinHandle<()>,
}

impl Running {
    /// Stop accepting, end open streams, and release the data directory.
    pub async fn stop(self) -> std::io::Result<()> {
        let _ = self.shutdown.send(true);
        let r = self.server.await.map_err(std::io::Error::other)?;
        self.sweeper.abort();
        let _ = self.sweeper.await;
        drop(self.store);
        r
    }

    /// A handle that triggers the same shutdown as [`Running::stop`].
    pub fn shutdown_sender(&self) -> watch::Sender<bool> {
        self.shutdown.clone()
    }

    /// Wait until the server exits (after a shutdown signal).
    pub async fn wait(self) -> std::io::Result<()> {
        let r = self.server.await.map_err(std::io::Error::other)?;
        self.sweeper.abort();
        r
    }
}

/// Open the store, start the sweeper, and serve on `cfg.listen`.
pub async fn start(cfg: Config) -> std::io::Result<Running> {
    let cfg = Arc::new(cfg);
    let store = Store::open(cfg.clone())?;
    let (tx, rx) = watch::channel(false);

    let weak = Arc::downgrade(&store);
    let interval = Duration::from_millis(cfg.sweep_interval_ms.max(10));
    let sweeper = tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let Some(store) = weak.upgrade() else { break };
            store.sweep(util::now_ms());
        }
    });

    let listener = tokio::net::TcpListener::bind(cfg.listen).await?;
    let addr = listener.local_addr()?;
    let app = router(api::AppState { store: store.clone(), shutdown: rx.clone() });
    let mut stop = rx;
    let server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(async move {
                let _ = stop.wait_for(|v| *v).await;
            })
            .await
    });
    tracing::info!(%addr, "airlock relay listening");
    Ok(Running { addr, store, shutdown: tx, server, sweeper })
}
