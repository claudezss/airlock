//! Airlox relay server.
//!
//! A transit buffer for end-to-end encrypted sessions: it stores signed
//! envelopes and ciphertext on local disk, evicts each blob once its
//! recipients have it, and never sees plaintext. No database.

pub mod api;
pub mod config;
pub mod error;
pub mod exec;
pub mod store;
mod util;
mod web;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::{get, post};
use axum::Router;
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub use config::Config;
use store::Store;

pub fn router(state: api::AppState) -> Router {
    Router::new()
        .route("/v1/health", get(api::health))
        .route("/v1/sessions", post(api::create_session))
        .route("/v1/sessions/{id}/participants", post(api::join).get(api::participants))
        .route("/v1/sessions/{id}/leave", post(api::leave))
        .route("/v1/sessions/{id}", get(api::get_session))
        .route("/v1/sessions/{id}/close", post(api::close_session))
        .route("/v1/sessions/{id}/events", get(api::events))
        .route("/v1/sessions/{id}/stream", get(api::stream))
        .route("/v1/sessions/{id}/items", post(api::post_item))
        .route("/v1/sessions/{id}/items/{item}/blob", get(api::get_blob))
        .route("/v1/sessions/{id}/items/{item}/ack", post(api::ack))
        .route("/v1/sessions/{id}/jobs", post(exec::post_job))
        .route("/v1/sessions/{id}/jobs/{job}", get(exec::get_job))
        .route("/v1/sessions/{id}/jobs/{job}/claim", post(exec::claim_job))
        .route("/v1/sessions/{id}/jobs/{job}/cancel", post(exec::cancel_job))
        .route("/v1/sessions/{id}/runners", get(exec::runners))
        .route("/v1/sessions/{id}/runners/me/stream", get(exec::runner_stream))
        .route("/v1/sessions/{id}/runners/me/heartbeat", post(exec::heartbeat))
        .route("/v1/sessions/{id}/runners/{participant}/approve", post(exec::approve_runner))
        .route("/v1/sessions/{id}/runners/{participant}/reject", post(exec::reject_runner))
        .route("/", get(web::index))
        .route("/new", get(web::new_page))
        .route("/s/{id}", get(web::session_page))
        .route("/assets/{*path}", get(web::asset))
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
    /// Stop accepting, end open streams, and release the data directory:
    /// when this returns, another server can open it.
    pub async fn stop(self) -> std::io::Result<()> {
        let _ = self.shutdown.send(true);
        self.wait().await
    }

    /// A handle that triggers the same shutdown as [`Running::stop`].
    pub fn shutdown_sender(&self) -> watch::Sender<bool> {
        self.shutdown.clone()
    }

    /// Wait until the server exits (after a shutdown signal) and has
    /// released the data directory.
    pub async fn wait(self) -> std::io::Result<()> {
        let r = self.server.await.map_err(std::io::Error::other);
        // The server may also end on its own (an I/O error): stop the
        // sweeper either way.
        let _ = self.shutdown.send(true);
        let _ = self.sweeper.await;
        release(self.store).await;
        r?
    }
}

/// Drop the last handle on the store, which releases the data directory's
/// lock. Request handlers that outlived the server's shutdown may still hold
/// a handle for a moment; wait for them rather than leave the lock behind.
async fn release(store: Arc<Store>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while Arc::strong_count(&store) > 1 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    if Arc::strong_count(&store) > 1 {
        tracing::warn!(
            "the data directory is still in use after shutdown; its lock is released when that ends"
        );
    }
    drop(store);
}

/// Open the store, start the sweeper, and serve on `cfg.listen`.
pub async fn start(cfg: Config) -> std::io::Result<Running> {
    let cfg = Arc::new(cfg);
    let store = Store::open(cfg.clone())?;
    let (tx, rx) = watch::channel(false);

    let weak = Arc::downgrade(&store);
    let interval = Duration::from_millis(cfg.sweep_interval_ms.max(10));
    let mut stopping = rx.clone();
    let sweeper = tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = stopping.wait_for(|v| *v) => break,
            }
            let Some(store) = weak.upgrade() else { break };
            // Awaited, not detached: the sweep holds the store until it ends.
            let _ = tokio::task::spawn_blocking(move || store.sweep(util::now_ms())).await;
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
    tracing::info!(%addr, "airlox relay listening");
    Ok(Running { addr, store, shutdown: tx, server, sweeper })
}
