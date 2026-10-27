use clap::Parser;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=warn".into()),
        )
        .init();
    let cfg = airlox_server::Config::parse();
    let running = airlox_server::start(cfg).await?;
    tokio::spawn(airlox_server::warm_web_assets());
    let shutdown = running_shutdown_handle(&running);
    tokio::spawn(async move {
        stop_signal().await;
        tracing::info!("shutting down");
        shutdown();
    });
    running.wait().await
}

/// Ctrl-C, or SIGTERM: what `docker stop` and systemd send. As PID 1 in a
/// container nothing else would end the process before the SIGKILL.
async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn running_shutdown_handle(r: &airlox_server::Running) -> impl FnOnce() + Send + 'static {
    let tx = r.shutdown_sender();
    move || {
        let _ = tx.send(true);
    }
}
