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
    let shutdown = running_shutdown_handle(&running);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
        shutdown();
    });
    running.wait().await
}

fn running_shutdown_handle(r: &airlox_server::Running) -> impl FnOnce() + Send + 'static {
    let tx = r.shutdown_sender();
    move || {
        let _ = tx.send(true);
    }
}
