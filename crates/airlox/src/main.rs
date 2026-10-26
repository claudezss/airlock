//! The `airlox` binary. M2 ships the runner: `airlox runner join`.

mod client;
mod job;
mod runner;
mod sandbox;
mod sse;
mod view;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "airlox", version, about = "Airlox: secure sessions for agents")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run jobs for an execute-mode session.
    #[command(subcommand)]
    Runner(RunnerCmd),
}

#[derive(Subcommand)]
enum RunnerCmd {
    /// Join a session with a runner invite and run its jobs until it ends.
    Join(runner::JoinArgs),
}

fn main() -> std::process::ExitCode {
    // Sandbox stages re-execute this binary; they must run before any thread starts.
    #[cfg(target_os = "linux")]
    {
        let args: Vec<String> = std::env::args().collect();
        if let Some(code) = sandbox::linux::dispatch(&args) {
            return std::process::ExitCode::from(code.clamp(0, 255) as u8);
        }
    }
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "airlox=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("airlox: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let r = rt.block_on(async {
        match cli.cmd {
            Cmd::Runner(RunnerCmd::Join(args)) => runner::run(args).await,
        }
    });
    match r {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("airlox: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
