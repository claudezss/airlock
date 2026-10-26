//! The `airlox` binary: the command-line client (`session`, `send`, `run`,
//! `result`, `items`, `watch`), the runner (`runner join`) and the MCP server
//! (`mcp`).

mod cli;
mod client;
mod files;
mod job;
mod mcp;
mod runner;
mod sandbox;
mod session;
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
    /// Create, inspect and close sessions.
    #[command(subcommand)]
    Session(cli::SessionCmd),
    /// Send a message or files.
    #[command(subcommand)]
    Send(cli::SendCmd),
    /// Run a Python file on a runner and print its result.
    Run(cli::RunArgs),
    /// Get a job's result.
    Result(cli::ResultArgs),
    /// Stop a running job.
    Cancel(cli::CancelArgs),
    /// Print the session's items so far.
    Items(cli::ItemsArgs),
    /// Print items as they arrive.
    Watch(cli::WatchArgs),
    /// Runners: run jobs for a session, or list, approve and reject them.
    #[command(subcommand)]
    Runner(RunnerCmd),
    /// Run an MCP server on stdio, for agents in chat apps and IDEs.
    Mcp(mcp::McpArgs),
}

#[derive(Subcommand)]
enum RunnerCmd {
    /// Join a session with a runner invite and run its jobs until it ends.
    Join(runner::JoinArgs),
    /// List the session's runners.
    List(cli::Conn),
    /// Let a runner take jobs (owner invite only).
    Approve {
        #[command(flatten)]
        conn: cli::Conn,
        /// Runner name or key.
        runner: String,
    },
    /// Turn a runner away (owner invite only).
    Reject {
        #[command(flatten)]
        conn: cli::Conn,
        /// Runner name or key.
        runner: String,
        #[arg(long)]
        reason: Option<String>,
    },
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
    // An empty AIRLOX_* variable counts as unset, so a launcher that fills in
    // every setting (an MCPB bundle's optional fields) leaves out the ones the
    // user left blank.
    for (k, v) in std::env::vars_os() {
        if v.is_empty() && k.to_str().is_some_and(|k| k.starts_with("AIRLOX_")) {
            std::env::remove_var(k);
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
            Cmd::Session(c) => cli::session(c).await.map(|()| 0),
            Cmd::Send(c) => cli::send(c).await.map(|()| 0),
            Cmd::Run(a) => cli::run(a).await,
            Cmd::Result(a) => cli::result(a).await,
            Cmd::Cancel(a) => cli::cancel(a).await.map(|()| 0),
            Cmd::Items(a) => cli::items(a).await.map(|()| 0),
            Cmd::Watch(a) => cli::watch(a).await.map(|()| 0),
            Cmd::Runner(RunnerCmd::Join(args)) => runner::run(args).await.map(|()| 0),
            Cmd::Mcp(a) => mcp::serve(a).await.map(|()| 0),
            Cmd::Runner(RunnerCmd::List(c)) => cli::runner_list(c).await.map(|()| 0),
            Cmd::Runner(RunnerCmd::Approve { conn, runner }) => {
                cli::runner_approve(conn, runner).await.map(|()| 0)
            }
            Cmd::Runner(RunnerCmd::Reject { conn, runner, reason }) => {
                cli::runner_reject(conn, runner, reason).await.map(|()| 0)
            }
        }
    });
    match r {
        Ok(code) => std::process::ExitCode::from(code.clamp(0, 255) as u8),
        Err(e) => {
            eprintln!("airlox: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
