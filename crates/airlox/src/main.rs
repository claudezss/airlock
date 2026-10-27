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
#[cfg(windows)]
mod service;
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
    /// Wait for items meant for you (addressed to you, replies, the owner's
    /// messages) and wake an agent: print and exit, or run a command.
    Listen(cli::ListenArgs),
    /// Runners: run jobs for a session, or list, approve and reject them.
    #[command(subcommand)]
    Runner(RunnerCmd),
    /// Print the invite link a one-time transfer code carries.
    Receive(cli::ReceiveArgs),
    /// Run an MCP server on stdio, for agents in chat apps and IDEs.
    Mcp(mcp::McpArgs),
}

#[derive(Subcommand)]
enum RunnerCmd {
    /// Join a session with a runner invite and run its jobs until it ends.
    Join(Box<runner::JoinArgs>),
    /// Run a runner as a Windows service: install or uninstall it.
    #[cfg(windows)]
    #[command(subcommand)]
    Service(service::ServiceCmd),
    /// List the session's runners.
    List(cli::Conn),
    /// Wait until a runner is online (and approved, with --approved); exits
    /// 1 if it reports that it could not start, 75 if the wait runs out.
    Wait(cli::WaitArgs),
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
    // user left blank. Not the relay: blanking a self-hosted one must not
    // quietly fall back to the public relay.
    for (k, v) in std::env::vars_os() {
        if v.is_empty() && k.to_str().is_some_and(|k| k.starts_with("AIRLOX_")) {
            if k == "AIRLOX_RELAY" {
                eprintln!(
                    "airlox: AIRLOX_RELAY is empty; set it to your relay, or unset it for https://airlox.app"
                );
                return std::process::ExitCode::from(2);
            }
            std::env::remove_var(k);
        }
    }
    let cli = Cli::parse();
    let filter =
        || tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "airlox=info".into());
    // Under the service manager there is no console: log to a file, and let
    // the service code build the runtime on the thread the manager gives it.
    #[cfg(windows)]
    if let Cmd::Runner(RunnerCmd::Join(a)) = &cli.cmd {
        if a.windows_service.is_some() {
            let log = match service::log_file(a) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("airlox: could not open the service log: {e:#}");
                    return std::process::ExitCode::FAILURE;
                }
            };
            let log = std::sync::Mutex::new(log);
            tracing_subscriber::fmt().with_env_filter(filter()).with_ansi(false).with_writer(log).init();
            let Cmd::Runner(RunnerCmd::Join(a)) = cli.cmd else { unreachable!() };
            return match service::run(*a) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => {
                    tracing::error!("{e:#}");
                    eprintln!("airlox: {e:#}");
                    std::process::ExitCode::FAILURE
                }
            };
        }
    }
    tracing_subscriber::fmt().with_env_filter(filter()).with_writer(std::io::stderr).init();
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
            Cmd::Listen(a) => cli::listen(a).await,
            Cmd::Receive(a) => cli::receive(a).await.map(|()| 0),
            Cmd::Runner(RunnerCmd::Join(args)) => runner::run(*args).await.map(|()| 0),
            #[cfg(windows)]
            Cmd::Runner(RunnerCmd::Service(service::ServiceCmd::Install(a))) => {
                service::install(*a).await.map(|()| 0)
            }
            #[cfg(windows)]
            Cmd::Runner(RunnerCmd::Service(service::ServiceCmd::Uninstall(a))) => {
                service::uninstall(a).map(|()| 0)
            }
            Cmd::Mcp(mcp::McpArgs { cmd: Some(mcp::McpCmd::Config(c)), .. }) => {
                mcp::print_config(&c).map(|()| 0)
            }
            Cmd::Mcp(mcp::McpArgs { cmd: Some(mcp::McpCmd::Prompt), .. }) => {
                println!("{}", mcp::WORKER_PROMPT);
                Ok(0)
            }
            Cmd::Mcp(a) => mcp::serve(a).await.map(|()| 0),
            Cmd::Runner(RunnerCmd::List(c)) => cli::runner_list(c).await.map(|()| 0),
            Cmd::Runner(RunnerCmd::Wait(a)) => cli::runner_wait(a).await,
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
