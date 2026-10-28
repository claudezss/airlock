//! The job shim: a dependency-free Python script every sandbox backend runs.
//!
//! ```text
//! python3 shim.py --work /work --entry summarize.py --timeout 30 --result /meta/result.json
//! ```
//!
//! It scrubs the environment, runs the entry file with `python -E -s` (or,
//! with `--shell sh --script PATH`, the script with `sh -e -c`), starting in
//! `--cwd` below the work dir if given, enforces the wall clock (killing the
//! whole process group), records peak RSS and writes `result.json`. Stdout and
//! stderr go to files next to the result.

use serde::{Deserialize, Serialize};

pub const SHIM_PY: &str = include_str!("../shim/shim.py");
pub const SHIM_VERSION: u32 = 1;

/// The `result.json` the shim writes.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ShimResult {
    pub shim_version: u32,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    /// The shim received SIGTERM/SIGINT/SIGHUP (runner cancel) and killed the job.
    pub cancelled: bool,
    pub wall_ms: u64,
    pub peak_rss_kb: u64,
    pub error: Option<String>,
}
