//! Plaintext payloads inside an item.
//!
//! ```text
//! payload = u32_be(len(meta)) || meta || body
//! meta    = canonical JSON, tagged by "type"
//! body    = raw file bytes for "file"; empty for every other type
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::cert::SandboxKind;
use crate::encoding::canonical_json;
use crate::item::{ItemKind, ItemRef};
use crate::keys::PublicKey;
pub use crate::session::JobKind;
use crate::{Error, Result};

pub const MAX_META_BYTES: usize = 4 * 1024 * 1024;
/// Ceiling for each of `stdout` and `stderr` in a result.
pub const MAX_STDIO_BYTES: usize = 1024 * 1024;
pub const MAX_OUT_FILES: usize = 64;
pub const MAX_REASON_CHARS: usize = 4096;
/// Most participants one message may be addressed to.
pub const MAX_RECIPIENTS: usize = 64;
/// Most packages a result's `env` lists.
pub const MAX_ENV_PACKAGES: usize = 256;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Target {
    /// One specific runner, pinned by its participant key. `name` is for display.
    Runner { participant_pub: PublicKey, name: String },
    /// Any idle runner carrying every listed label.
    Labels { labels: Vec<String> },
    /// Any idle approved runner.
    Any,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JobSpec {
    /// `python` or `shell`. Absent means `python`, so a Python job is
    /// byte-for-byte what clients before shell jobs send.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<JobKind>,
    /// Entry file name, e.g. "summarize.py"; for a shell job, a name for
    /// display (e.g. "job.sh").
    pub filename: String,
    /// The Python source, or the shell script (at most 64 KiB).
    pub code: String,
    /// Must equal the manifest's job_limits.runtime.
    pub runtime: String,
    pub timeout_s: u32,
    /// Optional, at most the manifest ceiling. Absent = the ceiling.
    pub memory_mb: Option<u32>,
    /// `file` items to place in the work dir, pinned by blob hash. ZIPs are unpacked.
    pub files: Vec<ItemRef>,
    /// Package names; each must be in the manifest allowlist.
    pub requirements: Vec<String>,
    pub target: Target,
    /// A file in the work dir (a relative `/`-separated path) whose tail
    /// the runner sends in its progress items while the job runs, such as
    /// a simulator's log. Absent from the canonical form when not given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress_file: Option<String>,
    /// Where in the work dir the job starts: a relative `/`-separated path
    /// (the component rules of `progress_file`). Absent for the work dir.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// The input in `files` that is a working tree (`tree.zip` with
    /// `.airlox/tree.json`): a runner with a workspace syncs it rather than
    /// unpacking it. Absent when the job sends no tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree: Option<ItemRef>,
    /// Empty the sender's workspace before the job runs. Absent when false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub fresh: bool,
}

impl JobSpec {
    /// The job's kind, `python` when unsaid.
    pub fn kind(&self) -> JobKind {
        self.kind.unwrap_or(JobKind::Python)
    }
}

/// Longest log tail a progress item carries.
pub const MAX_PROGRESS_TAIL_BYTES: usize = 64 * 1024;
/// Longest output chunk a progress item carries.
pub const MAX_CHUNK_BYTES: usize = 64 * 1024;
/// Longest shell script a job may carry.
pub const MAX_SHELL_CODE_BYTES: usize = 64 * 1024;

/// Which of a job's output streams a progress chunk is from.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Stream {
    Stdout,
    Stderr,
}

/// A running job's progress, posted by its runner (`kind: progress`, with a
/// reference to the job).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JobProgress {
    /// The job, pinned by blob hash.
    pub job: ItemRef,
    /// Time since the job started, measured by the runner.
    pub elapsed_ms: u64,
    /// The end of the job's `progress_file`, as UTF-8 (lossy), if it exists.
    pub tail: Option<String>,
    /// More of the file came before `tail`.
    pub tail_truncated: bool,
    /// An output chunk: which stream `data` is from. Absent for a
    /// heartbeat-style progress item (elapsed time and tail only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<Stream>,
    /// The byte position of `data` in its stream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// At most 64 KiB of the stream, cut at a UTF-8 boundary. Display only:
    /// the signed result's `stdout`/`stderr` are the authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// The runner stopped streaming here (its cap on streamed bytes); the
    /// result still carries the output. Absent when false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub truncated: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OutFile {
    pub name: String,
    pub size: u64,
    pub item: ItemRef,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JobResult {
    /// The job this result answers, pinned by blob hash.
    pub job: ItemRef,
    /// None when the job never ran to completion (refused, cancelled, killed).
    pub exit_code: Option<i32>,
    pub status: JobStatus,
    /// Human-readable reason for refused / failed / timed_out.
    pub reason: Option<String>,
    pub wall_ms: u64,
    pub peak_mem_mb: u32,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub out_files: Vec<OutFile>,
    /// Hex SHA-256 of the job code and of the concatenated input blobs.
    pub code_sha256: String,
    pub input_sha256: String,
    /// Where the job ran. Absent from the canonical form when the runner
    /// does not report it (older runners, or a job that never ran).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<JobEnv>,
}

/// The environment a job ran in, as its runner measured it once for the
/// runtime. Signed with the result, so a sender can check where a job ran
/// without trusting the job's own output. Holds no paths.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JobEnv {
    /// The interpreter's version, e.g. "3.12.4".
    pub python: String,
    /// Installed version of each allowlisted package, by normalized name.
    pub packages: BTreeMap<String, String>,
    /// The runner's airlox version.
    pub airlox: String,
    /// How the job was isolated.
    pub sandbox: SandboxKind,
    /// Where the interpreter came from: `uv-runtime` (built by the runner
    /// from the allowlist), `--python` (the operator's), or `docker:<image>`.
    pub interpreter: String,
    /// The kinds of job this runner accepts. Absent from runners before
    /// shell jobs (which run `python` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<JobKind>>,
    /// The shell `shell` jobs run under: `sh` or `pwsh`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    /// The working tree the job ran against, copied from its `tree.json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree: Option<TreeInfo>,
}

/// Which working tree a job ran against (from the job's `.airlox/tree.json`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TreeInfo {
    /// The commit checked out, hex; absent outside a git repository.
    pub head: Option<String>,
    /// The tree differs from `head` (uncommitted or untracked changes).
    pub dirty: bool,
    /// Files in the tree.
    pub count: u64,
    /// Hex SHA-256 of the tree's zip.
    pub sha256: String,
    /// For a job that ran in a workspace: the tree's files that were no
    /// longer as listed once it finished (edited or removed by the job or by
    /// its other inputs), at most [`MAX_TREE_CHANGED`]. Absent when the
    /// runner keeps no workspace or more changed than that; a sender then
    /// sends its next tree whole.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<Vec<String>>,
}

/// The most paths a result's `env.tree.changed` lists.
pub const MAX_TREE_CHANGED: usize = 256;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Completed,
    Refused,
    TimedOut,
    Cancelled,
    Failed,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    RunnerApprove { participant_pub: PublicKey },
    RunnerReject { participant_pub: PublicKey, reason: Option<String> },
    JobCancel { job: ItemRef },
    SessionClose,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Meta {
    Text {
        text: String,
        /// The participants this message is addressed to: the ones whose
        /// listeners it wakes. Absent (never empty) for a message to everyone.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to: Option<Vec<PublicKey>>,
    },
    File {
        name: String,
        mime: String,
    },
    Job(JobSpec),
    Result(JobResult),
    Event(Event),
    Progress(JobProgress),
}

impl Meta {
    pub fn kind(&self) -> ItemKind {
        match self {
            Meta::Text { .. } => ItemKind::Text,
            Meta::File { .. } => ItemKind::File,
            Meta::Job(_) => ItemKind::Job,
            Meta::Result(_) => ItemKind::Result,
            Meta::Event(_) => ItemKind::Event,
            Meta::Progress(_) => ItemKind::Progress,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload {
    pub meta: Meta,
    pub body: Vec<u8>,
}

impl Payload {
    pub fn text(text: impl Into<String>) -> Self {
        Payload { meta: Meta::Text { text: text.into(), to: None }, body: vec![] }
    }

    pub fn file(name: impl Into<String>, mime: impl Into<String>, body: Vec<u8>) -> Self {
        Payload { meta: Meta::File { name: name.into(), mime: mime.into() }, body }
    }

    pub fn job(spec: JobSpec) -> Self {
        Payload { meta: Meta::Job(spec), body: vec![] }
    }

    pub fn result(r: JobResult) -> Self {
        Payload { meta: Meta::Result(r), body: vec![] }
    }

    pub fn event(e: Event) -> Self {
        Payload { meta: Meta::Event(e), body: vec![] }
    }

    pub fn progress(p: JobProgress) -> Self {
        Payload { meta: Meta::Progress(p), body: vec![] }
    }

    pub fn kind(&self) -> ItemKind {
        self.meta.kind()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        if !matches!(self.meta, Meta::File { .. }) && !self.body.is_empty() {
            return Err(Error::invalid("payload", "only file payloads carry a body"));
        }
        let meta = canonical_json(&self.meta)?;
        if meta.len() > MAX_META_BYTES {
            return Err(Error::invalid("payload", "meta exceeds 4 MiB"));
        }
        let mut out = Vec::with_capacity(4 + meta.len() + self.body.len());
        out.extend_from_slice(&(meta.len() as u32).to_be_bytes());
        out.extend_from_slice(&meta);
        out.extend_from_slice(&self.body);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return Err(Error::invalid("payload", "truncated"));
        }
        let n = u32::from_be_bytes(bytes[..4].try_into().expect("4 bytes")) as usize;
        if n > MAX_META_BYTES || bytes.len() < 4 + n {
            return Err(Error::invalid("payload", "bad meta length"));
        }
        let meta_bytes = &bytes[4..4 + n];
        let meta: Meta = serde_json::from_slice(meta_bytes)?;
        if canonical_json(&meta)? != meta_bytes {
            return Err(Error::invalid("payload", "meta is not canonical json"));
        }
        let body = bytes[4 + n..].to_vec();
        let p = Payload { meta, body };
        if !matches!(p.meta, Meta::File { .. }) && !p.body.is_empty() {
            return Err(Error::invalid("payload", "only file payloads carry a body"));
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_kinds() {
        let cases = vec![
            Payload::text("hi"),
            Payload::file("a.md", "text/markdown", b"# a".to_vec()),
            Payload::job(JobSpec {
                kind: None,
                cwd: None,
                tree: None,
                fresh: false,
                filename: "x.py".into(),
                code: "print(1)".into(),
                runtime: "python3.12".into(),
                timeout_s: 10,
                memory_mb: None,
                files: vec![],
                requirements: vec![],
                target: Target::Labels { labels: vec!["gpu".into()] },
                progress_file: None,
            }),
            Payload::event(Event::JobCancel {
                job: ItemRef {
                    id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
                    blob_sha256: crate::encoding::b64e(&[0u8; 32]),
                },
            }),
            Payload::event(Event::SessionClose),
        ];
        for p in cases {
            let enc = p.encode().unwrap();
            assert_eq!(Payload::decode(&enc).unwrap(), p);
        }
    }

    #[test]
    fn rejects_noncanonical_and_bodies() {
        let mut enc = Payload::text("hi").encode().unwrap();
        enc.push(b'x');
        assert!(Payload::decode(&enc).is_err());
        let meta = br#"{"type": "text","text":"hi"}"#;
        let mut raw = (meta.len() as u32).to_be_bytes().to_vec();
        raw.extend_from_slice(meta);
        assert!(Payload::decode(&raw).is_err());
    }

    #[test]
    fn text_to_is_absent_unless_given() {
        // A message to everyone keeps the canonical form older clients accept.
        let meta = canonical_json(&Payload::text("hi").meta).unwrap();
        assert_eq!(meta, br#"{"text":"hi","type":"text"}"#);
        let pk = crate::keys::Keypair::from_seed(&[1u8; 32]).public();
        let p = Payload { meta: Meta::Text { text: "hi".into(), to: Some(vec![pk]) }, body: vec![] };
        let enc = p.encode().unwrap();
        assert_eq!(Payload::decode(&enc).unwrap(), p);
        assert!(String::from_utf8(canonical_json(&p.meta).unwrap()).unwrap().contains("\"to\":["));
    }

    #[test]
    fn target_json_shape() {
        let pk = crate::keys::Keypair::from_seed(&[1u8; 32]).public();
        let t =
            serde_json::to_string(&Target::Runner { participant_pub: pk, name: "runner-01".into() }).unwrap();
        assert_eq!(
            t,
            format!(r#"{{"type":"runner","participant_pub":"{}","name":"runner-01"}}"#, pk.to_b64())
        );
        assert_eq!(serde_json::to_string(&Target::Any).unwrap(), r#"{"type":"any"}"#);
    }
}
