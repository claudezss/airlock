//! Plaintext payloads inside an item.
//!
//! ```text
//! payload = u32_be(len(meta)) || meta || body
//! meta    = canonical JSON, tagged by "type"
//! body    = raw file bytes for "file"; empty for every other type
//! ```

use serde::{Deserialize, Serialize};

use crate::encoding::canonical_json;
use crate::item::{ItemKind, ItemRef};
use crate::keys::PublicKey;
use crate::{Error, Result};

pub const MAX_META_BYTES: usize = 4 * 1024 * 1024;
/// Ceiling for each of `stdout` and `stderr` in a result.
pub const MAX_STDIO_BYTES: usize = 1024 * 1024;
pub const MAX_OUT_FILES: usize = 64;
pub const MAX_REASON_CHARS: usize = 4096;

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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JobSpec {
    /// Entry file name, e.g. "summarize.py".
    pub filename: String,
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
}

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
    Text { text: String },
    File { name: String, mime: String },
    Job(JobSpec),
    Result(JobResult),
    Event(Event),
}

impl Meta {
    pub fn kind(&self) -> ItemKind {
        match self {
            Meta::Text { .. } => ItemKind::Text,
            Meta::File { .. } => ItemKind::File,
            Meta::Job(_) => ItemKind::Job,
            Meta::Result(_) => ItemKind::Result,
            Meta::Event(_) => ItemKind::Event,
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
        Payload { meta: Meta::Text { text: text.into() }, body: vec![] }
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
                filename: "x.py".into(),
                code: "print(1)".into(),
                runtime: "python3.12".into(),
                timeout_s: 10,
                memory_mb: None,
                files: vec![],
                requirements: vec![],
                target: Target::Labels { labels: vec!["gpu".into()] },
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
