//! A job's answer, kept on disk until the relay has it.
//!
//! ```text
//! <outbox>/<job id>/
//!   0000.env, 0000.blob, …   sealed out files, posted in order
//!   answer.json               the result (listing every out file) and its refs;
//!                             written last, so the folder is complete once it exists
//!   result.env, result.blob   the sealed result, sealed once so a resend is the same item
//! ```
//!
//! Nothing is posted before `answer.json` exists, so a folder without it
//! was never sent and is simply replaced. Every item is sealed before it is
//! first sent and sent as saved, so after a restart the relay either has it
//! already (`duplicate`, which counts as delivered) or gets it for the
//! first time: a job's result reaches the relay exactly once.

use std::fs;
use std::path::{Path, PathBuf};

use airlox_core::item::{ItemKind, ItemRef};
use airlox_core::payload::{JobResult, Payload, MAX_STDIO_BYTES};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::{record, Ctx, Poster, Sealed, RESULT_PATIENCE};
use crate::client::is_transient;
use crate::view::write_atomic;

/// What `answer.json` holds.
#[derive(Serialize, Deserialize)]
struct Answer {
    result: JobResult,
    refs: Vec<ItemRef>,
}

/// A job's outbox folder while its answer is being put together.
pub(super) struct Outbox {
    dir: PathBuf,
    files: usize,
}

impl Outbox {
    /// A fresh folder for `job`, replacing one a stopped runner left
    /// unfinished (nothing in it was sent).
    pub fn create(root: &Path, job: &str) -> Result<Self> {
        let dir = root.join(job);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        Ok(Outbox { dir, files: 0 })
    }

    /// Keep a sealed out file; returns its reference.
    pub fn add_file(&mut self, item: &Sealed) -> Result<ItemRef> {
        let stem = format!("{:04}", self.files);
        write_atomic(&self.dir.join(format!("{stem}.blob")), &item.blob, 0o600)?;
        write_atomic(&self.dir.join(format!("{stem}.env")), item.env.as_bytes(), 0o600)?;
        self.files += 1;
        Ok(item.item_ref.clone())
    }

    /// Complete the folder with the result; returns it, ready for [`deliver`].
    pub fn finish(self, result: &JobResult, refs: &[ItemRef]) -> Result<PathBuf> {
        let answer = serde_json::to_vec(&Answer { result: result.clone(), refs: refs.to_vec() })?;
        write_atomic(&self.dir.join("answer.json"), &answer, 0o600)?;
        Ok(self.dir)
    }
}

/// A complete outbox folder: the runner stopped before posting all of it.
pub(super) fn is_complete(dir: &Path) -> bool {
    dir.join("answer.json").is_file()
}

/// Post what `dir` holds: the out files, then the result. A file the relay
/// refuses is left out of the result, with a note; one it already has
/// counts as sent. Once the result is posted (or refused for good) the job
/// is recorded as answered and the folder removed. While the relay stays
/// unreachable the folder is kept, for the next try or the next start.
pub(super) async fn deliver(ctx: &Ctx, poster: &Poster, dir: &Path) -> Result<()> {
    let answer_path = dir.join("answer.json");
    let mut answer: Answer = serde_json::from_slice(&fs::read(&answer_path)?)
        .with_context(|| format!("reading {}", answer_path.display()))?;
    let job = answer.result.job.id.clone();
    let mut files: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "env") && p.file_stem().is_some_and(|s| s != "result"))
        .collect();
    files.sort();
    for env_path in files {
        let blob_path = env_path.with_extension("blob");
        let env = fs::read_to_string(&env_path)?;
        let blob = fs::read(&blob_path)?;
        if let Err(e) = poster.send(&env, &blob, RESULT_PATIENCE).await {
            if is_transient(&e) {
                return Err(e.context("the relay is unreachable; the answer stays queued"));
            }
            let id = serde_json::from_str::<serde_json::Value>(&env)?["header"]["id"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let name = answer.result.out_files.iter().find(|f| f.item.id == id).map(|f| f.name.clone());
            answer.result.out_files.retain(|f| f.item.id != id);
            answer.refs.retain(|r| r.id != id);
            let line = format!("\n[airlox] could not upload out/{}: {e:#}", name.unwrap_or(id));
            if answer.result.stderr.len() + line.len() <= MAX_STDIO_BYTES {
                answer.result.stderr.push_str(&line);
            }
            write_atomic(&answer_path, &serde_json::to_vec(&answer)?, 0o600)?;
        }
        fs::remove_file(&env_path)?;
        let _ = fs::remove_file(&blob_path);
    }
    let (result_env, result_blob) = (dir.join("result.env"), dir.join("result.blob"));
    if !result_env.is_file() {
        let sealed = poster.seal(
            &ctx.keypair,
            ItemKind::Result,
            None,
            answer.refs.clone(),
            Payload::result(answer.result.clone()),
        )?;
        write_atomic(&result_blob, &sealed.blob, 0o600)?;
        write_atomic(&result_env, sealed.env.as_bytes(), 0o600)?;
    }
    let sent =
        poster.send(&fs::read_to_string(&result_env)?, &fs::read(&result_blob)?, RESULT_PATIENCE).await;
    match sent {
        Err(e) if is_transient(&e) => Err(e.context("the relay is unreachable; the result stays queued")),
        outcome => {
            // Delivered, or refused for good: either way, never again.
            record(ctx, &format!("{job} posted"))?;
            let _ = fs::remove_dir_all(dir);
            outcome.context("the relay refused the result")
        }
    }
}
