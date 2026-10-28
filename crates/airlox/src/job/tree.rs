//! A job's working tree: the input `spec.tree` points at (design §6).
//!
//! It is a zip of the files plus `.airlox/tree.json`:
//!
//! ```json
//! {"root_name": "app", "head": "ab12…", "branch": "main", "dirty": true,
//!  "files": [{"path": "src/a.py", "sha256": "…", "mode": 33188}],
//!  "count": 1, "bytes": 123}
//! ```
//!
//! The runner reads `head`, `dirty`, `files` (path, sha256, mode), `count`
//! and `delta`; the rest is for people. `files` lists every file the tree
//! consists of: that list is what a workspace syncs to. Each must be in the
//! zip, unless the tree says `"delta": true`: then the zip holds only what
//! the sender believes differs from the sender's workspace here, and the
//! rest must already be there, byte for byte, or the job is refused
//! (`tree_stale`) and the sender sends the whole tree.

use std::collections::HashSet;
use std::io::{Cursor, Read};

use airlox_core::encoding::{hex, sha256};
use airlox_core::payload::TreeInfo;
use airlox_core::validate::zip::{check_entry_path, inspect_zip, ZipLimits};
use anyhow::{bail, Context, Result};
use serde::Deserialize;

pub const TREE_JSON: &str = ".airlox/tree.json";
/// The most `tree.json` the runner reads.
const MAX_TREE_JSON: u64 = 16 << 20;

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TreeFile {
    pub path: String,
    /// Hex SHA-256 of the file's bytes.
    pub sha256: String,
    /// Unix mode, such as 33188 (0o100644) or 33261 (0o100755).
    pub mode: u32,
}

impl TreeFile {
    pub fn executable(&self) -> bool {
        self.mode & 0o111 != 0
    }
}

#[derive(Deserialize, Debug)]
struct TreeJson {
    head: Option<String>,
    #[serde(default)]
    dirty: bool,
    files: Vec<TreeFile>,
    count: u64,
    #[serde(default)]
    delta: bool,
}

#[derive(Debug)]
pub struct Tree {
    pub files: Vec<TreeFile>,
    /// The zip leaves out files the workspace should already hold.
    pub delta: bool,
    /// What a result's `env` says about the tree.
    pub info: TreeInfo,
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Tree {
    /// Read and check the tree in `zip` (the input's plaintext body): the zip
    /// is inspected under `limits`, `.airlox/tree.json` must be there and
    /// well formed, and every file it lists must be in the zip.
    pub fn load(zip: &[u8], limits: &ZipLimits) -> Result<Tree> {
        let entries = inspect_zip(zip, limits)?;
        let mut ar = zip::ZipArchive::new(Cursor::new(zip))?;
        let mut raw = Vec::new();
        ar.by_name(TREE_JSON)
            .with_context(|| format!("the tree has no {TREE_JSON}"))?
            .take(MAX_TREE_JSON + 1)
            .read_to_end(&mut raw)?;
        if raw.len() as u64 > MAX_TREE_JSON {
            bail!("{TREE_JSON} is over {} MiB", MAX_TREE_JSON >> 20);
        }
        let json: TreeJson =
            serde_json::from_slice(&raw).with_context(|| format!("{TREE_JSON} is not valid"))?;
        if json.count != json.files.len() as u64 {
            bail!("{TREE_JSON} says {} files but lists {}", json.count, json.files.len());
        }
        if let Some(head) = &json.head {
            if head.is_empty() || head.len() > 64 || !head.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("{TREE_JSON} head is not a commit hash");
            }
        }
        let in_zip: HashSet<&str> = entries.iter().filter(|e| !e.is_dir).map(|e| e.path.as_str()).collect();
        let mut seen = HashSet::new();
        for f in &json.files {
            check_entry_path(&f.path, limits).map_err(|e| anyhow::anyhow!("{TREE_JSON}: {e}"))?;
            if f.path.ends_with('/') || f.path == TREE_JSON || f.path.starts_with(".airlox/") {
                bail!("{TREE_JSON} lists {:?}, which is reserved", f.path);
            }
            if !is_hex(&f.sha256, 64) {
                bail!("{TREE_JSON}: the sha256 of {:?} is not 64 lowercase hex digits", f.path);
            }
            if !json.delta && !in_zip.contains(f.path.as_str()) {
                bail!("{TREE_JSON} lists {:?}, which is not in the zip", f.path);
            }
            if !seen.insert(f.path.as_str()) {
                bail!("{TREE_JSON} lists {:?} twice", f.path);
            }
        }
        Ok(Tree {
            info: TreeInfo {
                head: json.head.clone().map(|h| h.to_ascii_lowercase()),
                dirty: json.dirty,
                count: json.count,
                sha256: hex(&sha256(zip)),
                changed: None,
            },
            files: json.files,
            delta: json.delta,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    /// A tree zip as the CLI would build it: `files` (path, content, mode)
    /// plus `.airlox/tree.json`.
    pub fn build(head: Option<&str>, files: &[(&str, &[u8], u32)]) -> Vec<u8> {
        build_delta(head, files, &[])
    }

    /// A delta tree: `files` are listed, but those named in `left_out` are
    /// not in the zip.
    pub fn build_delta(head: Option<&str>, files: &[(&str, &[u8], u32)], left_out: &[&str]) -> Vec<u8> {
        let list: Vec<_> = files
            .iter()
            .map(|(p, data, mode)| serde_json::json!({"path": p, "sha256": hex(&sha256(data)), "mode": mode}))
            .collect();
        let json = serde_json::json!({
            "root_name": "app", "head": head, "branch": "main", "dirty": true,
            "files": list, "count": files.len(), "bytes": files.iter().map(|f| f.1.len()).sum::<usize>(),
        });
        let mut json = json;
        if !left_out.is_empty() {
            json["delta"] = true.into();
        }
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        for (p, data, _) in files.iter().filter(|f| !left_out.contains(&f.0)) {
            w.start_file(*p, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.start_file(TREE_JSON, opts).unwrap();
        w.write_all(json.to_string().as_bytes()).unwrap();
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn a_tree_reports_what_results_say_about_it() {
        let z = build(
            Some("AB12cd"),
            &[("src/a.py", b"print(1)\n", 0o100644), ("run.sh", b"#!/bin/sh\n", 0o100755)],
        );
        let t = Tree::load(&z, &ZipLimits::default()).unwrap();
        assert_eq!(t.info.head.as_deref(), Some("ab12cd"));
        assert!(t.info.dirty);
        assert_eq!(t.info.count, 2);
        assert_eq!(t.info.sha256, hex(&sha256(&z)));
        assert!(!t.files[0].executable() && t.files[1].executable());
        // Outside a repository there is no commit.
        let z = build(None, &[("a", b"x", 0o100644)]);
        assert_eq!(Tree::load(&z, &ZipLimits::default()).unwrap().info.head, None);
    }

    #[test]
    fn a_delta_tree_may_leave_listed_files_out() {
        let files = [("a", &b"x"[..], 0o100644), ("b", &b"y"[..], 0o100644)];
        let t = Tree::load(&build_delta(None, &files, &["a"]), &ZipLimits::default()).unwrap();
        assert!(t.delta);
        assert_eq!(t.info.count, 2);
        assert!(!Tree::load(&build(None, &files), &ZipLimits::default()).unwrap().delta);
    }

    #[test]
    fn a_malformed_tree_is_refused_with_why() {
        let l = ZipLimits::default();
        // No tree.json.
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        w.start_file("a", zip::write::SimpleFileOptions::default()).unwrap();
        w.write_all(b"x").unwrap();
        let e = Tree::load(&w.finish().unwrap().into_inner(), &l).unwrap_err().to_string();
        assert!(e.contains("no .airlox/tree.json"), "{e}");
        // Each way tree.json can be wrong.
        let good = [("a.py", &b"1"[..], 0o100644u32)];
        type Edit = fn(&mut serde_json::Value);
        let edits: [(&str, Edit); 7] = [
            ("head", |j: &mut serde_json::Value| j["head"] = "xyz".into()),
            ("lists 1", |j: &mut serde_json::Value| j["count"] = 5.into()),
            ("reserved", |j: &mut serde_json::Value| j["files"][0]["path"] = ".airlox/tree.json".into()),
            ("not in the zip", |j: &mut serde_json::Value| j["files"][0]["path"] = "ghost.py".into()),
            ("64 lowercase hex", |j: &mut serde_json::Value| j["files"][0]["sha256"] = "ABC".into()),
            ("is not valid", |j: &mut serde_json::Value| j["files"] = "no".into()),
            ("../x", |j: &mut serde_json::Value| j["files"][0]["path"] = "../x".into()),
        ];
        for (what, edit) in edits {
            let z = build(None, &good);
            let mut ar = zip::ZipArchive::new(Cursor::new(&z)).unwrap();
            let mut j = String::new();
            ar.by_name(TREE_JSON).unwrap().read_to_string(&mut j).unwrap();
            let mut j: serde_json::Value = serde_json::from_str(&j).unwrap();
            edit(&mut j);
            let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
            let opts = zip::write::SimpleFileOptions::default();
            w.start_file("a.py", opts).unwrap();
            w.write_all(b"1").unwrap();
            w.start_file(TREE_JSON, opts).unwrap();
            w.write_all(j.to_string().as_bytes()).unwrap();
            let e = format!("{:#}", Tree::load(&w.finish().unwrap().into_inner(), &l).unwrap_err());
            assert!(e.contains(what), "{what}: {e}");
        }
    }
}
