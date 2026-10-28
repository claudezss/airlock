//! `airlox run --tree`: the current checkout as one job input.
//!
//! The file list is what git would commit plus what it would add
//! (`git ls-files -co --exclude-standard`: tracked and untracked files,
//! ignored ones left out), from the repository root, zipped as `tree.zip`
//! with `.airlox/tree.json` describing it. Outside a repository it is every
//! regular file under the current directory except `.git`.
//!
//! Untracked files are the usual home of secrets, so a tree holding a file
//! with a well-known credential name is refused unless `--tree-allow` names
//! it; `--tree-exclude` and `.airloxignore` drop files. The list is a seat
//! belt, not a scanner.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use airlox_core::encoding::{hex, sha256};
use airlox_core::validate::zip::{check_entry_path, ZipLimits};
use anyhow::{bail, Context, Result};
use serde::Serialize;

/// The input's file name; a runner knows a tree by the job's `tree` field.
pub const TREE_ZIP: &str = "tree.zip";
/// Where the description goes inside the zip.
pub const TREE_JSON: &str = ".airlox/tree.json";
/// Read from the tree's root: one glob per line, like `--tree-exclude`.
pub const IGNORE_FILE: &str = ".airloxignore";

/// File names that usually hold credentials (matched against the name, not
/// the path).
const CREDENTIAL_NAMES: &[&str] =
    &[".env", ".env.*", "*.pem", "id_rsa*", "*.keystore", ".netrc", "credentials.json"];

#[derive(Serialize, Debug, Clone)]
pub struct TreeFile {
    pub path: String,
    pub sha256: String,
    pub mode: u32,
}

/// `.airlox/tree.json`.
#[derive(Serialize, Debug, Clone)]
pub struct TreeJson {
    pub root_name: String,
    /// The commit checked out; `None` outside a repository or before the
    /// first commit.
    pub head: Option<String>,
    pub branch: Option<String>,
    /// Anything differs from `head`: changes, staged or not, or untracked files.
    pub dirty: bool,
    pub files: Vec<TreeFile>,
    pub count: u64,
    pub bytes: u64,
}

pub struct Tree {
    /// The repository root (or the directory, outside a repository).
    pub root: PathBuf,
    pub json: TreeJson,
    pub zip: Vec<u8>,
    /// The current directory relative to the root, `/`-separated; `None` at the root.
    pub cwd: Option<String>,
    /// Files changed against `head` (from `git status`), for the summary.
    pub changed: Option<usize>,
    /// Up to five of the largest files, largest first.
    pub largest: Vec<(String, u64)>,
    /// Files left out, and why.
    pub notes: Vec<String>,
    pub in_git: bool,
}

pub struct TreeOpts<'a> {
    pub allow: &'a [String],
    pub exclude: &'a [String],
}

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git").arg("-C").arg(root).args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Shell-style glob over a `/`-separated path: `*` and `?` stay within a
/// component, `**` crosses them.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    fn rec(p: &[u8], t: &[u8]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some(b'*') if p.get(1) == Some(&b'*') => {
                let rest = p[2..].strip_prefix(b"/").unwrap_or(&p[2..]);
                (0..=t.len()).any(|i| rec(rest, &t[i..]))
            }
            Some(b'*') => {
                (0..=t.len()).take_while(|&i| i == 0 || t[i - 1] != b'/').any(|i| rec(&p[1..], &t[i..]))
            }
            Some(b'?') => !t.is_empty() && t[0] != b'/' && rec(&p[1..], &t[1..]),
            Some(c) => t.first() == Some(c) && rec(&p[1..], &t[1..]),
        }
    }
    rec(pattern.as_bytes(), text.as_bytes())
}

/// Whether a pattern names this path: a pattern with a `/` matches the
/// whole path (or a directory above it); one without matches any
/// component, as in `.gitignore`.
pub fn pattern_matches(pattern: &str, path: &str) -> bool {
    let pattern = pattern.trim().trim_start_matches("./");
    let pattern = pattern.strip_suffix('/').unwrap_or(pattern);
    if pattern.is_empty() {
        return false;
    }
    if let Some(anchored) = pattern.strip_prefix('/') {
        return glob_match(anchored, path) || glob_match(&format!("{anchored}/**"), path);
    }
    if pattern.contains('/') {
        return glob_match(pattern, path) || glob_match(&format!("{pattern}/**"), path);
    }
    path.split('/').any(|c| glob_match(pattern, c))
}

fn credential_name(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    CREDENTIAL_NAMES.iter().any(|p| glob_match(p, name))
}

/// The root of the repository holding `dir`, if there is one.
fn git_root(dir: &Path) -> Option<PathBuf> {
    let top = git(dir, &["rev-parse", "--show-toplevel"])?;
    let top = top.trim();
    (!top.is_empty()).then(|| PathBuf::from(top))
}

/// Every regular file under `root` except `.git`, `/`-separated, sorted.
fn walk(root: &Path, notes: &mut Vec<String>) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        for e in std::fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
            let e = e?;
            let Some(name) = e.file_name().to_str().map(String::from) else {
                notes.push(format!("left out {}: the name is not UTF-8", e.path().display()));
                continue;
            };
            let rel = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
            let ft = e.file_type()?;
            if ft.is_dir() {
                if name != ".git" {
                    stack.push((e.path(), rel));
                }
            } else {
                out.push(rel);
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(unix)]
fn file_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    if meta.permissions().mode() & 0o111 != 0 {
        0o100755
    } else {
        0o100644
    }
}

#[cfg(not(unix))]
fn file_mode(_meta: &std::fs::Metadata) -> u32 {
    0o100644
}

fn ignore_patterns(root: &Path) -> Vec<String> {
    std::fs::read_to_string(root.join(IGNORE_FILE))
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

/// Build the tree for the checkout holding `dir`.
pub fn build(dir: &Path, opts: &TreeOpts) -> Result<Tree> {
    let dir = dir.canonicalize().with_context(|| format!("{}", dir.display()))?;
    let mut notes = Vec::new();
    let git_top = git_root(&dir);
    let in_git = git_top.is_some();
    let root = git_top.map(|r| r.canonicalize().unwrap_or(r)).unwrap_or_else(|| dir.clone());
    let listed: Vec<String> = if in_git {
        let out = Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["ls-files", "-z", "-co", "--exclude-standard"])
            .output()
            .context("running git ls-files")?;
        if !out.status.success() {
            bail!("git ls-files failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        let mut v: Vec<String> = out
            .stdout
            .split(|b| *b == 0)
            .filter(|p| !p.is_empty())
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect();
        v.sort();
        v.dedup();
        v
    } else {
        walk(&root, &mut notes)?
    };
    let mut excludes: Vec<String> = opts.exclude.to_vec();
    excludes.extend(ignore_patterns(&root));
    let limits = ZipLimits::default();
    let mut files = Vec::new();
    let mut flagged = Vec::new();
    for rel in listed {
        if excludes.iter().any(|p| pattern_matches(p, &rel)) {
            continue;
        }
        // The tree's own description lives there; runners refuse a tree
        // that has anything else in it.
        if rel.starts_with(".airlox/") {
            notes.push(format!("left out {rel}: .airlox/ is reserved for the tree's description"));
            continue;
        }
        let path = root.join(&rel);
        // A tracked file deleted in the work tree, a submodule, a link:
        // only regular files go.
        let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
        if meta.file_type().is_symlink() {
            notes.push(format!("left out {rel}: a symbolic link"));
            continue;
        }
        if !meta.is_file() {
            continue;
        }
        if check_entry_path(&rel, &limits).is_err() {
            notes.push(format!("left out {rel}: the name is not portable"));
            continue;
        }
        if credential_name(&rel) && !opts.allow.iter().any(|p| pattern_matches(p, &rel)) {
            flagged.push(rel.clone());
            continue;
        }
        files.push((rel, path, meta));
    }
    if !flagged.is_empty() {
        let shown: Vec<_> = flagged.iter().take(10).map(String::as_str).collect();
        bail!(
            "the tree holds files whose names usually mean credentials: {}{}\n\
             Leave them out with --tree-exclude <glob> (or a line in {IGNORE_FILE}), or send them anyway with \
             --tree-allow <glob>.",
            shown.join(", "),
            if flagged.len() > shown.len() { format!(" and {} more", flagged.len() - shown.len()) } else { String::new() }
        );
    }
    if files.len() + 1 > limits.max_entries {
        bail!(
            "the tree has {} files; a job input holds at most {}. Leave some out with --tree-exclude <glob>",
            files.len(),
            limits.max_entries - 1
        );
    }
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let mut entries = Vec::with_capacity(files.len());
    let mut sizes = Vec::with_capacity(files.len());
    let mut total = 0u64;
    for (rel, path, meta) in &files {
        let data = std::fs::read(path).with_context(|| format!("reading {rel}"))?;
        let mode = file_mode(meta);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(mode & 0o777)
            .large_file(data.len() as u64 >= u32::MAX as u64);
        w.start_file(rel.as_str(), opts)?;
        w.write_all(&data)?;
        total += data.len() as u64;
        sizes.push((rel.clone(), data.len() as u64));
        entries.push(TreeFile { path: rel.clone(), sha256: hex(&sha256(&data)), mode });
    }
    let (head, branch, changed) = if in_git {
        let head = git(&root, &["rev-parse", "--verify", "-q", "HEAD"]).map(|h| h.trim().to_string());
        let branch = git(&root, &["symbolic-ref", "--short", "-q", "HEAD"]).map(|b| b.trim().to_string());
        let changed = git(&root, &["status", "--porcelain"]).map(|s| s.lines().count());
        (head.filter(|h| !h.is_empty()), branch.filter(|b| !b.is_empty()), changed)
    } else {
        (None, None, None)
    };
    let json = TreeJson {
        root_name: root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
        head,
        branch,
        dirty: changed.is_none_or(|c| c > 0),
        count: entries.len() as u64,
        bytes: total,
        files: entries,
    };
    w.start_file(
        TREE_JSON,
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated),
    )?;
    w.write_all(&serde_json::to_vec(&json)?)?;
    let zip = w.finish()?.into_inner();
    airlox_core::validate::zip::inspect_zip(&zip, &limits)
        .context("the tree does not make an acceptable ZIP")?;
    sizes.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    sizes.truncate(5);
    let cwd = match dir.strip_prefix(&root) {
        Ok(p) if p.as_os_str().is_empty() => None,
        Ok(p) => {
            let parts: Vec<String> =
                p.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
            let rel = parts.join("/");
            airlox_core::policy::check_cwd(&rel).map_err(|e| {
                anyhow::anyhow!("{e}; run from a directory the job can start in, such as the repository root")
            })?;
            Some(rel)
        }
        Err(_) => None,
    };
    Ok(Tree { root, json, zip, cwd, changed, largest: sizes, notes, in_git })
}

impl Tree {
    /// "tree 412 files, 3.1 MB (18 changed)".
    pub fn summary(&self) -> String {
        let changed = match self.changed {
            Some(0) => " (clean)".to_string(),
            Some(n) => format!(" ({n} changed)"),
            None => String::new(),
        };
        format!("tree {} files, {}{changed}", self.json.count, crate::cli::human_bytes(self.json.bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob_match("*.pem", "server.pem"));
        assert!(!glob_match("*.pem", "a/server.pem"));
        assert!(glob_match(".env.*", ".env.local"));
        assert!(!glob_match(".env.*", ".env"));
        assert!(glob_match("id_rsa*", "id_rsa.pub"));
        assert!(glob_match("**/fixtures/*.bin", "tests/fixtures/a.bin"));
        assert!(glob_match("**/fixtures/*.bin", "fixtures/a.bin"));
        assert!(glob_match("data/**", "data/x/y.csv"));
        assert!(pattern_matches("*.pem", "certs/server.pem"));
        assert!(pattern_matches("fixtures", "tests/fixtures/big.bin"));
        assert!(pattern_matches("tests/fixtures", "tests/fixtures/big.bin"));
        assert!(!pattern_matches("tests/fixtures", "other/tests/fixtures/big.bin"));
        assert!(pattern_matches("/build/", "build/out.o"));
        assert!(!pattern_matches("/build/", "src/build/out.o"));
    }

    #[test]
    fn credential_names_are_recognised_by_name() {
        for p in [".env", "app/.env.production", "deploy/key.pem", "id_rsa", ".netrc", "x/credentials.json"] {
            assert!(credential_name(p), "{p}");
        }
        for p in ["env.py", "README.md", "src/pem.rs", "credentials.json.example"] {
            assert!(!credential_name(p), "{p}");
        }
    }

    fn write(root: &Path, rel: &str, data: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }

    #[test]
    fn a_plain_directory_becomes_a_tree_with_its_description() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("proj");
        write(&root, "src/lib.py", "x = 1\n");
        write(&root, ".git/config", "not sent");
        write(&root, "big.bin", &"0".repeat(5000));
        write(&root, "notes/skip.tmp", "dropped");
        write(&root, IGNORE_FILE, "# comment\n*.tmp\n");
        let t = build(&root, &TreeOpts { allow: &[], exclude: &[] }).unwrap();
        // Not a repository (unless the temp dir is inside one): every file
        // under the directory but .git, rooted there.
        if !t.in_git {
            let paths: Vec<_> = t.json.files.iter().map(|f| f.path.as_str()).collect();
            assert_eq!(paths, [IGNORE_FILE, "big.bin", "src/lib.py"]);
            assert_eq!(t.cwd, None);
            assert_eq!(t.largest[0].0, "big.bin");
            let entries = airlox_core::validate::zip::inspect_zip(&t.zip, &ZipLimits::default()).unwrap();
            assert!(entries.iter().any(|e| e.path == TREE_JSON));
            assert_eq!(t.json.files[2].sha256, hex(&sha256(b"x = 1\n")));
        }
    }

    #[test]
    fn in_a_repository_the_tree_is_what_git_would_add_and_the_job_starts_where_you_are() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("repo");
        std::fs::create_dir_all(&root).unwrap();
        let git = |args: &[&str]| {
            Command::new("git").arg("-C").arg(&root).args(args).output().is_ok_and(|o| o.status.success())
        };
        if !git(&["init", "-q"]) {
            return; // no git here
        }
        write(&root, ".gitignore", "node_modules/\n");
        write(&root, "services/api/app.py", "print(1)\n");
        write(&root, "services/api/untracked.txt", "new\n");
        write(&root, "node_modules/x/index.js", "ignored");
        assert!(git(&["add", ".gitignore", "services/api/app.py"]));
        let t = build(&root.join("services/api"), &TreeOpts { allow: &[], exclude: &[] }).unwrap();
        assert!(t.in_git);
        let paths: Vec<_> = t.json.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, [".gitignore", "services/api/app.py", "services/api/untracked.txt"]);
        assert_eq!(t.cwd.as_deref(), Some("services/api"));
        assert!(t.json.dirty && t.json.head.is_none(), "no commit yet");
    }

    #[test]
    fn credentials_are_refused_unless_allowed_or_excluded() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("proj");
        write(&root, "app.py", "");
        write(&root, ".env", "SECRET=1");
        let e = build(&root, &TreeOpts { allow: &[], exclude: &[] }).err().unwrap().to_string();
        assert!(e.contains(".env") && e.contains("--tree-allow"), "{e}");
        let allowed = vec![".env".to_string()];
        let t = build(&root, &TreeOpts { allow: &allowed, exclude: &[] }).unwrap();
        assert!(t.json.files.iter().any(|f| f.path == ".env"));
        let t = build(&root, &TreeOpts { allow: &[], exclude: &allowed }).unwrap();
        assert!(!t.json.files.iter().any(|f| f.path == ".env"));
    }
}
