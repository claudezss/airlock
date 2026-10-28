//! Workspaces: a work directory kept between one sender's jobs (design §7).
//!
//! ```text
//! <cache-dir>/workspaces/<session_id>/<sender>/
//!     work/               the job's /work, kept
//!     .airlox/placed.json the paths the last tree put there
//!     .airlox/state.json  its size after the last job; its age is the idle time
//! ```
//!
//! A tree is *synced* into `work/`: files already there with the same
//! SHA-256 are left alone, others are written, and files the previous tree
//! placed that this one lacks are deleted. Nothing else is touched, so
//! directories a tree never lists (`node_modules`, `target`) survive. A
//! delta tree leaves out of its zip the files its sender believes are here;
//! each must be, byte for byte, before anything is written, or the sync
//! fails with [`TreeStale`]. After the job, [`Workspace::changed`] says
//! which of the tree's files are no longer as listed, so the sender knows
//! what to send next time.
//!
//! The previous job controlled everything in `work/`. Every step here
//! therefore looks at what is on disk without following links (`lstat`,
//! `O_NOFOLLOW`), replaces a link or a file where a directory is needed, and
//! writes through a temporary file renamed into place, which replaces a link
//! instead of writing through it. No job runs while a workspace is synced
//! (a workspace serves one job at a time: the runner leases it to the job
//! from staging to its result), so the checks cannot race the job.

use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use airlox_core::encoding::hex;
use airlox_core::keys::PublicKey;
use airlox_core::validate::zip::{check_entry_path, inspect_zip, ZipLimits};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::tree::{Tree, TreeFile};
use crate::sandbox::make_removable;

/// Every workspace this runner keeps, under `<cache-dir>/workspaces`.
#[derive(Clone, Debug)]
pub struct Workspaces {
    root: PathBuf,
    /// A workspace over this refuses the sender's next job (`--workspace-max-mb`).
    pub max_bytes: u64,
    /// Idle workspaces older than this are removed (`--workspace-ttl`).
    pub ttl: Duration,
}

impl Workspaces {
    pub fn new(cache_root: &Path, max_mb: u64, ttl: Duration) -> Self {
        Workspaces { root: cache_root.join("workspaces"), max_bytes: max_mb.saturating_mul(1 << 20), ttl }
    }

    /// The workspace of `sender`'s jobs in `session_id`. The key is lowercase
    /// hex, so no two senders share a directory on a case-folding disk.
    pub fn of(&self, session_id: &str, sender: &PublicKey) -> Workspace {
        Workspace { dir: self.root.join(session_id).join(hex(&sender.to_bytes())) }
    }

    /// Closing a session removes everything kept for it.
    pub fn remove_session(&self, session_id: &str) {
        let dir = self.root.join(session_id);
        make_removable(&dir);
        let _ = fs::remove_dir_all(dir);
    }

    /// Remove the workspaces unused for longer than the TTL; returns how many.
    /// `in_use` holds the work directories jobs have leased: one leased is
    /// left alone however old its state, and one being removed is leased
    /// meanwhile, so no job starts in it.
    pub fn sweep(&self, in_use: &Mutex<HashSet<PathBuf>>) -> usize {
        let mut removed = 0;
        let lock = || in_use.lock().unwrap_or_else(|e| e.into_inner());
        for session in fs::read_dir(&self.root).into_iter().flatten().flatten() {
            for ws in fs::read_dir(session.path()).into_iter().flatten().flatten() {
                let ws = Workspace { dir: ws.path() };
                if ws.idle().is_none_or(|idle| idle <= self.ttl) || !lock().insert(ws.work()) {
                    continue;
                }
                tracing::info!(workspace = %ws.dir.display(), "removing a workspace unused for {} days", self.ttl.as_secs() / 86400);
                ws.remove();
                lock().remove(&ws.work());
                removed += 1;
            }
            // Gone with its last workspace.
            let _ = fs::remove_dir(session.path());
        }
        removed
    }
}

#[derive(Serialize, Deserialize, Default)]
struct State {
    size_bytes: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct Placed {
    paths: Vec<String>,
}

#[derive(Debug)]
pub struct Workspace {
    dir: PathBuf,
}

fn private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// A file inside a workspace's own `.airlox` directory, which no job can reach.
fn write_json(path: &Path, v: &impl Serialize) -> Result<()> {
    crate::view::write_atomic(path, &serde_json::to_vec(v)?, 0o600)
}

impl Workspace {
    fn meta(&self, name: &str) -> PathBuf {
        self.dir.join(".airlox").join(name)
    }

    pub fn work(&self) -> PathBuf {
        self.dir.join("work")
    }

    /// How long since a job last used it; `None` if it cannot tell.
    fn idle(&self) -> Option<Duration> {
        let stamp = fs::metadata(self.meta("state.json")).or_else(|_| fs::metadata(&self.dir)).ok()?;
        SystemTime::now().duration_since(stamp.modified().ok()?).ok()
    }

    fn remove(&self) {
        make_removable(&self.dir);
        let _ = fs::remove_dir_all(&self.dir);
    }

    /// What the last job left, in bytes; 0 for a workspace not yet used.
    pub fn size_bytes(&self) -> u64 {
        match fs::read(self.meta("state.json")).ok().and_then(|b| serde_json::from_slice::<State>(&b).ok()) {
            Some(s) => s.size_bytes,
            None if self.work().exists() => scan(&self.work()),
            None => 0,
        }
    }

    /// Get the work dir ready for a job: it exists, is a real directory, and
    /// is empty first if the job asked for `fresh`. Returns its path.
    pub fn prepare(&self, fresh: bool) -> Result<PathBuf> {
        private_dir(&self.dir)?;
        private_dir(&self.dir.join(".airlox"))?;
        let work = self.work();
        let real = fs::symlink_metadata(&work).is_ok_and(|m| m.is_dir());
        if fresh || (!real && fs::symlink_metadata(&work).is_ok()) {
            make_removable(&work);
            match fs::symlink_metadata(&work) {
                Ok(m) if m.is_dir() => fs::remove_dir_all(&work)?,
                Ok(_) => fs::remove_file(&work)?,
                Err(_) => {}
            }
            // A fresh workspace remembers nothing of the last one.
            let _ = fs::remove_file(self.meta("placed.json"));
            let _ = fs::remove_file(self.meta("state.json"));
        }
        fs::create_dir_all(&work)?;
        self.save_size(self.size_bytes())?;
        Ok(work)
    }

    fn save_size(&self, size_bytes: u64) -> Result<()> {
        write_json(&self.meta("state.json"), &State { size_bytes })
    }

    /// After a job: make the directories the job may have locked deletable
    /// again, then measure and remember the workspace's size.
    pub fn finish(&self) -> u64 {
        let work = self.work();
        make_removable(&work);
        let size = scan(&work);
        if let Err(e) = self.save_size(size) {
            tracing::warn!(workspace = %self.dir.display(), "could not record the workspace's size: {e:#}");
        }
        size
    }

    fn placed(&self) -> Vec<String> {
        let paths = fs::read(self.meta("placed.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<Placed>(&b).ok())
            .map(|p| p.paths)
            .unwrap_or_default();
        // Our own file, but it is only ever used to delete: hold it to the rules.
        paths.into_iter().filter(|p| check_entry_path(p, &ZipLimits::default()).is_ok()).collect()
    }

    fn set_placed(&self, paths: impl IntoIterator<Item = String>) -> Result<()> {
        write_json(&self.meta("placed.json"), &Placed { paths: paths.into_iter().collect() })
    }

    /// Make the work dir hold `tree`: write what differs, delete what the
    /// previous tree placed and this one lacks, touch nothing else. A file a
    /// delta tree left out must already be here, or nothing is touched and
    /// the error is a [`TreeStale`].
    pub fn sync_tree(&self, tree: &Tree, zip: &[u8]) -> Result<()> {
        let work = self.work();
        let mut ar = zip::ZipArchive::new(std::io::Cursor::new(zip))?;
        let stale: Vec<String> = tree
            .files
            .iter()
            .filter(|f| ar.index_for_name(&f.path).is_none() && !unchanged(&work, f, None))
            .map(|f| f.path.clone())
            .collect();
        if !stale.is_empty() {
            return Err(TreeStale { missing: stale }.into());
        }
        let old = self.placed();
        let new: HashSet<&str> = tree.files.iter().map(|f| f.path.as_str()).collect();
        // Until the sync is done, every path of both trees may be on disk.
        self.set_placed(old.iter().cloned().chain(tree.files.iter().map(|f| f.path.clone())))?;
        let mut known = HashSet::new();
        for f in &tree.files {
            // Left out of a delta tree, and checked above.
            let Ok(mut entry) = ar.by_name(&f.path) else { continue };
            if unchanged(&work, f, Some(entry.size())) {
                continue;
            }
            let size = entry.size();
            put_file(&work, &f.path, &mut entry, size, f.executable(), Some(&f.sha256), &mut known)?;
        }
        for p in old.iter().filter(|p| !new.contains(p.as_str())) {
            remove_placed(&work, p);
        }
        self.set_placed(tree.files.iter().map(|f| f.path.clone()))
    }

    /// After a job: the files of `tree` that are no longer as it listed them
    /// (edited, replaced or removed); `None` if more than the result can
    /// carry. Modes are not compared: a sync puts those right without a copy.
    pub fn changed(&self, tree: &Tree) -> Option<Vec<String>> {
        let work = self.work();
        let mut out = Vec::new();
        for f in &tree.files {
            if same_bytes(&work, f, None).is_none() {
                out.push(f.path.clone());
                if out.len() > airlox_core::payload::MAX_TREE_CHANGED {
                    return None;
                }
            }
        }
        Some(out)
    }

    /// Place a file or archive that is not the tree, replacing what is there.
    pub fn put(
        &self,
        name: &str,
        body: &[u8],
        zipped: bool,
        limits: &ZipLimits,
        claimed: &mut HashSet<String>,
    ) -> Result<()> {
        let work = self.work();
        let mut known = HashSet::new();
        let mut claim = |path: &str| -> Result<()> {
            if claimed.insert(path.to_lowercase()) {
                Ok(())
            } else {
                bail!("inputs collide on {path:?}")
            }
        };
        if !zipped {
            claim(name)?;
            return put_file(&work, name, &mut &body[..], body.len() as u64, false, None, &mut known);
        }
        let entries = inspect_zip(body, limits)?;
        let mut ar = zip::ZipArchive::new(std::io::Cursor::new(body))?;
        for (i, e) in entries.iter().enumerate() {
            if e.is_dir {
                ensure_dir(&work, &e.path, &mut known)?;
                continue;
            }
            claim(&e.path)?;
            let mut f = ar.by_index(i)?;
            let exec = f.unix_mode().is_some_and(|m| m & 0o111 != 0);
            put_file(&work, &e.path, &mut f, e.size, exec, None, &mut known)?;
        }
        Ok(())
    }
}

/// Total size of the files under `dir`, not following links.
fn scan(dir: &Path) -> u64 {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    let (mut total, mut stack, mut linked) = (0u64, vec![dir.to_path_buf()], HashSet::<(u64, u64)>::new());
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).into_iter().flatten().flatten() {
            let Ok(m) = fs::symlink_metadata(e.path()) else { continue };
            if m.is_dir() {
                stack.push(e.path());
            } else if m.is_file() {
                #[cfg(unix)]
                if m.nlink() > 1 && !linked.insert((m.dev(), m.ino())) {
                    continue;
                }
                total += m.len();
            }
        }
    }
    let _ = &mut linked;
    total
}

/// Open `path` for reading as a regular file only: no links followed, no
/// blocking on a FIFO.
fn open_regular(path: &Path) -> Option<fs::File> {
    let mut o = fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut o,
        (nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits(),
    );
    let f = o.open(path).ok()?;
    f.metadata().ok()?.is_file().then_some(f)
}

/// The directory `rel` lives in, if every component of it is a real directory
/// (not a link, not a file) under `work`.
fn real_parent(work: &Path, rel: &str) -> Option<PathBuf> {
    let mut cur = work.to_path_buf();
    let mut parts = rel.split('/').peekable();
    while let Some(c) = parts.next() {
        if parts.peek().is_none() {
            break;
        }
        cur.push(c);
        if !fs::symlink_metadata(&cur).ok()?.is_dir() {
            return None;
        }
    }
    Some(cur)
}

/// A delta tree left out files the workspace does not hold as listed.
#[derive(Debug)]
pub struct TreeStale {
    pub missing: Vec<String>,
}

impl std::fmt::Display for TreeStale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let shown: Vec<_> = self.missing.iter().take(3).map(String::as_str).collect();
        write!(
            f,
            "tree_stale: the tree left out {} file(s) this workspace does not hold as listed ({}{}); send the \
             whole tree",
            self.missing.len(),
            shown.join(", "),
            if self.missing.len() > shown.len() { ", …" } else { "" }
        )
    }
}

impl std::error::Error for TreeStale {}

/// The file `f` on disk, opened, if it holds the listed bytes (hashed, not
/// trusted) and, when given, is `size` long.
fn same_bytes(work: &Path, f: &TreeFile, size: Option<u64>) -> Option<fs::File> {
    let parent = real_parent(work, &f.path)?;
    let path = parent.join(f.path.rsplit('/').next().unwrap_or(&f.path));
    let mut file = open_regular(&path)?;
    if size.is_some_and(|size| file.metadata().ok().map(|m| m.len()) != Some(size))
        || sha256_reader(&mut file).ok().as_deref() != Some(&f.sha256)
    {
        return None;
    }
    Some(file)
}

/// The file `f` is already on disk, with the right bytes (hashed, not
/// trusted); a wrong executable bit is put right.
fn unchanged(work: &Path, f: &TreeFile, size: Option<u64>) -> bool {
    let Some(file) = same_bytes(work, f, size) else { return false };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let want = if f.executable() { 0o755 } else { 0o644 };
        let have = file.metadata().map(|m| m.permissions().mode()).unwrap_or(want);
        if (have & 0o111 != 0) != f.executable() {
            let _ = file.set_permissions(fs::Permissions::from_mode(want));
        }
    }
    true
}

fn sha256_reader(r: &mut impl Read) -> std::io::Result<String> {
    let (mut h, mut buf) = (Sha256::new(), [0u8; 64 * 1024]);
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            return Ok(hex(&h.finalize()));
        }
        h.update(&buf[..n]);
    }
}

/// Make every directory on the way to `rel` (and `rel` itself) a real
/// directory under `work`, replacing a link or file in the way. `known`
/// remembers the directories already checked in this pass.
fn ensure_dir(work: &Path, rel: &str, known: &mut HashSet<PathBuf>) -> Result<PathBuf> {
    let mut cur = work.to_path_buf();
    for c in rel.split('/') {
        cur.push(c);
        if known.contains(&cur) {
            continue;
        }
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => {
                // A link, a file, a pipe: not what a tree has put here.
                fs::remove_file(&cur).or_else(|_| fs::remove_dir(&cur))?;
                fs::create_dir(&cur)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => fs::create_dir(&cur)?,
            Err(e) => return Err(e.into()),
        }
        known.insert(cur.clone());
    }
    Ok(cur)
}

static TMP: AtomicU64 = AtomicU64::new(0);

/// Write `rel` under `work` from `data`: through a temporary file in the same
/// directory, renamed over whatever is there. A link is replaced, not
/// written through; a directory in the way is removed. With `sha256`, the
/// bytes must hash to it, or nothing is placed.
fn put_file(
    work: &Path,
    rel: &str,
    data: &mut impl Read,
    size: u64,
    executable: bool,
    sha256: Option<&str>,
    known: &mut HashSet<PathBuf>,
) -> Result<()> {
    let (dir, name) = rel.rsplit_once('/').unwrap_or(("", rel));
    let parent = if dir.is_empty() { work.to_path_buf() } else { ensure_dir(work, dir, known)? };
    let dest = parent.join(name);
    if fs::symlink_metadata(&dest).is_ok_and(|m| m.is_dir()) {
        make_removable(&dest);
        fs::remove_dir_all(&dest)?;
    }
    let tmp =
        parent.join(format!(".airlox-sync-{}-{}", std::process::id(), TMP.fetch_add(1, Ordering::Relaxed)));
    let written = (|| -> Result<()> {
        // create_new: fails on anything already at that name, links included.
        let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        let (mut h, mut buf, mut n) = (Sha256::new(), [0u8; 64 * 1024], 0u64);
        loop {
            let k = data.read(&mut buf)?;
            if k == 0 {
                break;
            }
            n += k as u64;
            if n > size {
                bail!("{rel:?} inflates beyond its declared size");
            }
            h.update(&buf[..k]);
            f.write_all(&buf[..k])?;
        }
        if let Some(want) = sha256 {
            let got = hex(&h.finalize());
            if got != want {
                bail!("{rel:?} does not match the sha256 in tree.json");
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }))?;
        }
        #[cfg(not(unix))]
        let _ = executable;
        Ok(())
    })();
    match written.and_then(|()| fs::rename(&tmp, &dest).map_err(Into::into)) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e).with_context(|| format!("placing {rel}"))
        }
    }
}

/// Delete a file an earlier tree placed, if it is still a file where it was
/// left: a path that now runs through a link or a file is not ours to touch.
/// Directories left empty go too.
fn remove_placed(work: &Path, rel: &str) {
    let Some(parent) = real_parent(work, rel) else { return };
    let dest = parent.join(rel.rsplit('/').next().unwrap_or(rel));
    match fs::symlink_metadata(&dest) {
        Ok(m) if !m.is_dir() => {
            if fs::remove_file(&dest).is_err() {
                return;
            }
        }
        _ => return,
    }
    let mut dir = parent;
    while dir != work && fs::remove_dir(&dir).is_ok() {
        dir.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::tree::tests::{build, build_delta};

    const MODE: u32 = 0o100644;
    const EXEC: u32 = 0o100755;

    fn ws() -> (tempfile::TempDir, Workspace) {
        let d = tempfile::tempdir().unwrap();
        let w = Workspaces::new(d.path(), 10, Duration::from_secs(86400))
            .of("ax_s", &airlox_core::keys::Keypair::generate().public());
        (d, w)
    }

    fn sync(w: &Workspace, files: &[(&str, &[u8], u32)]) -> Result<()> {
        let z = build(Some("abc"), files);
        w.prepare(false)?;
        w.sync_tree(&Tree::load(&z, &ZipLimits::default())?, &z)
    }

    fn read(w: &Workspace, rel: &str) -> String {
        fs::read_to_string(w.work().join(rel)).unwrap_or_else(|e| format!("<{e}>"))
    }

    #[test]
    fn a_tree_is_written_and_a_second_one_changes_only_the_difference() {
        let (_d, w) = ws();
        sync(&w, &[("src/a.py", b"a1", MODE), ("src/b.py", b"b1", MODE), ("run.sh", b"#!/bin/sh\n", EXEC)])
            .unwrap();
        assert_eq!(read(&w, "src/a.py"), "a1");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &str| fs::metadata(w.work().join(p)).unwrap().permissions().mode() & 0o777;
            assert_eq!((mode("run.sh"), mode("src/a.py")), (0o755, 0o644));
        }
        // Things a tree never lists: a dependency directory, a job's output.
        fs::create_dir_all(w.work().join("node_modules/left-pad")).unwrap();
        fs::write(w.work().join("node_modules/left-pad/index.js"), "x").unwrap();
        fs::write(w.work().join("src/untracked.log"), "log").unwrap();
        // An unchanged file keeps its inode: it was not rewritten.
        #[cfg(unix)]
        let before = std::os::unix::fs::MetadataExt::ino(&fs::metadata(w.work().join("src/a.py")).unwrap());

        sync(&w, &[("src/a.py", b"a1", MODE), ("src/b.py", b"b2", MODE), ("new/c.py", b"c", MODE)]).unwrap();
        assert_eq!(read(&w, "src/b.py"), "b2");
        assert_eq!(read(&w, "new/c.py"), "c");
        #[cfg(unix)]
        assert_eq!(
            before,
            std::os::unix::fs::MetadataExt::ino(&fs::metadata(w.work().join("src/a.py")).unwrap())
        );
        // run.sh left the tree: gone, with nothing else disturbed.
        assert!(!w.work().join("run.sh").exists());
        assert_eq!(read(&w, "node_modules/left-pad/index.js"), "x");
        assert_eq!(read(&w, "src/untracked.log"), "log");
        // And the next tree drops a whole directory it had placed, but not
        // the file the job added beside them.
        sync(&w, &[("src/a.py", b"a1", MODE)]).unwrap();
        assert!(!w.work().join("new").exists(), "an emptied directory goes with its files");
        assert!(!w.work().join("src/b.py").exists());
        assert_eq!(read(&w, "src/untracked.log"), "log");
    }

    fn sync_delta(w: &Workspace, files: &[(&str, &[u8], u32)], left_out: &[&str]) -> Result<()> {
        let z = build_delta(Some("abc"), files, left_out);
        w.prepare(false)?;
        w.sync_tree(&Tree::load(&z, &ZipLimits::default())?, &z)
    }

    #[test]
    fn a_delta_tree_relies_on_what_is_there_and_is_refused_when_it_is_not() {
        let (_d, w) = ws();
        sync(&w, &[("a.py", b"a1", MODE), ("b.py", b"b1", MODE), ("gone.py", b"g", MODE)]).unwrap();
        // a.py unchanged and left out; b.py changed; c.py new; gone.py dropped.
        let next = [("a.py", &b"a1"[..], MODE), ("b.py", &b"b2"[..], MODE), ("c.py", &b"c"[..], MODE)];
        sync_delta(&w, &next, &["a.py"]).unwrap();
        assert_eq!(
            (read(&w, "a.py"), read(&w, "b.py"), read(&w, "c.py")),
            ("a1".into(), "b2".into(), "c".into())
        );
        assert!(!w.work().join("gone.py").exists());

        // The job edits a.py and deletes c.py: both are reported.
        fs::write(w.work().join("a.py"), "edited").unwrap();
        fs::remove_file(w.work().join("c.py")).unwrap();
        let t = Tree::load(&build(Some("abc"), &next), &ZipLimits::default()).unwrap();
        assert_eq!(w.changed(&t), Some(vec!["a.py".to_string(), "c.py".to_string()]));

        // A delta that counts on them is refused, and writes nothing.
        let then = [("a.py", &b"a1"[..], MODE), ("b.py", &b"b3"[..], MODE), ("c.py", &b"c"[..], MODE)];
        let e = sync_delta(&w, &then, &["a.py", "c.py"]).unwrap_err();
        let stale = e.downcast_ref::<TreeStale>().expect("a TreeStale");
        assert_eq!(stale.missing, ["a.py", "c.py"]);
        assert!(stale.to_string().starts_with("tree_stale: "), "{stale}");
        assert_eq!(read(&w, "b.py"), "b2");
        // The whole tree puts everything right.
        sync(&w, &then).unwrap();
        assert_eq!(
            (read(&w, "a.py"), read(&w, "b.py"), read(&w, "c.py")),
            ("a1".into(), "b3".into(), "c".into())
        );
        assert_eq!(
            w.changed(&Tree::load(&build(Some("abc"), &then), &ZipLimits::default()).unwrap()),
            Some(vec![])
        );
    }

    #[test]
    fn a_file_the_job_edited_is_put_back_and_a_matching_one_is_left_alone() {
        let (_d, w) = ws();
        sync(&w, &[("a.py", b"one", MODE), ("b.py", b"two", MODE)]).unwrap();
        fs::write(w.work().join("a.py"), "edited by the last job").unwrap();
        fs::write(w.work().join("b.py"), "two").unwrap();
        sync(&w, &[("a.py", b"one", MODE), ("b.py", b"two", MODE)]).unwrap();
        assert_eq!(read(&w, "a.py"), "one");
    }

    #[test]
    fn an_exec_bit_the_job_cleared_comes_back_without_rewriting() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let (_d, w) = ws();
            sync(&w, &[("run.sh", b"x", EXEC)]).unwrap();
            fs::set_permissions(w.work().join("run.sh"), fs::Permissions::from_mode(0o600)).unwrap();
            sync(&w, &[("run.sh", b"x", EXEC)]).unwrap();
            assert_eq!(fs::metadata(w.work().join("run.sh")).unwrap().permissions().mode() & 0o111, 0o111);
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_planted_in_the_workspace_is_replaced_never_followed() {
        let (d, w) = ws();
        let outside = d.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("victim.txt"), "precious").unwrap();
        sync(&w, &[("keep.txt", b"k", MODE), ("gone.txt", b"g", MODE)]).unwrap();
        let work = w.work();
        // The last job: a directory component that is a link out, a file that
        // is a link to a file out, and a placed file turned into a link.
        std::os::unix::fs::symlink(&outside, work.join("src")).unwrap();
        std::os::unix::fs::symlink(outside.join("victim.txt"), work.join("link.txt")).unwrap();
        fs::remove_file(work.join("gone.txt")).unwrap();
        std::os::unix::fs::symlink(outside.join("victim.txt"), work.join("gone.txt")).unwrap();
        std::os::unix::fs::symlink(&outside, work.join("deep")).unwrap();

        sync(
            &w,
            &[
                ("keep.txt", b"k", MODE),
                ("src/a.py", b"fresh", MODE),
                ("link.txt", b"mine", MODE),
                ("deep/x/y.txt", b"y", MODE),
            ],
        )
        .unwrap();
        // Nothing outside changed, and nothing new appeared there.
        assert_eq!(fs::read_to_string(outside.join("victim.txt")).unwrap(), "precious");
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 1, "wrote through a link");
        // What the tree names is in the workspace, as real files and directories.
        assert_eq!(read(&w, "src/a.py"), "fresh");
        assert_eq!(read(&w, "link.txt"), "mine");
        assert_eq!(read(&w, "deep/x/y.txt"), "y");
        assert!(fs::symlink_metadata(work.join("src")).unwrap().is_dir());
        // gone.txt left the tree: the link is removed, its target is not.
        assert!(fs::symlink_metadata(work.join("gone.txt")).is_err());
        assert_eq!(fs::read_to_string(outside.join("victim.txt")).unwrap(), "precious");
    }

    #[cfg(unix)]
    #[test]
    fn deleting_a_placed_path_does_not_walk_through_a_link() {
        let (d, w) = ws();
        let outside = d.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("a.py"), "precious").unwrap();
        sync(&w, &[("src/a.py", b"a", MODE)]).unwrap();
        // The job swaps the directory the tree placed for a link out.
        fs::remove_dir_all(w.work().join("src")).unwrap();
        std::os::unix::fs::symlink(&outside, w.work().join("src")).unwrap();
        // The next tree no longer has src/a.py, so it would be deleted.
        sync(&w, &[("other.txt", b"o", MODE)]).unwrap();
        assert_eq!(fs::read_to_string(outside.join("a.py")).unwrap(), "precious");
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_where_a_file_belongs_and_a_pipe_where_a_directory_belongs_are_replaced() {
        let (_d, w) = ws();
        sync(&w, &[("a", b"x", MODE)]).unwrap();
        fs::remove_file(w.work().join("a")).unwrap();
        fs::create_dir_all(w.work().join("a/inner")).unwrap();
        fs::write(w.work().join("a/inner/f"), "f").unwrap();
        nix::unistd::mkfifo(&w.work().join("d"), nix::sys::stat::Mode::S_IRWXU).unwrap();
        let t = std::time::Instant::now();
        sync(&w, &[("a", b"x", MODE), ("d/e.txt", b"e", MODE)]).unwrap();
        assert!(t.elapsed() < Duration::from_secs(5), "blocked on a pipe");
        assert_eq!(read(&w, "a"), "x");
        assert_eq!(read(&w, "d/e.txt"), "e");
    }

    #[test]
    fn a_tree_whose_json_lies_about_a_file_places_nothing_of_it() {
        let (_d, w) = ws();
        // tree.json says the hash of "good", the zip holds something else.
        let good = hex(&airlox_core::encoding::sha256(b"good"));
        let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        z.start_file("a.py", opts).unwrap();
        z.write_all(b"evil").unwrap();
        z.start_file(".airlox/tree.json", opts).unwrap();
        let json = serde_json::json!({"head": null, "dirty": false, "count": 1,
            "files": [{"path": "a.py", "sha256": good, "mode": MODE}]});
        z.write_all(json.to_string().as_bytes()).unwrap();
        let z = z.finish().unwrap().into_inner();
        w.prepare(false).unwrap();
        let e = w.sync_tree(&Tree::load(&z, &ZipLimits::default()).unwrap(), &z).unwrap_err();
        assert!(format!("{e:#}").contains("does not match the sha256"), "{e:#}");
        assert!(!w.work().join("a.py").exists());
        assert!(fs::read_dir(w.work()).unwrap().next().is_none(), "left a temporary file behind");
    }

    #[test]
    fn other_inputs_replace_files_but_not_each_other() {
        let (_d, w) = ws();
        sync(&w, &[("data.csv", b"from the tree", MODE)]).unwrap();
        let limits = ZipLimits::default();
        let mut claimed = HashSet::new();
        w.put("data.csv", b"from an input", false, &limits, &mut claimed).unwrap();
        assert_eq!(read(&w, "data.csv"), "from an input");
        let z = build(None, &[("sub/x.txt", b"x", MODE)]);
        w.put("pack.zip", &z, true, &limits, &mut claimed).unwrap();
        assert_eq!(read(&w, "sub/x.txt"), "x");
        // Two inputs naming the same file is still an error.
        assert!(w.put("DATA.csv", b"again", false, &limits, &mut claimed).is_err());
        assert!(w.put("pack2.zip", &z, true, &limits, &mut claimed).is_err());
    }

    #[test]
    fn size_is_measured_after_a_job_and_fresh_empties_the_workspace() {
        let (_d, w) = ws();
        sync(&w, &[("a", b"12345", MODE)]).unwrap();
        fs::write(w.work().join("big"), vec![0u8; 3000]).unwrap();
        assert_eq!(w.finish(), 3005);
        assert_eq!(w.size_bytes(), 3005);
        w.prepare(true).unwrap();
        assert_eq!(w.size_bytes(), 0);
        assert!(fs::read_dir(w.work()).unwrap().next().is_none());
        assert!(w.placed().is_empty(), "a fresh workspace remembers no placed paths");
        // Not a hard link counted twice.
        #[cfg(unix)]
        {
            fs::write(w.work().join("one"), vec![0u8; 100]).unwrap();
            fs::hard_link(w.work().join("one"), w.work().join("two")).unwrap();
            assert_eq!(w.finish(), 100);
        }
    }

    #[test]
    fn workspaces_are_per_sender_per_session_and_swept_when_idle() {
        let d = tempfile::tempdir().unwrap();
        let all = Workspaces::new(d.path(), 1, Duration::from_secs(3600));
        let (a, b) = (
            airlox_core::keys::Keypair::generate().public(),
            airlox_core::keys::Keypair::generate().public(),
        );
        let (wa, wb, wa2) = (all.of("ax_s", &a), all.of("ax_s", &b), all.of("ax_t", &a));
        assert!(wa.dir != wb.dir && wa.dir != wa2.dir);
        for w in [&wa, &wb, &wa2] {
            w.prepare(false).unwrap();
        }
        let in_use = Mutex::new(HashSet::new());
        assert_eq!(all.sweep(&in_use), 0, "just used");
        // Backdate one: only it goes, and its emptied session directory with it.
        let old = SystemTime::now() - Duration::from_secs(7200);
        fs::File::options().write(true).open(wa2.meta("state.json")).unwrap().set_modified(old).unwrap();
        // Not while a job holds it.
        in_use.lock().unwrap().insert(wa2.work());
        assert_eq!(all.sweep(&in_use), 0, "in use");
        in_use.lock().unwrap().clear();
        assert_eq!(all.sweep(&in_use), 1);
        assert!(in_use.lock().unwrap().is_empty());
        assert!(!wa2.dir.exists() && !all.root.join("ax_t").exists());
        assert!(wa.dir.exists() && wb.dir.exists());
        all.remove_session("ax_s");
        assert!(!all.root.join("ax_s").exists());
    }
}
