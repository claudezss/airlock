//! ZIP inspection and safe extraction.
//!
//! Rejected: absolute paths, `..`, backslashes, colons (drive letters and NTFS
//! streams), NUL, control and invisible formatting characters, trailing dots
//! or spaces, Windows device names, duplicates after Unicode NFC and case
//! folding, symlinks, encrypted entries, compression other than stored/deflate,
//! too many entries, too much uncompressed data, and suspicious compression
//! ratios per entry or for the archive as a whole. Extraction only writes into
//! an empty destination, counts the bytes actually written and fails if an
//! entry inflates beyond its declared size.

use std::collections::HashSet;
use std::io::Cursor;

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use zip::{CompressionMethod, ZipArchive};

use crate::validate::check_name_component;
use crate::{Error, Result};

#[derive(Clone, Debug)]
pub struct ZipLimits {
    pub max_entries: usize,
    pub max_total_bytes: u64,
    pub max_entry_bytes: u64,
    /// Applied to entries larger than `ratio_floor_bytes`, and to the whole
    /// archive (total declared size / archive size) once the total exceeds it.
    pub max_ratio: u64,
    pub ratio_floor_bytes: u64,
    pub max_path_len: usize,
    pub max_depth: usize,
}

impl Default for ZipLimits {
    fn default() -> Self {
        ZipLimits {
            max_entries: 10_000,
            max_total_bytes: 1024 * 1024 * 1024,
            max_entry_bytes: 512 * 1024 * 1024,
            max_ratio: 100,
            ratio_floor_bytes: 1024 * 1024,
            max_path_len: 512,
            max_depth: 32,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ZipEntry {
    pub path: String,
    pub size: u64,
    pub compressed_size: u64,
    pub is_dir: bool,
}

fn zerr(e: impl std::fmt::Display) -> Error {
    Error::Zip(e.to_string())
}

/// Validate a relative archive path and return it without a trailing `/`.
pub fn check_entry_path(raw: &str, limits: &ZipLimits) -> Result<String> {
    let bad = |why: &str| Err(Error::Zip(format!("{why}: {raw:?}")));
    if raw.is_empty() || raw.len() > limits.max_path_len {
        return bad("path length");
    }
    if raw.starts_with('/') {
        return bad("absolute path");
    }
    let p = raw.strip_suffix('/').unwrap_or(raw);
    let parts: Vec<&str> = p.split('/').collect();
    if parts.len() > limits.max_depth {
        return bad("path too deep");
    }
    for part in &parts {
        if let Err(why) = check_name_component(part) {
            return bad(why);
        }
    }
    Ok(p.to_string())
}

/// List and validate every entry without decompressing anything.
pub fn inspect_zip(bytes: &[u8], limits: &ZipLimits) -> Result<Vec<ZipEntry>> {
    let mut ar = ZipArchive::new(Cursor::new(bytes)).map_err(zerr)?;
    if ar.len() > limits.max_entries {
        return Err(Error::Zip(format!("more than {} entries", limits.max_entries)));
    }
    let mut seen = HashSet::new();
    let mut total: u64 = 0;
    let mut out = Vec::with_capacity(ar.len());
    for i in 0..ar.len() {
        let f = ar.by_index_raw(i).map_err(zerr)?;
        let path = check_entry_path(f.name(), limits)?;
        if f.encrypted() {
            return Err(Error::Zip(format!("encrypted entry {path:?}")));
        }
        if let Some(mode) = f.unix_mode() {
            if mode & 0o170000 == 0o120000 {
                return Err(Error::Zip(format!("symlink entry {path:?}")));
            }
        }
        if !matches!(f.compression(), CompressionMethod::Stored | CompressionMethod::Deflated) {
            return Err(Error::Zip(format!("unsupported compression for {path:?}")));
        }
        if !seen.insert(path.nfc().collect::<String>().to_lowercase()) {
            return Err(Error::Zip(format!("duplicate entry {path:?}")));
        }
        let size = f.size();
        let csize = f.compressed_size();
        if size > limits.max_entry_bytes {
            return Err(Error::Zip(format!("entry {path:?} too large")));
        }
        if size > limits.ratio_floor_bytes && size / csize.max(1) > limits.max_ratio {
            return Err(Error::Zip(format!("compression ratio too high for {path:?}")));
        }
        total = total.saturating_add(size);
        if total > limits.max_total_bytes {
            return Err(Error::Zip("archive expands beyond the size limit".into()));
        }
        out.push(ZipEntry { path, size, compressed_size: csize, is_dir: f.is_dir() });
    }
    // Many small, highly compressible entries each stay under the per-entry
    // floor; the archive-wide ratio catches them.
    if total > limits.ratio_floor_bytes && total / (bytes.len() as u64).max(1) > limits.max_ratio {
        return Err(Error::Zip("archive-wide compression ratio too high".into()));
    }
    Ok(out)
}

/// Inspect, then extract into `dest`, which must be an existing, empty
/// directory that nothing else writes to while extraction runs (a fresh
/// per-job work dir). Because it starts empty and every file is created with
/// `create_new`, no symlink can redirect a write.
#[cfg(feature = "fs")]
pub fn extract_zip(bytes: &[u8], dest: &std::path::Path, limits: &ZipLimits) -> Result<Vec<ZipEntry>> {
    use std::fs;
    use std::io::{Read, Write};

    let entries = inspect_zip(bytes, limits)?;
    let dest = dest.canonicalize()?;
    if fs::read_dir(&dest)?.next().is_some() {
        return Err(Error::Zip("destination directory is not empty".into()));
    }
    let inside = |p: &std::path::Path| -> Result<()> {
        if p.canonicalize()?.starts_with(&dest) {
            Ok(())
        } else {
            Err(Error::Zip(format!("entry escapes destination: {}", p.display())))
        }
    };
    let mut ar = ZipArchive::new(Cursor::new(bytes)).map_err(zerr)?;
    for (i, e) in entries.iter().enumerate() {
        let target = dest.join(&e.path);
        if e.is_dir {
            fs::create_dir_all(&target)?;
            inside(&target)?;
            continue;
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
            inside(parent)?;
        }
        let mut f = ar.by_index(i).map_err(zerr)?;
        let mut out = fs::OpenOptions::new().write(true).create_new(true).open(&target)?;
        let mut limited = (&mut f).take(e.size + 1);
        let mut buf = [0u8; 64 * 1024];
        let mut written: u64 = 0;
        loop {
            let n = limited.read(&mut buf).map_err(zerr)?;
            if n == 0 {
                break;
            }
            written += n as u64;
            if written > e.size {
                return Err(Error::Zip(format!("entry {:?} inflates beyond its declared size", e.path)));
            }
            out.write_all(&buf[..n])?;
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn build(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in entries {
            w.start_file(*name, SimpleFileOptions::default()).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn lists_good_archive() {
        let z = build(&[("dataset/orders.csv", b"a,b\n1,2\n"), ("dataset/schema.json", b"{}")]);
        let e = inspect_zip(&z, &ZipLimits::default()).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].path, "dataset/orders.csv");
    }

    #[test]
    fn rejects_traversal_and_duplicates() {
        for bad in [
            "../evil",
            "/etc/passwd",
            "a/../../b",
            "C:/x",
            "C:x",
            "C:foo/bar",
            "a\\b",
            "a//b",
            "d/CON",
            "a./b",
        ] {
            assert!(check_entry_path(bad, &ZipLimits::default()).is_err(), "{bad}");
        }
        let z = build(&[("A.txt", b"1"), ("a.txt", b"2")]);
        assert!(inspect_zip(&z, &ZipLimits::default()).is_err());
        // "é" precomposed vs "e" + combining acute: same name after NFC.
        let z = build(&[("caf\u{e9}.txt", b"1"), ("cafe\u{301}.txt", b"2")]);
        assert!(inspect_zip(&z, &ZipLimits::default()).is_err());
    }

    #[test]
    fn rejects_bombs() {
        let zeros = vec![0u8; 4 * 1024 * 1024];
        let z = {
            let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
            w.start_file(
                "z.bin",
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
            )
            .unwrap();
            w.write_all(&zeros).unwrap();
            w.finish().unwrap().into_inner()
        };
        let err = inspect_zip(&z, &ZipLimits::default()).unwrap_err();
        assert!(err.to_string().contains("ratio"), "{err}");
        let limits = ZipLimits { max_total_bytes: 10, ..Default::default() };
        assert!(inspect_zip(&build(&[("a", b"0123456789ab")]), &limits).is_err());
    }

    #[test]
    fn rejects_many_small_entries_bomb() {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        let chunk = vec![0u8; 512 * 1024]; // under the per-entry floor
        for i in 0..16 {
            w.start_file(format!("f{i}.bin"), opts).unwrap();
            w.write_all(&chunk).unwrap();
        }
        let z = w.finish().unwrap().into_inner();
        let err = inspect_zip(&z, &ZipLimits::default()).unwrap_err();
        assert!(err.to_string().contains("archive-wide"), "{err}");
    }

    #[test]
    fn rejects_symlinks() {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        w.add_symlink("link", "/etc/passwd", SimpleFileOptions::default()).unwrap();
        let z = w.finish().unwrap().into_inner();
        assert!(inspect_zip(&z, &ZipLimits::default()).unwrap_err().to_string().contains("symlink"));
    }

    #[cfg(feature = "fs")]
    #[test]
    fn extracts_into_dest() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        w.add_directory("empty/", SimpleFileOptions::default()).unwrap();
        w.start_file("d/a.txt", SimpleFileOptions::default()).unwrap();
        w.write_all(b"hello").unwrap();
        let z = w.finish().unwrap().into_inner();
        extract_zip(&z, dir.path(), &ZipLimits::default()).unwrap();
        assert_eq!(std::fs::read(dir.path().join("d/a.txt")).unwrap(), b"hello");
        assert!(dir.path().join("empty").is_dir());
    }

    #[cfg(all(feature = "fs", unix))]
    #[test]
    fn refuses_non_empty_dest_with_symlink() {
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("dest");
        let outside = root.path().join("outside");
        std::fs::create_dir(&dest).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, dest.join("link")).unwrap();
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        w.add_directory("link/made_by_dir_entry/", SimpleFileOptions::default()).unwrap();
        w.start_file("link/made_by_parent/f.txt", SimpleFileOptions::default()).unwrap();
        w.write_all(b"x").unwrap();
        let z = w.finish().unwrap().into_inner();
        assert!(extract_zip(&z, &dest, &ZipLimits::default()).is_err());
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0, "wrote outside dest");
    }
}
