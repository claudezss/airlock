//! ZIP inspection and safe extraction.
//!
//! Rejected: absolute paths, `..`, backslashes, drive letters, NUL and control
//! characters, case-insensitive duplicates, symlinks, encrypted entries,
//! compression other than stored/deflate, too many entries, too much
//! uncompressed data, and suspicious compression ratios. Extraction counts
//! the bytes actually written and fails if an entry inflates beyond its
//! declared size.

use std::collections::HashSet;
use std::io::Cursor;

use serde::{Deserialize, Serialize};
use zip::{CompressionMethod, ZipArchive};

use crate::{Error, Result};

#[derive(Clone, Debug)]
pub struct ZipLimits {
    pub max_entries: usize,
    pub max_total_bytes: u64,
    pub max_entry_bytes: u64,
    /// Applied to entries larger than `ratio_floor_bytes`.
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
            max_ratio: 200,
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
    if raw.chars().any(|c| c == '\\' || c == '\0' || c.is_control()) {
        return bad("illegal character in path");
    }
    if raw.starts_with('/') {
        return bad("absolute path");
    }
    let p = raw.trim_end_matches('/');
    if p.is_empty() {
        return bad("empty path");
    }
    let parts: Vec<&str> = p.split('/').collect();
    if parts.len() > limits.max_depth {
        return bad("path too deep");
    }
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() || *part == "." || *part == ".." {
            return bad("traversal or empty component");
        }
        if i == 0 && part.len() == 2 && part.ends_with(':') {
            return bad("drive letter");
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
        if !seen.insert(path.to_lowercase()) {
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
    Ok(out)
}

/// Inspect, then extract into `dest` (which must exist and should be empty).
#[cfg(feature = "fs")]
pub fn extract_zip(bytes: &[u8], dest: &std::path::Path, limits: &ZipLimits) -> Result<Vec<ZipEntry>> {
    use std::fs;
    use std::io::{Read, Write};

    let entries = inspect_zip(bytes, limits)?;
    let dest = dest.canonicalize()?;
    let mut ar = ZipArchive::new(Cursor::new(bytes)).map_err(zerr)?;
    for (i, e) in entries.iter().enumerate() {
        let target = dest.join(&e.path);
        if !target.starts_with(&dest) {
            return Err(Error::Zip(format!("entry escapes destination: {:?}", e.path)));
        }
        if e.is_dir {
            fs::create_dir_all(&target)?;
            continue;
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
            // A parent that is a symlink (pre-existing in dest) could redirect writes.
            if !parent.canonicalize()?.starts_with(&dest) {
                return Err(Error::Zip(format!("entry escapes destination: {:?}", e.path)));
            }
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
        for bad in ["../evil", "/etc/passwd", "a/../../b", "C:/x", "a\\b", "a//b"] {
            assert!(check_entry_path(bad, &ZipLimits::default()).is_err(), "{bad}");
        }
        let z = build(&[("A.txt", b"1"), ("a.txt", b"2")]);
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
        let z = build(&[("d/a.txt", b"hello"), ("b.txt", b"x")]);
        extract_zip(&z, dir.path(), &ZipLimits::default()).unwrap();
        assert_eq!(std::fs::read(dir.path().join("d/a.txt")).unwrap(), b"hello");
    }
}
