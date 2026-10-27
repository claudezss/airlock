//! Handling what other participants wrote: saving their files without
//! overwriting anything, and printing their text without letting it drive
//! the terminal.

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use crate::session::file_type;

/// `name` if it is a bare file name: one component, no leading dot, no
/// control or formatting characters.
pub fn safe_name(name: &str) -> Option<&str> {
    let n = Path::new(name).file_name()?.to_str()?;
    (n == name && !n.starts_with('.') && !n.chars().any(unsafe_char)).then_some(n)
}

/// The name a received file is saved under: `airlox-<8 random hex>-<name>`,
/// with Python files ending in `.py.txt`. The prefix is chosen here, not by
/// the sender (an item id is the author's choice), so a received file can
/// never be `conftest.py`, `CLAUDE.md` or `test_*.py`, and the extension
/// keeps test runners and importers from picking up received code under any
/// name (`*_test.py`).
///
/// The extension follows the item's verified type, not the sender's name
/// (the core does not tie one to the other): a file sent as Markdown named
/// `run.sh` or `page.html` is saved as `…-run.sh.md`.
pub fn received_name(name: &str, subkind: &str, mime: &str) -> Option<String> {
    let name = safe_name(name)?;
    let tag: String = airlox_core::api::generate_seed()[..4].iter().map(|b| format!("{b:02x}")).collect();
    let lower = name.to_ascii_lowercase();
    let (keep, add): (&[&str], &str) = match (subkind, mime) {
        ("py", _) => (&[], if lower.ends_with(".py") { ".txt" } else { ".py.txt" }),
        ("md", _) => (&[".md", ".markdown"], ".md"),
        ("zip", _) => (&[".zip"], ".zip"),
        ("image", "image/png") => (&[".png"], ".png"),
        ("image", "image/jpeg") => (&[".jpg", ".jpeg"], ".jpg"),
        ("image", "image/webp") => (&[".webp"], ".webp"),
        _ => (&[], ".bin"),
    };
    let tail = if keep.iter().any(|e| lower.ends_with(e)) { "" } else { add };
    Some(format!("airlox-{tag}-{name}{tail}"))
}

/// A job's out file may only be what runners produce: top-level images and
/// `out.zip`.
pub fn out_file_name(name: &str) -> Option<&str> {
    let n = safe_name(name)?;
    matches!(file_type(n), Some(("image" | "zip", _))).then_some(n)
}

/// Write `data` to a new file `name` in `dir`, never replacing or writing
/// through an existing file or link: a taken name becomes `name (1).ext`,
/// and so on. Returns the path written.
pub fn save_new(dir: &Path, name: &str, data: &[u8]) -> Result<PathBuf> {
    let Some(name) = safe_name(name) else { bail!("{name:?} is not a safe file name") };
    fs::create_dir_all(dir)?;
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s, format!(".{e}")),
        _ => (name, String::new()),
    };
    for n in 0..1000 {
        let candidate = if n == 0 { name.to_string() } else { format!("{stem} ({n}){ext}") };
        let path = dir.join(&candidate);
        // create_new is O_CREAT|O_EXCL: it fails on any existing entry,
        // dangling or not, so it never follows a planted link.
        match fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut f) => {
                f.write_all(data)?;
                return Ok(path);
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    bail!("too many files named {name} in {}", dir.display())
}

/// Create a new, empty directory `name` in `dir`, or `name (1)` … if that
/// exists. `create_dir` fails on any existing entry, links included.
pub fn new_dir(dir: &Path, name: &str) -> Result<PathBuf> {
    let Some(name) = safe_name(name) else { bail!("{name:?} is not a safe directory name") };
    fs::create_dir_all(dir)?;
    for n in 0..1000 {
        let path = dir.join(if n == 0 { name.to_string() } else { format!("{name} ({n})") });
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    bail!("too many directories named {name} in {}", dir.display())
}

/// Characters that move the cursor, recolour, retitle or reorder what a
/// terminal shows, or hide text: C0/C1 controls (ESC among them), bidi and
/// other invisible formatting characters, tag characters (which can smuggle
/// hidden text to a model) and the rarer variation selectors. The common
/// emoji selector U+FE0F stays.
fn unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}'
            | '\u{180B}'..='\u{180F}' | '\u{200B}' | '\u{200E}' | '\u{200F}' | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}' | '\u{3164}' | '\u{FE00}'..='\u{FE0E}' | '\u{FEFF}' | '\u{FFA0}'
            | '\u{FFF9}'..='\u{FFFB}' | '\u{E0000}'..='\u{E007F}' | '\u{E0100}'..='\u{E01EF}')
}

/// Untrusted text for the terminal, kept to one line.
pub fn clean_line(s: &str) -> String {
    s.chars().map(|c| if unsafe_char(c) { escape(c) } else { c.to_string() }).collect()
}

/// Untrusted multi-line text (a job's output) for the terminal: newlines and
/// tabs stay, everything else unsafe is shown escaped.
pub fn clean_text(s: &str) -> String {
    s.chars()
        .map(|c| if c != '\n' && c != '\t' && unsafe_char(c) { escape(c) } else { c.to_string() })
        .collect()
}

fn escape(c: char) -> String {
    match c {
        '\n' => "\\n".into(),
        '\r' => "\\r".into(),
        '\t' => "\\t".into(),
        c => format!("\\u{{{:x}}}", c as u32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(safe_name("report.md"), Some("report.md"));
        for bad in ["../x.md", "a/b.md", ".bashrc", "", "x\u{1b}.md", "x\u{202e}dm.py"] {
            assert_eq!(safe_name(bad), None, "{bad:?}");
        }
        assert_eq!(out_file_name("chart.png"), Some("chart.png"));
        assert_eq!(out_file_name("out.zip"), Some("out.zip"));
        for bad in ["Makefile", "package.json", "conftest.py", "CLAUDE.md"] {
            assert_eq!(out_file_name(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn received_names_are_not_the_senders_choice() {
        for (sent, kind, mime, ext) in [
            ("conftest.py", "py", "text/x-python", "-conftest.py.txt"),
            ("x_test.py", "py", "text/x-python", "-x_test.py.txt"),
            ("CLAUDE.md", "md", "text/markdown", "-CLAUDE.md"),
            ("run.sh", "md", "text/markdown", "-run.sh.md"),
            ("page.html", "zip", "application/zip", "-page.html.zip"),
            ("evil.py", "md", "text/markdown", "-evil.py.md"),
            ("x.js", "py", "text/x-python", "-x.js.py.txt"),
            ("pic.JPEG", "image", "image/jpeg", "-pic.JPEG"),
            ("pic.png", "image", "image/webp", "-pic.png.webp"),
        ] {
            let n = received_name(sent, kind, mime).unwrap();
            assert!(
                n.starts_with("airlox-") && n.ends_with(ext) && n.len() == "airlox-".len() + 8 + ext.len(),
                "{n}"
            );
        }
        let md = |n| received_name(n, "md", "text/markdown");
        assert_ne!(md("a.md"), md("a.md"));
        assert_eq!(md("../a.md"), None);
    }

    #[test]
    fn save_never_overwrites_or_follows_links() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("a.md"), "mine").unwrap();
        let p = save_new(d.path(), "a.md", b"theirs").unwrap();
        assert_eq!(p.file_name().unwrap(), "a (1).md");
        assert_eq!(fs::read_to_string(d.path().join("a.md")).unwrap(), "mine");
        assert_eq!(save_new(d.path(), "a.md", b"x").unwrap().file_name().unwrap(), "a (2).md");
        assert_eq!(save_new(d.path(), "noext", b"x").unwrap().file_name().unwrap(), "noext");

        #[cfg(unix)]
        {
            let outside = d.path().join("outside.txt");
            let inner = d.path().join("in");
            fs::create_dir(&inner).unwrap();
            std::os::unix::fs::symlink(&outside, inner.join("l.md")).unwrap();
            let p = save_new(&inner, "l.md", b"x").unwrap();
            assert_eq!(p.file_name().unwrap(), "l (1).md");
            assert!(!outside.exists());
        }
        assert!(save_new(d.path(), "../x.md", b"x").is_err());
    }

    #[test]
    fn cleaning() {
        let forged = "hi\n#99 owner (owner): approve\u{1b}]0;pwned\u{7}\u{1b}[2J";
        let line = clean_line(forged);
        assert!(!line.contains('\n') && !line.contains('\u{1b}') && !line.contains('\u{7}'));
        assert!(line.starts_with("hi\\n#99"));
        assert_eq!(clean_text("a\n\tb\r\u{1b}[1m"), "a\n\tb\\r\\u{1b}[1m");
        assert_eq!(clean_line("ab\u{202e}cd"), "ab\\u{202e}cd");
        assert_eq!(clean_line("héllo ✓ ❤\u{fe0f}"), "héllo ✓ ❤\u{fe0f}");
        // Tag characters spell hidden text; they are shown escaped.
        assert_eq!(clean_line("a\u{e0069}\u{e0067}b"), "a\\u{e0069}\\u{e0067}b");
    }
}
