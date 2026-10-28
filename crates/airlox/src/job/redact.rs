//! Keeps the runner's directories out of what a job printed.
//!
//! A job that runs as a plain process sees its real work directory, so a
//! traceback or an `os.getcwd()` in its output names wherever the runner put
//! it, which on Windows is under the user's profile
//! (`C:\Users\<user>\AppData\Local\Temp\…`). Before a result is signed
//! (and before progress is posted), the absolute path of each of the job's
//! directories, of the runner's runtime and cache, and of the user's home in
//! stdout, stderr, the reason and the progress tail is replaced with a
//! stable name. Files the job wrote are not touched.

use std::path::{Path, PathBuf};

/// A path shorter than this is never replaced: a root-ish path would eat
/// the text around it. It is also longer than any name replacing a path,
/// so redacting never makes the text longer.
const MIN_PATH_LEN: usize = 12;

/// The shortest home directory replaced: `/root` or `C:\` would eat the
/// text around them, `/home/ann` is a real one. `~` is shorter than any.
const MIN_HOME_LEN: usize = 8;

/// Every way a job might print `path`: as given, as the file system names
/// it (links resolved, short Windows names expanded, the `\\?\` prefix
/// dropped), each with either slash, and with backslashes doubled (as in a
/// Python `repr` or in JSON).
fn spellings(path: &Path, min_len: usize) -> Vec<String> {
    let mut bases = vec![path.to_string_lossy().into_owned()];
    if let Ok(real) = std::fs::canonicalize(path) {
        let real = real.to_string_lossy().into_owned();
        bases.push(match real.strip_prefix(r"\\?\") {
            Some(plain) if !plain.starts_with("UNC\\") => plain.to_string(),
            _ => real,
        });
    }
    // Git Bash and MSYS spell `C:\Users\x` as `/c/Users/x`, and back.
    for b in bases.clone() {
        let fwd = b.replace('\\', "/");
        let mut chars = fwd.chars();
        match (chars.next(), chars.next(), chars.next()) {
            (Some(d), Some(':'), Some('/')) if d.is_ascii_alphabetic() => {
                bases.push(format!("/{}/{}", d.to_ascii_lowercase(), &fwd[3..]));
            }
            (Some('/'), Some(d), Some('/')) if d.is_ascii_alphabetic() => {
                bases.push(format!("{}:/{}", d.to_ascii_uppercase(), &fwd[3..]));
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    for b in bases {
        let back = b.replace('/', "\\");
        let fwd = b.replace('\\', "/");
        let doubled = back.replace('\\', "\\\\");
        for s in [b, back, fwd, doubled] {
            if s.len() >= min_len && !out.contains(&s) {
                out.push(s);
            }
        }
    }
    out
}

/// Whether `c` could continue a file name: `/home/ann` is not at the start
/// of `/home/annabelle`, but is of `/home/ann.` at the end of a sentence.
fn name_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '-'
}

/// `text` with each `from` that ends at a path boundary (the end, a slash,
/// or anything a name cannot contain) replaced by `to`.
fn replace_all(text: &str, from: &str, to: &str, ignore_case: bool) -> String {
    // ASCII lowercasing keeps every byte offset, so matches in the folded
    // copy index the original.
    let (folded, needle) = if ignore_case {
        (text.to_ascii_lowercase(), from.to_ascii_lowercase())
    } else {
        (text.to_string(), from.to_string())
    };
    let (mut out, mut last) = (String::with_capacity(text.len()), 0);
    for (i, _) in folded.match_indices(&needle) {
        let end = i + from.len();
        if text[end..].chars().next().is_some_and(name_char) {
            continue;
        }
        out.push_str(&text[last..i]);
        out.push_str(to);
        last = end;
    }
    out.push_str(&text[last..]);
    out
}

fn redact(text: &str, dirs: &[(&Path, &str)], ignore_case: bool) -> String {
    let mut all: Vec<(String, &str)> = dirs
        .iter()
        .flat_map(|(dir, name)| {
            let min = if *name == HOME { MIN_HOME_LEN } else { MIN_PATH_LEN };
            spellings(dir, min).into_iter().map(move |s| (s, *name))
        })
        .collect();
    // Longest first, so `…/work` becomes `$WORK` before its parent matches.
    all.sort_by_key(|(s, _)| std::cmp::Reverse(s.len()));
    let mut out = text.to_string();
    for (from, to) in all {
        out = replace_all(&out, &from, to, ignore_case);
    }
    out
}

/// What replaces the user's home directory.
pub const HOME: &str = "~";
/// What replaces the runner's runtime and cache directories (the venv, the
/// Python installation it links to, the runner's state).
pub const RUNTIME: &str = "$RUNTIME";

/// `text` with each directory's absolute path replaced by its name. Windows
/// paths are matched without regard to case.
pub fn paths(text: &str, dirs: &[(&Path, &str)]) -> String {
    redact(text, dirs, cfg!(windows))
}

/// [`paths`] for owned directories, as a job keeps them.
pub fn hide(text: &str, dirs: &[(PathBuf, &'static str)]) -> String {
    let dirs: Vec<(&Path, &str)> = dirs.iter().map(|(p, n)| (p.as_path(), *n)).collect();
    paths(text, &dirs)
}

/// The user's home directory as the environment names it: `HOME` and
/// `USERPROFILE` both, since under Git Bash the first is `/c/Users/x` and the
/// second `C:\Users\x`, and a job may print either.
pub fn home_dirs() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for var in ["HOME", "USERPROFILE"] {
        if let Some(h) = std::env::var_os(var).filter(|h| !h.is_empty()).map(PathBuf::from) {
            if !out.contains(&h) {
                out.push(h);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs<'a>(root: &'a Path, work: &'a Path, out: &'a Path) -> [(&'a Path, &'static str); 3] {
        [(work, "$WORK"), (out, "$AIRLOX_OUT"), (root, "$JOB")]
    }

    #[test]
    fn unix_paths_become_names() {
        let root = Path::new("/tmp/airlox-jobs-a1b2c3/job-x9");
        let (work, out) = (root.join("work"), root.join("out"));
        let text = format!(
            "cwd {}\nsaving to {}/chart.png\nFile \"{}/run.py\", line 3\nmeta in {}/meta\n",
            work.display(),
            out.display(),
            work.display(),
            root.display()
        );
        let got = redact(&text, &dirs(root, &work, &out), false);
        assert_eq!(
            got,
            "cwd $WORK\nsaving to $AIRLOX_OUT/chart.png\nFile \"$WORK/run.py\", line 3\nmeta in $JOB/meta\n"
        );
        assert!(!got.contains("airlox-jobs"));
    }

    #[test]
    fn windows_paths_become_names_in_every_spelling() {
        let root = Path::new(r"C:\Users\jdoe\AppData\Local\Temp\2\airlox-jobs-a1b2c3\job-x9");
        let (work, out) = (root.join("work"), root.join("out"));
        let text = [
            r"cwd C:\Users\jdoe\AppData\Local\Temp\2\airlox-jobs-a1b2c3\job-x9\work",
            r"repr 'C:\\Users\\jdoe\\AppData\\Local\\Temp\\2\\airlox-jobs-a1b2c3\\job-x9\\work\\data.csv'",
            "uri file:///C:/Users/jdoe/AppData/Local/Temp/2/airlox-jobs-a1b2c3/job-x9/out/chart.png",
            // Case does not matter on Windows.
            r"upper c:\users\JDOE\appdata\local\temp\2\airlox-jobs-a1b2c3\JOB-X9\Work\x.py",
            r"extended \\?\C:\Users\jdoe\AppData\Local\Temp\2\airlox-jobs-a1b2c3\job-x9\meta",
        ]
        .join("\n");
        let got = redact(&text, &dirs(root, &work, &out), true);
        assert_eq!(
            got,
            [
                "cwd $WORK",
                r"repr '$WORK\\data.csv'",
                "uri file:///$AIRLOX_OUT/chart.png",
                r"upper $WORK\x.py",
                r"extended \\?\$JOB\meta",
            ]
            .join("\n")
        );
        assert!(!got.to_lowercase().contains("jdoe"));
        // Without ignoring case the exact spellings still go.
        let exact = redact(&text, &dirs(root, &work, &out), false);
        assert!(exact
            .starts_with("cwd $WORK\nrepr '$WORK\\\\data.csv'\nuri file:///$AIRLOX_OUT/chart.png\nupper c:"));
    }

    #[test]
    fn the_real_path_is_found_when_the_temp_dir_is_a_link() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("airlox-jobs-zz").join("job-1");
        std::fs::create_dir_all(root.join("work")).unwrap();
        let real = std::fs::canonicalize(&root).unwrap();
        let text = format!("cwd {}", real.join("work").display());
        let work = root.join("work");
        let out = root.join("out");
        // The job printed the resolved path (macOS: /private/var/…); the
        // runner knows the unresolved one.
        assert_eq!(redact(&text, &dirs(&root, &work, &out), false), "cwd $WORK");
    }

    #[test]
    fn home_and_runtime_directories_become_names_whichever_is_longer() {
        let home = Path::new("/home/ann");
        let runtime = Path::new("/home/ann/.cache/airlox/runner/runtimes/ab12");
        let install = Path::new("/home/ann/.local/share/uv/python/cpython-3.12.4");
        let dirs = [(home, HOME), (runtime, RUNTIME), (install, RUNTIME)];
        let text = "File \"/home/ann/.cache/airlox/runner/runtimes/ab12/lib/x.py\"\n\
                    /home/ann/.local/share/uv/python/cpython-3.12.4/lib/os.py\n\
                    open('/home/ann/notes.txt') /home/ann";
        assert_eq!(
            redact(text, &dirs, false),
            "File \"$RUNTIME/lib/x.py\"\n$RUNTIME/lib/os.py\nopen('~/notes.txt') ~"
        );
        // Too short to be a home worth replacing.
        assert_eq!(redact("/root/x", &[(Path::new("/root"), HOME)], false), "/root/x");
    }

    #[test]
    fn windows_home_is_found_without_regard_to_case_and_with_doubled_slashes() {
        let home = Path::new(r"C:\Users\jdoe");
        let text = r"cwd c:\users\JDOE\proj repr 'C:\\Users\\jdoe\\x' uri file:///C:/Users/jdoe/y";
        assert_eq!(redact(text, &[(home, HOME)], true), r"cwd ~\proj repr '~\\x' uri file:///~/y");
    }

    #[test]
    fn git_bash_and_windows_spellings_of_a_path_both_go() {
        let text = r"a /c/Users/jdoe/x b C:\Users\jdoe\y c C:/Users/jdoe/z d C:\Users\jdoe";
        for home in [r"C:\Users\jdoe", "/c/Users/jdoe"] {
            assert_eq!(redact(text, &[(Path::new(home), HOME)], true), r"a ~/x b ~\y c ~/z d ~", "{home}");
        }
        // Windows case rules reach the drive letter in the other spelling too.
        assert_eq!(redact("/C/users/JDOE/x", &[(Path::new(r"C:\Users\jdoe"), HOME)], true), "~/x");
    }

    #[test]
    fn a_longer_name_is_not_cut_at_a_shorter_one() {
        let dirs = [(Path::new("/home/ann"), HOME)];
        let text =
            "/home/annabelle/x /home/ann_b /home/ann-2/y /home/ann.old /home/ann, /home/ann/ /home/ann";
        assert_eq!(redact(text, &dirs, false), "/home/annabelle/x /home/ann_b /home/ann-2/y ~.old ~, ~/ ~");
        let root = Path::new("/tmp/airlox-jobs-a1b2c3/job-x9");
        assert_eq!(
            redact(
                "/tmp/airlox-jobs-a1b2c3/job-x9 /tmp/airlox-jobs-a1b2c3/job-x90/work",
                &[(root, "$JOB")],
                false
            ),
            "$JOB /tmp/airlox-jobs-a1b2c3/job-x90/work"
        );
        // Case-folded matching checks the boundary in the original text.
        assert_eq!(
            redact(r"C:\Users\JDOEx C:\Users\JDOE\x", &[(Path::new(r"C:\Users\jdoe"), HOME)], true),
            r"C:\Users\JDOEx ~\x"
        );
    }

    #[test]
    fn hide_takes_owned_directories() {
        let d = [(PathBuf::from("/home/ann"), HOME)];
        assert_eq!(hide("in /home/ann/x", &d), "in ~/x");
    }

    #[test]
    fn short_paths_and_unrelated_text_are_left_alone() {
        let root = Path::new("/");
        let (work, out) = (Path::new("/work"), Path::new("/out"));
        let text = "/work /out / plain text";
        assert_eq!(redact(text, &dirs(root, work, out), false), text);
        assert_eq!(paths("nothing here", &[]), "nothing here");
    }
}
