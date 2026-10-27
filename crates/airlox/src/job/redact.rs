//! Keeps the runner's job directories out of what a job printed.
//!
//! A job that runs as a plain process sees its real work directory, so a
//! traceback or an `os.getcwd()` in its output names wherever the runner put
//! it, which on Windows is under the user's profile
//! (`C:\Users\<user>\AppData\Local\Temp\…`). Before a result is signed, the
//! absolute path of each of the job's directories in stdout and stderr is
//! replaced with a stable name. Files the job wrote are not touched.

use std::path::Path;

/// A path shorter than this is never replaced: a root-ish path would eat
/// the text around it. It is also longer than any name replacing a path,
/// so redacting never makes the text longer.
const MIN_PATH_LEN: usize = 12;

/// Every way a job might print `path`: as given, as the file system names
/// it (links resolved, short Windows names expanded, the `\\?\` prefix
/// dropped), each with either slash, and with backslashes doubled (as in a
/// Python `repr` or in JSON).
fn spellings(path: &Path) -> Vec<String> {
    let mut bases = vec![path.to_string_lossy().into_owned()];
    if let Ok(real) = std::fs::canonicalize(path) {
        let real = real.to_string_lossy().into_owned();
        bases.push(match real.strip_prefix(r"\\?\") {
            Some(plain) if !plain.starts_with("UNC\\") => plain.to_string(),
            _ => real,
        });
    }
    let mut out = Vec::new();
    for b in bases {
        let back = b.replace('/', "\\");
        let fwd = b.replace('\\', "/");
        let doubled = back.replace('\\', "\\\\");
        for s in [b, back, fwd, doubled] {
            if s.len() >= MIN_PATH_LEN && !out.contains(&s) {
                out.push(s);
            }
        }
    }
    out
}

fn replace_all(text: &str, from: &str, to: &str, ignore_case: bool) -> String {
    if !ignore_case {
        return text.replace(from, to);
    }
    // ASCII lowercasing keeps every byte offset, so matches in the folded
    // copy index the original.
    let (folded, needle) = (text.to_ascii_lowercase(), from.to_ascii_lowercase());
    let (mut out, mut last) = (String::with_capacity(text.len()), 0);
    for (i, _) in folded.match_indices(&needle) {
        out.push_str(&text[last..i]);
        out.push_str(to);
        last = i + from.len();
    }
    out.push_str(&text[last..]);
    out
}

fn redact(text: &str, dirs: &[(&Path, &str)], ignore_case: bool) -> String {
    let mut all: Vec<(String, &str)> =
        dirs.iter().flat_map(|(dir, name)| spellings(dir).into_iter().map(move |s| (s, *name))).collect();
    // Longest first, so `…/work` becomes `$WORK` before its parent matches.
    all.sort_by_key(|(s, _)| std::cmp::Reverse(s.len()));
    let mut out = text.to_string();
    for (from, to) in all {
        out = replace_all(&out, &from, to, ignore_case);
    }
    out
}

/// `text` with each directory's absolute path replaced by its name. Windows
/// paths are matched without regard to case.
pub fn paths(text: &str, dirs: &[(&Path, &str)]) -> String {
    redact(text, dirs, cfg!(windows))
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
    fn short_paths_and_unrelated_text_are_left_alone() {
        let root = Path::new("/");
        let (work, out) = (Path::new("/work"), Path::new("/out"));
        let text = "/work /out / plain text";
        assert_eq!(redact(text, &dirs(root, work, out), false), text);
        assert_eq!(paths("nothing here", &[]), "nothing here");
    }
}
