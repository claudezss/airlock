//! PEP 440 versions and version specifiers: what a package allowlist entry
//! such as `cugrid==0.1.0` or `numpy>=1.26,<3` needs, and no more.
//!
//! A [`SpecifierSet`] is parsed from the comma-separated clauses after a
//! package name (`==`, `!=`, `>=`, `<=`, `>`, `<`, `~=`, `===`), written
//! back in one canonical spelling (no spaces, lowercase) and checked
//! against a version an interpreter reports. Checking always allows
//! pre-releases: it asks what a package manager installed, not what it
//! should pick.

use std::cmp::Ordering;

/// Longest version string a specifier or an installed package may have.
const MAX_VERSION_LEN: usize = 64;
/// Most clauses in one specifier.
const MAX_CLAUSES: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum LocalPart {
    // Alphanumeric segments sort before numeric ones.
    Str(String),
    Num(u64),
}

/// A parsed PEP 440 version (the forms `packaging` normalizes included, such
/// as `1.0-1`, `1.0alpha2`, `v2`).
#[derive(Clone, Debug)]
pub struct Version {
    epoch: u64,
    release: Vec<u64>,
    /// 0 = a, 1 = b, 2 = rc, with its number.
    pre: Option<(u8, u64)>,
    post: Option<u64>,
    dev: Option<u64>,
    local: Option<Vec<LocalPart>>,
}

type Key = (u64, Vec<u64>, (u8, u8, u64), Option<u64>, (bool, u64), Option<Vec<LocalPart>>);

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn digit_next(&self, at: usize) -> bool {
        self.b.get(at).is_some_and(u8::is_ascii_digit)
    }
    fn num(&mut self) -> Option<u64> {
        let start = self.i;
        while self.digit_next(self.i) {
            self.i += 1;
        }
        if start == self.i || self.i - start > 18 {
            return None;
        }
        std::str::from_utf8(&self.b[start..self.i]).ok()?.parse().ok()
    }
    fn is_sep(c: Option<u8>) -> bool {
        matches!(c, Some(b'.' | b'-' | b'_'))
    }
    /// An optional separator then one of `words` (longest listed first).
    fn word(&mut self, words: &[&'static str]) -> Option<&'static str> {
        let at = self.i + usize::from(Self::is_sep(self.peek()));
        for w in words {
            if self.b[at.min(self.b.len())..].starts_with(w.as_bytes()) {
                self.i = at + w.len();
                return Some(w);
            }
        }
        None
    }
    /// An optional separator then a number, if a number follows.
    fn opt_num(&mut self) -> Option<u64> {
        let at = self.i + usize::from(Self::is_sep(self.peek()));
        if self.digit_next(at) {
            self.i = at;
            self.num()
        } else {
            None
        }
    }
}

impl Version {
    /// The whole of `s` as a version, or `None`.
    pub fn parse(s: &str) -> Option<Version> {
        if s.len() > MAX_VERSION_LEN {
            return None;
        }
        let lower = s.trim().to_ascii_lowercase();
        let mut c = Cursor { b: lower.as_bytes(), i: 0 };
        if c.peek() == Some(b'v') {
            c.i += 1;
        }
        let first = c.num()?;
        let (epoch, mut release) = if c.peek() == Some(b'!') {
            c.i += 1;
            (first, vec![c.num()?])
        } else {
            (0, vec![first])
        };
        while c.peek() == Some(b'.') && c.digit_next(c.i + 1) {
            c.i += 1;
            release.push(c.num()?);
        }
        let mut v = Version { epoch, release, pre: None, post: None, dev: None, local: None };
        let save = c.i;
        if let Some(w) = c.word(&["alpha", "beta", "preview", "pre", "rc", "a", "b", "c"]) {
            let kind = match w {
                "alpha" | "a" => 0,
                "beta" | "b" => 1,
                _ => 2,
            };
            v.pre = Some((kind, c.opt_num().unwrap_or(0)));
        } else {
            c.i = save;
        }
        // Implicit post release: `1.0-1`.
        if c.peek() == Some(b'-') && c.digit_next(c.i + 1) {
            c.i += 1;
            v.post = Some(c.num()?);
        } else {
            let save = c.i;
            if c.word(&["post", "rev", "r"]).is_some() {
                v.post = Some(c.opt_num().unwrap_or(0));
            } else {
                c.i = save;
            }
        }
        let save = c.i;
        if c.word(&["dev"]).is_some() {
            v.dev = Some(c.opt_num().unwrap_or(0));
        } else {
            c.i = save;
        }
        if c.peek() == Some(b'+') {
            c.i += 1;
            let mut parts = Vec::new();
            loop {
                let start = c.i;
                while c.peek().is_some_and(|b| b.is_ascii_alphanumeric()) {
                    c.i += 1;
                }
                if start == c.i {
                    return None;
                }
                let seg = std::str::from_utf8(&c.b[start..c.i]).ok()?;
                parts.push(match seg.bytes().all(|b| b.is_ascii_digit()) {
                    true => LocalPart::Num(seg.parse().ok()?),
                    false => LocalPart::Str(seg.to_string()),
                });
                if Cursor::is_sep(c.peek()) {
                    c.i += 1;
                } else {
                    break;
                }
            }
            v.local = Some(parts);
        }
        (c.i == c.b.len()).then_some(v)
    }

    fn key(&self) -> Key {
        let mut release = self.release.clone();
        while release.len() > 1 && release.last() == Some(&0) {
            release.pop();
        }
        // A dev release sorts before the pre-releases of its version; a
        // final release after them.
        let pre = match (self.pre, self.post, self.dev) {
            (None, None, Some(_)) => (0, 0, 0),
            (Some((k, n)), ..) => (1, k, n),
            (None, ..) => (2, 0, 0),
        };
        let dev = (self.dev.is_none(), self.dev.unwrap_or(0));
        (self.epoch, release, pre, self.post, dev, self.local.clone())
    }

    fn public(&self) -> Version {
        Version { local: None, ..self.clone() }
    }

    fn base(&self) -> (u64, Vec<u64>) {
        (self.epoch, self.key().1)
    }

    fn is_prerelease(&self) -> bool {
        self.pre.is_some() || self.dev.is_some()
    }
}

/// Versions are equal when they compare equal: `1.0` is `1.0.0`.
impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Eq,
    Ne,
    Ge,
    Le,
    Gt,
    Lt,
    Compat,
    Arbitrary,
}

const OPERATORS: &[(&str, Op)] = &[
    ("===", Op::Arbitrary),
    ("==", Op::Eq),
    ("!=", Op::Ne),
    ("~=", Op::Compat),
    (">=", Op::Ge),
    ("<=", Op::Le),
    (">", Op::Gt),
    ("<", Op::Lt),
];

/// One clause, such as `>=1.26`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Clause {
    op: Op,
    op_text: &'static str,
    /// The version as written, lowercased, with a trailing `.*` kept.
    text: String,
    version: Option<Version>,
    wildcard: bool,
}

/// The comma-separated clauses after a package name, all of which must hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecifierSet {
    clauses: Vec<Clause>,
}

impl Clause {
    fn parse(raw: &str) -> Result<Clause, String> {
        let raw = raw.trim();
        let Some(&(op_text, op)) = OPERATORS.iter().find(|(t, _)| raw.starts_with(t)) else {
            return Err(format!(
                "{raw:?} needs an operator (==, !=, >=, <=, >, <, ~=, ===) before the version"
            ));
        };
        let text = raw[op_text.len()..].trim().to_ascii_lowercase();
        if text.is_empty() || text.len() > MAX_VERSION_LEN {
            return Err(format!(
                "{raw:?} needs a version of 1 to {MAX_VERSION_LEN} characters after {op_text}"
            ));
        }
        if op == Op::Arbitrary {
            let ok = text.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+!*-".contains(&b));
            if !ok {
                return Err(format!("{raw:?}: === takes a plain version string"));
            }
            return Ok(Clause { op, op_text, text, version: None, wildcard: false });
        }
        let (body, wildcard) = match text.strip_suffix(".*") {
            Some(b) => (b, true),
            None => (text.as_str(), false),
        };
        if wildcard && !matches!(op, Op::Eq | Op::Ne) {
            return Err(format!("{raw:?}: .* works only with == and !="));
        }
        let Some(version) = Version::parse(body) else {
            return Err(format!("{raw:?} is not a PEP 440 version (like 1.2.3, 2.0rc1 or 0.1.0.dev0)"));
        };
        if body.contains(char::is_whitespace) {
            return Err(format!("{raw:?}: no spaces inside a version"));
        }
        if wildcard
            && (version.pre.is_some()
                || version.post.is_some()
                || version.dev.is_some()
                || version.local.is_some())
        {
            return Err(format!("{raw:?}: .* goes after the release numbers only (like ==1.2.*)"));
        }
        if version.local.is_some() && !matches!(op, Op::Eq | Op::Ne) {
            return Err(format!("{raw:?}: a local version (+tag) works only with == and !="));
        }
        if op == Op::Compat && version.release.len() < 2 {
            return Err(format!("{raw:?}: ~= needs at least two release numbers (like ~=1.4)"));
        }
        Ok(Clause { op, op_text, text, version: Some(version), wildcard })
    }

    fn matches(&self, installed: &str) -> bool {
        let Some(spec) = &self.version else {
            return installed.trim().eq_ignore_ascii_case(&self.text);
        };
        let Some(v) = Version::parse(installed) else { return false };
        let prefix = |n: usize| {
            v.epoch == spec.epoch
                && (0..n).all(|i| {
                    v.release.get(i).copied().unwrap_or(0) == spec.release.get(i).copied().unwrap_or(0)
                })
        };
        let equal = || {
            if self.wildcard {
                prefix(spec.release.len())
            } else if spec.local.is_none() {
                v.public() == spec.public()
            } else {
                v == *spec
            }
        };
        match self.op {
            Op::Eq => equal(),
            Op::Ne => !equal(),
            Op::Ge => v.public() >= *spec,
            Op::Le => v.public() <= *spec,
            Op::Compat => v.public() >= *spec && prefix(spec.release.len() - 1),
            // `>1.0` excludes 1.0.post1 and 1.0+local; `<1.0` excludes 1.0rc1.
            Op::Gt => {
                (v.post.is_none() || spec.post.is_some() || v.base() != spec.base())
                    && (v.local.is_none() || v.base() != spec.base())
                    && v > *spec
            }
            Op::Lt => v < *spec && (spec.is_prerelease() || !v.is_prerelease() || v.base() != spec.base()),
            Op::Arbitrary => unreachable!("=== has no parsed version"),
        }
    }
}

impl SpecifierSet {
    /// Parse `>=1.26, <3` or `==0.1.0`: one or more comma-separated clauses.
    pub fn parse(s: &str) -> Result<SpecifierSet, String> {
        let parts: Vec<&str> = s.split(',').collect();
        if parts.len() > MAX_CLAUSES {
            return Err(format!("at most {MAX_CLAUSES} version clauses"));
        }
        let clauses: Result<Vec<_>, _> = parts.iter().map(|p| Clause::parse(p)).collect();
        Ok(SpecifierSet { clauses: clauses? })
    }

    /// Whether the installed `version` satisfies every clause. A version
    /// that is not PEP 440 satisfies only `===` clauses.
    pub fn matches(&self, version: &str) -> bool {
        self.clauses.iter().all(|c| c.matches(version))
    }

    /// The clauses `version` does not satisfy, as written canonically.
    pub fn unmet(&self, version: &str) -> Vec<String> {
        self.clauses
            .iter()
            .filter(|c| !c.matches(version))
            .map(|c| format!("{}{}", c.op_text, c.text))
            .collect()
    }
}

impl std::fmt::Display for SpecifierSet {
    /// The canonical spelling: `>=1.26,<3`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, c) in self.clauses.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{}{}", c.op_text, c.text)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap_or_else(|| panic!("{s}"))
    }

    fn set(s: &str) -> SpecifierSet {
        SpecifierSet::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[test]
    fn versions_parse_and_order_as_pep_440_says() {
        let ascending = [
            "1.0.dev1",
            "1.0a1.dev1",
            "1.0a1",
            "1.0a2",
            "1.0b1",
            "1.0rc1",
            "1.0",
            "1.0+local",
            "1.0.post1.dev1",
            "1.0.post1",
            "1.0.1",
            "1.1",
            "2!0.1",
        ];
        for w in ascending.windows(2) {
            assert!(v(w[0]) < v(w[1]), "{} < {}", w[0], w[1]);
        }
        // Spellings of one version.
        assert_eq!(v("1.0"), v("1.0.0"));
        assert_eq!(v("1.0alpha1").cmp(&v("1.0a1")), Ordering::Equal);
        assert_eq!(v("1.0-1").cmp(&v("1.0.post1")), Ordering::Equal);
        assert_eq!(v("V1.0RC2").cmp(&v("1.0rc2")), Ordering::Equal);
        assert_eq!(v("1.0.dev").cmp(&v("1.0.dev0")), Ordering::Equal);
        assert!(v("1.0+abc.5") > v("1.0+abc.4") && v("1.0+abc") < v("1.0+5"));
        for bad in ["", "x", "1.", "1..0", "1.0.0.", "1.0+", "1.0 beta", "1.0+a_", "a1", "1!"] {
            assert!(Version::parse(bad).is_none(), "{bad:?}");
        }
        assert!(Version::parse(&"1.".repeat(40)).is_none());
    }

    #[test]
    fn clauses_match_the_installed_version() {
        let cases: &[(&str, &str, bool)] = &[
            ("==0.1.0", "0.1.0", true),
            ("==0.1.0", "0.1", true),
            ("==0.1.0", "0.2.1", false),
            ("==0.1.0", "0.1.0+cu121", true),
            ("==0.1.0+cu121", "0.1.0", false),
            ("==0.1.0+cu121", "0.1.0+cu121", true),
            ("==1.2.*", "1.2.7", true),
            ("==1.2.*", "1.2", true),
            ("==1.2.*", "1.3.0", false),
            ("==1.2.*", "1.2.0rc1", true),
            ("!=1.5", "1.5.0", false),
            ("!=1.5", "1.5.1", true),
            ("!=1.5.*", "1.5.1", false),
            (">=0.1.0.dev0", "0.1.0.dev5", true),
            (">=0.1.0.dev0", "0.1.0", true),
            (">=0.1.0.dev0", "0.0.9", false),
            (">=1.26", "2.1.0", true),
            (">=1.26", "1.25.9", false),
            ("<=2", "2.0.0", true),
            ("<=2", "2.0.1", false),
            (">1.0", "1.0.post1", false),
            (">1.0", "1.0.1", true),
            (">1.0", "1.0", false),
            (">1.0.post1", "1.0.post2", true),
            ("<2.0", "2.0rc1", false),
            ("<2.0", "1.9", true),
            ("<2.0", "2.0", false),
            ("<2.0rc2", "2.0rc1", true),
            ("~=1.4.2", "1.4.9", true),
            ("~=1.4.2", "1.5.0", false),
            ("~=1.4.2", "1.4.1", false),
            ("~=1.4", "1.9", true),
            ("~=1.4", "2.0", false),
            ("===1.0", "1.0", true),
            ("===1.0", "1.0.0", false),
            ("===Foo-1", "foo-1", true),
            // Not PEP 440 text.
            ("==1.0", "git-abc", false),
            ("!=1.0", "git-abc", false),
        ];
        for (spec, installed, want) in cases {
            assert_eq!(set(spec).matches(installed), *want, "{spec} vs {installed}");
        }
    }

    #[test]
    fn a_set_needs_every_clause_and_names_the_ones_missed() {
        let s = set(">=1.26, <3");
        assert_eq!(s.to_string(), ">=1.26,<3");
        assert!(s.matches("2.2.0") && !s.matches("3.0.0") && !s.matches("1.0"));
        assert_eq!(s.unmet("3.1"), ["<3"]);
        assert_eq!(s.unmet("0.9"), [">=1.26"]);
        assert!(s.unmet("2.0").is_empty());
    }

    #[test]
    fn specifier_syntax_is_checked() {
        // Canonical text: whitespace dropped, lowercase.
        assert_eq!(set("== 1.0.0RC1 , != 1.0.0rc2").to_string(), "==1.0.0rc1,!=1.0.0rc2");
        assert_eq!(set("===Foo.1").to_string(), "===foo.1");
        for bad in [
            "",
            "1.0",
            "=1.0",
            "==",
            "== ",
            ">=1.0,",
            ",>=1.0",
            ">= 1 0",
            ">=1.*",
            "~=1",
            "~=1.0.*",
            ">=1.0+local",
            "<1.0+local",
            "==1.0rc1.*",
            "==1.0.*.*",
            "==x",
            ">=1.0; python_version>'3'",
            "==1.0 @ https://evil.example/x.whl",
            "===a b",
            "===a/b",
            "==1.0)",
            "(==1.0)",
        ] {
            assert!(SpecifierSet::parse(bad).is_err(), "{bad:?}");
        }
        assert!(SpecifierSet::parse(&vec![">=1"; 9].join(",")).is_err());
        assert!(SpecifierSet::parse(&format!("==1.{}", "0".repeat(70))).is_err());
        // Local versions stay with equality.
        assert!(SpecifierSet::parse("==1.0+cpu,!=1.0+gpu").is_ok());
    }
}
