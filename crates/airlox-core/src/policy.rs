//! Policy checks.
//!
//! Two layers, because the server never sees plaintext:
//! - [`check_header`] runs anywhere, including the server.
//! - [`check_payload`] and the job/result helpers run on clients and runners
//!   after decryption.
//!
//! An author's role is never taken on trust: [`author_role`] derives it from a
//! role certificate verified against the manifest and bound to the item's
//! author key. The checks below take that derived role.

use crate::cert::{is_runner_token, SignedRoleCert};
use crate::item::{ItemHeader, ItemKind, ItemRef};
use crate::keys::PublicKey;
use crate::payload::{
    Event, JobEnv, JobKind, JobProgress, JobResult, JobSpec, JobStatus, Meta, Payload, Target,
    MAX_CHUNK_BYTES, MAX_ENV_PACKAGES, MAX_OUT_FILES, MAX_PROGRESS_TAIL_BYTES, MAX_REASON_CHARS,
    MAX_RECIPIENTS, MAX_SHELL_CODE_BYTES, MAX_STDIO_BYTES,
};
use crate::pep440::SpecifierSet;
use crate::session::{ContentType, Manifest, Mode, Role};
use crate::validate::{check_name_component, sniff};
use crate::{Error, Result};

pub const MAX_CODE_BYTES: usize = 1024 * 1024;
pub const MAX_JOB_FILES: usize = 32;

/// Verify `cert` against the manifest and that it certifies the item's author.
/// Returns the author's role.
pub fn author_role(m: &Manifest, cert: &SignedRoleCert, h: &ItemHeader) -> Result<Role> {
    cert.verify(m)?;
    if cert.participant() != h.author {
        return Err(Error::policy("item author does not match the certificate"));
    }
    Ok(cert.role())
}

/// Which item kinds each role may author.
pub fn role_may_post(role: Role, kind: ItemKind) -> bool {
    use ItemKind::*;
    match role {
        Role::Owner => true,
        Role::Sender => matches!(kind, Text | File | Job | Event),
        Role::Runner => matches!(kind, Result | File | Progress),
        Role::Observer => false,
    }
}

/// Server-enforceable checks on a header whose author holds `author_role`
/// (obtained from [`author_role`]).
pub fn check_header(m: &Manifest, author_role: Role, h: &ItemHeader) -> Result<()> {
    h.validate()?;
    if h.session_id != m.session_id {
        return Err(Error::policy("item belongs to another session"));
    }
    if !role_may_post(author_role, h.kind) {
        return Err(Error::policy(format!(
            "role {} may not post {} items",
            author_role.as_str(),
            h.kind.as_str()
        )));
    }
    if author_role == Role::Runner {
        require_execute(m)?;
    }
    if h.size > m.max_item_bytes {
        return Err(Error::policy(format!("item exceeds {} bytes", m.max_item_bytes)));
    }
    if h.created_at_ms < m.created_at_ms || m.expires_at_ms.is_some_and(|e| h.created_at_ms >= e) {
        return Err(Error::policy("item timestamp is outside the session lifetime"));
    }
    match h.kind {
        ItemKind::Text => require_type(m, ContentType::Text)?,
        ItemKind::File => require_type(m, h.subkind.expect("validated"))?,
        ItemKind::Job => {
            require_execute(m)?;
            let kind = match h.subkind {
                Some(ContentType::Sh) => JobKind::Shell,
                _ => {
                    require_type(m, ContentType::Py)?;
                    JobKind::Python
                }
            };
            require_kind(m, kind)?;
        }
        ItemKind::Result | ItemKind::Progress => require_execute(m)?,
        ItemKind::Event => {}
    }
    Ok(())
}

fn require_type(m: &Manifest, t: ContentType) -> Result<()> {
    if m.allows(t) {
        Ok(())
    } else {
        Err(Error::policy(format!("content type {} is not allowed in this session", t.as_str())))
    }
}

fn require_kind(m: &Manifest, k: JobKind) -> Result<()> {
    let limits = m.job_limits.as_ref().expect("execute manifests carry job_limits");
    if limits.allows_kind(k) {
        Ok(())
    } else {
        Err(Error::policy(format!("{} jobs are not allowed in this session", k.as_str())))
    }
}

fn require_execute(m: &Manifest) -> Result<()> {
    if m.mode == Mode::Execute {
        Ok(())
    } else {
        Err(Error::policy("session is in relay mode"))
    }
}

/// Client-side checks on a decrypted payload.
pub fn check_payload(m: &Manifest, author_role: Role, h: &ItemHeader, p: &Payload) -> Result<()> {
    check_header(m, author_role, h)?;
    if p.kind() != h.kind {
        return Err(Error::policy("payload type does not match header kind"));
    }
    match &p.meta {
        Meta::Text { to, .. } => check_recipients(to.as_deref()),
        Meta::File { name, mime } => check_file(h.subkind.expect("validated"), name, mime, &p.body),
        Meta::Job(spec) => {
            if h.subkind != Some(spec.kind().subkind()) {
                return Err(Error::policy("the job's kind does not match its header subkind"));
            }
            check_job(m, spec)
        }
        Meta::Result(r) => check_result(r),
        Meta::Event(e) => check_event(author_role, e),
        Meta::Progress(p) => check_progress(p),
    }
}

/// A text item's `to`: absent, or 1 to 64 distinct participant keys.
pub fn check_recipients(to: Option<&[PublicKey]>) -> Result<()> {
    let Some(to) = to else { return Ok(()) };
    if to.is_empty() || to.len() > MAX_RECIPIENTS {
        return Err(Error::policy("`to` names 1 to 64 participants, or is absent"));
    }
    let distinct: std::collections::HashSet<_> = to.iter().collect();
    if distinct.len() != to.len() {
        return Err(Error::policy("`to` names a participant twice"));
    }
    Ok(())
}

/// Shape checks on a progress item: a heartbeat (elapsed time, maybe a
/// tail) or an output chunk (`stream`, `offset` and `data` together).
pub fn check_progress(p: &JobProgress) -> Result<()> {
    p.job.validate()?;
    if p.tail.as_ref().is_some_and(|t| t.len() > MAX_PROGRESS_TAIL_BYTES) {
        return Err(Error::policy("a progress tail is limited to 64 KiB"));
    }
    match (&p.stream, &p.offset, &p.data) {
        (None, None, None) if !p.truncated => {}
        (Some(_), Some(_), Some(d)) => {
            if d.len() > MAX_CHUNK_BYTES {
                return Err(Error::policy("an output chunk is limited to 64 KiB"));
            }
            if p.tail.is_some() || p.tail_truncated {
                return Err(Error::policy("an output chunk carries no tail"));
            }
        }
        _ => return Err(Error::policy("an output chunk needs stream, offset and data together")),
    }
    Ok(())
}

/// A job's `progress_file`: a relative, `/`-separated path of portable
/// components, none starting with a dot, at most 8 deep and 255 bytes.
pub fn check_progress_file(path: &str) -> Result<()> {
    check_rel_path("progress_file", path)
}

/// A job's `cwd`: the same rules as `progress_file`.
pub fn check_cwd(path: &str) -> Result<()> {
    check_rel_path("cwd", path)
}

fn check_rel_path(what: &str, path: &str) -> Result<()> {
    let bad = |why: &str| Err(Error::policy(format!("bad {what} {path:?}: {why}")));
    if path.is_empty() || path.len() > 255 {
        return bad("1 to 255 bytes");
    }
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > 8 {
        return bad("at most 8 components");
    }
    for part in parts {
        if part.starts_with('.') {
            return bad("no component may start with a dot");
        }
        if let Err(why) = check_name_component(part) {
            return bad(why);
        }
    }
    Ok(())
}

fn check_event(author_role: Role, e: &Event) -> Result<()> {
    match e {
        Event::RunnerReject { reason: Some(r), .. } if r.chars().count() > MAX_REASON_CHARS => {
            return Err(Error::policy("reason too long"));
        }
        Event::JobCancel { job } => job.validate()?,
        _ => {}
    }
    match (author_role, e) {
        (Role::Owner, _) => Ok(()),
        // Whether this sender authored the job is checked with `may_cancel`
        // once the job item is at hand.
        (Role::Sender, Event::JobCancel { .. }) => Ok(()),
        _ => Err(Error::policy("only the owner may post this event")),
    }
}

/// A job may be cancelled by the owner or by the sender who submitted it.
pub fn may_cancel(canceller_role: Role, canceller: PublicKey, job_author: PublicKey) -> bool {
    canceller_role == Role::Owner || (canceller_role == Role::Sender && canceller == job_author)
}

/// A bare, portable file name for a shared file: the component rules from
/// [`check_name_component`], no leading dot, at most 255 bytes.
pub fn check_file_name(name: &str) -> Result<()> {
    if name.len() > 255 || name.starts_with('.') {
        return Err(Error::policy(format!("bad file name {name:?}")));
    }
    check_name_component(name).map_err(|why| Error::policy(format!("bad file name {name:?}: {why}")))
}

fn ext(name: &str) -> String {
    name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default()
}

pub fn check_file(subkind: ContentType, name: &str, mime: &str, body: &[u8]) -> Result<()> {
    check_file_name(name)?;
    let e = ext(name);
    let ok = match subkind {
        ContentType::Py => e == "py" && mime == "text/x-python" && std::str::from_utf8(body).is_ok(),
        ContentType::Md => {
            matches!(e.as_str(), "md" | "markdown")
                && mime == "text/markdown"
                && crate::validate::markdown::validate_markdown(body).is_ok()
        }
        ContentType::Zip => {
            if !(e == "zip" && mime == "application/zip" && sniff::is_zip(body)) {
                false
            } else {
                // The full archive rules from protocol §9.
                crate::validate::zip::inspect_zip(body, &Default::default())?;
                true
            }
        }
        ContentType::Image => {
            let sniffed = sniff::image_mime(body);
            let ext_ok = match mime {
                "image/png" => e == "png",
                "image/jpeg" => e == "jpg" || e == "jpeg",
                "image/webp" => e == "webp",
                _ => false,
            };
            ext_ok && sniffed == Some(mime)
        }
        ContentType::Text | ContentType::Sh => false,
    };
    if !ok {
        return Err(Error::policy(format!(
            "file {name:?} ({mime}) does not match declared type {}",
            subkind.as_str()
        )));
    }
    Ok(())
}

/// PEP 503 normalization: lowercase, runs of `-_.` become `-`.
pub fn normalize_package(name: &str) -> Result<String> {
    let valid = !name.is_empty()
        && name.len() <= 100
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if !valid {
        return Err(Error::invalid("package name", name));
    }
    let mut out = String::with_capacity(name.len());
    let mut prev_sep = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !prev_sep {
                out.push('-');
            }
            prev_sep = true;
        } else {
            out.push(c.to_ascii_lowercase());
            prev_sep = false;
        }
    }
    Ok(out)
}

/// Longest package allowlist entry (name and version specifier).
pub const MAX_ALLOWLIST_ENTRY_LEN: usize = 256;

/// A package allowlist entry: a name, and optionally the versions jobs may
/// run against, such as `cugrid==0.1.0` or `numpy>=1.26,<3`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowedPackage {
    /// PEP 503 normalized; what a job's `requirements` name.
    pub name: String,
    pub specifier: Option<SpecifierSet>,
}

impl AllowedPackage {
    /// Parse an entry as a person writes it: `pyPowerGEM`, `cugrid == 0.1.0`,
    /// `numpy>=1.26, <3`. Extras, markers and URLs are not accepted.
    pub fn parse(entry: &str) -> Result<AllowedPackage> {
        let bad = |why: &str| Err(Error::invalid("package", format!("{entry:?}: {why}")));
        let entry = entry.trim();
        if entry.len() > MAX_ALLOWLIST_ENTRY_LEN {
            return bad("too long");
        }
        let (name, rest) = entry.split_at(allowlist_name(entry).len());
        let Ok(name) = normalize_package(name) else { return bad("not a package name") };
        let rest = rest.trim_start();
        if rest.is_empty() {
            return Ok(AllowedPackage { name, specifier: None });
        }
        match rest.as_bytes()[0] {
            b'[' => return bad("extras are not supported; name the package alone"),
            b';' => return bad("environment markers are not supported"),
            b'@' => return bad("URLs are not supported; use a version specifier such as ==1.2.3"),
            b'=' | b'!' | b'<' | b'>' | b'~' => {}
            _ => return bad("a version specifier starts with an operator (==, >=, <, ...)"),
        }
        match SpecifierSet::parse(rest) {
            Ok(specifier) => Ok(AllowedPackage { name, specifier: Some(specifier) }),
            Err(why) => bad(&why),
        }
    }

    /// The one spelling the manifest records: the normalized name, then the
    /// clauses with no spaces. A name alone is just the normalized name.
    pub fn canonical(&self) -> String {
        match &self.specifier {
            Some(s) => format!("{}{s}", self.name),
            None => self.name.clone(),
        }
    }

    /// Whether an installed `version` is one this entry allows.
    pub fn allows_version(&self, version: &str) -> bool {
        self.specifier.as_ref().is_none_or(|s| s.matches(version))
    }
}

/// An allowlist entry in its canonical spelling (see [`AllowedPackage`]).
pub fn canonical_allowlist_entry(entry: &str) -> Result<String> {
    Ok(AllowedPackage::parse(entry)?.canonical())
}

/// The package name part of an allowlist entry, without any version
/// specifier: `cugrid` for `cugrid==0.1.0`.
pub fn allowlist_name(entry: &str) -> &str {
    let end = entry
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .unwrap_or(entry.len());
    &entry[..end]
}

/// Checks a runner must pass before running a job.
pub fn check_job(m: &Manifest, job: &JobSpec) -> Result<()> {
    require_execute(m)?;
    let limits = m.job_limits.as_ref().expect("execute manifests carry job_limits");
    require_kind(m, job.kind())?;
    check_file_name(&job.filename)?;
    match job.kind() {
        JobKind::Python => {
            if ext(&job.filename) != "py" {
                return Err(Error::policy("job entry file must end in .py"));
            }
            if job.code.len() > MAX_CODE_BYTES {
                return Err(Error::policy("job code exceeds 1 MiB"));
            }
        }
        JobKind::Shell => {
            if job.code.len() > MAX_SHELL_CODE_BYTES {
                return Err(Error::policy("a shell job's script exceeds 64 KiB"));
            }
            if !job.requirements.is_empty() {
                return Err(Error::policy(
                    "requirements are for python jobs; a shell job uses the sandbox's tools",
                ));
            }
        }
    }
    if let Some(c) = &job.cwd {
        check_cwd(c)?;
    }
    if let Some(t) = &job.tree {
        t.validate()?;
        if !job.files.contains(t) {
            return Err(Error::policy("the job's tree must be one of its files"));
        }
    }
    if job.runtime != limits.runtime {
        return Err(Error::policy(format!(
            "runtime {} not offered (session runtime is {})",
            job.runtime, limits.runtime
        )));
    }
    if job.timeout_s == 0 || job.timeout_s > limits.timeout_s {
        return Err(Error::policy(format!("timeout must be 1..={} s", limits.timeout_s)));
    }
    if let Some(mem) = job.memory_mb {
        if mem == 0 || mem > limits.memory_mb {
            return Err(Error::policy(format!("memory must be 1..={} MB", limits.memory_mb)));
        }
    }
    if job.files.len() > MAX_JOB_FILES {
        return Err(Error::policy("at most 32 input files"));
    }
    for f in &job.files {
        f.validate()?;
    }
    if let Some(p) = &job.progress_file {
        check_progress_file(p)?;
    }
    for r in &job.requirements {
        let n = normalize_package(r).map_err(|_| {
            Error::policy(format!(
                "requirement {r:?}: requirements name packages only; a version comes from the session's allowlist"
            ))
        })?;
        if !limits.allows_package(&n) {
            return Err(Error::policy(format!("{r} not in allowlist")));
        }
    }
    match &job.target {
        Target::Runner { name, .. } if !is_runner_token(name) => {
            Err(Error::policy(format!("bad runner name {name:?}")))
        }
        Target::Labels { labels }
            if labels.is_empty() || labels.len() > 16 || !labels.iter().all(|l| is_runner_token(l)) =>
        {
            Err(Error::policy("labels target needs 1..=16 valid labels"))
        }
        _ => Ok(()),
    }
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Shape checks on the environment a result reports: short printable
/// strings, and package names in normalized form.
pub fn check_env(env: &JobEnv) -> Result<()> {
    let short = |what: &str, s: &str, max: usize| {
        if s.is_empty() || s.chars().count() > max || s.chars().any(char::is_control) {
            Err(Error::policy(format!("env {what} must be 1 to {max} printable characters")))
        } else {
            Ok(())
        }
    };
    short("python", &env.python, 32)?;
    short("airlox", &env.airlox, 32)?;
    short("interpreter", &env.interpreter, 128)?;
    if env.packages.len() > MAX_ENV_PACKAGES {
        return Err(Error::policy(format!("env lists at most {MAX_ENV_PACKAGES} packages")));
    }
    for (name, version) in &env.packages {
        if normalize_package(name).ok().as_deref() != Some(name.as_str()) {
            return Err(Error::policy(format!("env package {name:?} is not a normalized name")));
        }
        short("package version", version, 64)?;
    }
    if let Some(kinds) = &env.kinds {
        if kinds.is_empty() || kinds.len() > 2 {
            return Err(Error::policy("env kinds must list 1 or 2 kinds"));
        }
    }
    if let Some(sh) = &env.shell {
        short("shell", sh, 32)?;
    }
    if let Some(t) = &env.tree {
        if let Some(head) = &t.head {
            if head.is_empty() || head.len() > 64 || !head.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::policy("env tree head must be 1 to 64 hex digits"));
            }
        }
        if !is_hex64(&t.sha256) {
            return Err(Error::policy("env tree sha256 must be 64 lowercase hex characters"));
        }
    }
    Ok(())
}

/// Shape checks on a job result.
pub fn check_result(r: &JobResult) -> Result<()> {
    r.job.validate()?;
    if r.stdout.len() > MAX_STDIO_BYTES || r.stderr.len() > MAX_STDIO_BYTES {
        return Err(Error::policy("stdout and stderr are limited to 1 MiB each"));
    }
    if !is_hex64(&r.code_sha256) || !is_hex64(&r.input_sha256) {
        return Err(Error::policy("hashes must be 64 lowercase hex characters"));
    }
    if r.out_files.len() > MAX_OUT_FILES {
        return Err(Error::policy("at most 64 output files"));
    }
    for f in &r.out_files {
        check_file_name(&f.name)?;
        f.item.validate()?;
    }
    if r.reason.as_ref().is_some_and(|s| s.chars().count() > MAX_REASON_CHARS) {
        return Err(Error::policy("reason too long"));
    }
    if let Some(env) = &r.env {
        check_env(env)?;
    }
    let consistent = match r.status {
        JobStatus::Completed => r.exit_code.is_some(),
        JobStatus::Refused | JobStatus::TimedOut | JobStatus::Cancelled => r.exit_code.is_none(),
        JobStatus::Failed => true,
    };
    if !consistent {
        return Err(Error::policy("status and exit_code disagree"));
    }
    if matches!(r.status, JobStatus::Refused | JobStatus::Failed) && r.reason.is_none() {
        return Err(Error::policy("refused and failed results need a reason"));
    }
    Ok(())
}

/// A result counts only from a runner the owner approved, when the session
/// requires approval. `approved` lists the runners with a verified
/// `runner_approve` event and no `runner_reject` (a rejection is final);
/// `None` means the session does not require approval.
pub fn check_result_author(approved: Option<&[PublicKey]>, result_author: PublicKey) -> Result<()> {
    match approved {
        Some(list) if !list.contains(&result_author) => {
            Err(Error::policy("result is not from a runner the owner approved"))
        }
        _ => Ok(()),
    }
}

/// Whether a runner with this key and these labels may take a job aimed at
/// `target`. The relay routes with it; the runner re-checks the signed target.
pub fn target_matches(target: &Target, runner: PublicKey, labels: &[String]) -> bool {
    match target {
        Target::Runner { participant_pub, .. } => *participant_pub == runner,
        Target::Labels { labels: want } => want.iter().all(|l| labels.contains(l)),
        Target::Any => true,
    }
}

/// Bind a result to the job it claims to answer. `job_ref` must already have
/// been matched against the fetched job item ([`ItemRef::matches`]). A job
/// aimed at one runner only accepts a result from that runner's key.
pub fn check_result_matches_job(
    job_ref: &ItemRef,
    job: &JobSpec,
    result_author: PublicKey,
    r: &JobResult,
) -> Result<()> {
    if &r.job != job_ref {
        return Err(Error::policy("result references a different job"));
    }
    if let Target::Runner { participant_pub, .. } = &job.target {
        if *participant_pub != result_author {
            return Err(Error::policy("result is not from the runner the job targeted"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::issue_cert;
    use crate::encoding::{b64e, canonical_json};
    use crate::item::{seal, NewItem};
    use crate::keys::Keypair;
    use crate::payload::OutFile;
    use crate::session::{JobLimits, SessionParams, SessionSecrets};

    fn secrets() -> SessionSecrets {
        SessionSecrets::from_owner_seed([1u8; 32])
    }

    fn manifest(mode: Mode) -> Manifest {
        let limits = JobLimits { packages: vec!["numpy".into(), "pandas".into()], ..Default::default() };
        secrets()
            .manifest(&SessionParams {
                mode,
                created_at_ms: 1000,
                ttl_ms: Some(1000),
                allowed_types: vec![ContentType::Text, ContentType::Py, ContentType::Md, ContentType::Zip],
                max_item_bytes: 1024 * 1024,
                job_limits: (mode == Mode::Execute).then_some(limits),
                insecure_http_host: None,
            })
            .unwrap()
            .manifest
    }

    fn iref(byte: u8) -> ItemRef {
        ItemRef { id: b64e(&[byte; 16]), blob_sha256: b64e(&[byte; 32]) }
    }

    fn job() -> JobSpec {
        JobSpec {
            kind: None,
            cwd: None,
            tree: None,
            fresh: false,
            filename: "summarize.py".into(),
            code: "print(1)".into(),
            runtime: "python3.12".into(),
            timeout_s: 30,
            memory_mb: None,
            files: vec![iref(1)],
            requirements: vec!["Pandas".into()],
            target: Target::Any,
            progress_file: None,
        }
    }

    fn result() -> JobResult {
        JobResult {
            job: iref(3),
            exit_code: Some(0),
            status: JobStatus::Completed,
            reason: None,
            wall_ms: 10,
            peak_mem_mb: 1,
            stdout: "ok".into(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            out_files: vec![OutFile { name: "chart.png".into(), size: 1, item: iref(4) }],
            code_sha256: "a".repeat(64),
            input_sha256: "b".repeat(64),
            env: None,
        }
    }

    fn header(m: &Manifest, kind: ItemKind, sub: Option<ContentType>, size: usize) -> ItemHeader {
        seal(
            &[0u8; 32],
            &Keypair::from_seed(&[2u8; 32]),
            NewItem {
                id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
                session_id: m.session_id.clone(),
                kind,
                subkind: sub,
                created_at_ms: 1500,
                refs: vec![],
            },
            &vec![0u8; size],
        )
        .unwrap()
        .envelope
        .header
    }

    #[test]
    fn recipients() {
        let a = crate::keys::Keypair::from_seed(&[1u8; 32]).public();
        let b = crate::keys::Keypair::from_seed(&[2u8; 32]).public();
        assert!(check_recipients(None).is_ok());
        assert!(check_recipients(Some(&[a, b])).is_ok());
        assert!(check_recipients(Some(&[])).is_err());
        assert!(check_recipients(Some(&[a, a])).is_err());
        assert!(check_recipients(Some(&vec![a; MAX_RECIPIENTS + 1])).is_err());
    }

    #[test]
    fn author_role_is_bound_to_cert() {
        let m = manifest(Mode::Execute);
        let h = header(&m, ItemKind::Text, None, 1);
        let author = Keypair::from_seed(&[2u8; 32]).public();
        let other = Keypair::from_seed(&[9u8; 32]).public();
        let s = secrets();
        let good = issue_cert(&s.role_keypair(Role::Sender), &m.session_id, Role::Sender, author, 1).unwrap();
        assert_eq!(author_role(&m, &good, &h).unwrap(), Role::Sender);
        // An owner cert for someone else cannot lend its role to this author.
        let theirs = issue_cert(&s.owner(), &m.session_id, Role::Owner, other, 1).unwrap();
        assert!(author_role(&m, &theirs, &h).is_err());
    }

    #[test]
    fn roles_and_types() {
        let m = manifest(Mode::Execute);
        let job_h = header(&m, ItemKind::Job, Some(ContentType::Py), 10);
        check_header(&m, Role::Sender, &job_h).unwrap();
        assert!(check_header(&m, Role::Observer, &job_h).is_err());
        assert!(check_header(&m, Role::Runner, &job_h).is_err());
        let big = header(&m, ItemKind::Text, None, 2 * 1024 * 1024);
        assert!(check_header(&m, Role::Sender, &big).is_err());
        let relay = manifest(Mode::Relay);
        let job_r = header(&relay, ItemKind::Job, Some(ContentType::Py), 10);
        assert!(check_header(&relay, Role::Sender, &job_r).is_err());
        let file_r = header(&relay, ItemKind::File, Some(ContentType::Md), 10);
        assert!(check_header(&relay, Role::Runner, &file_r).is_err(), "runners are execute-only");
    }

    #[test]
    fn job_limits_enforced() {
        let m = manifest(Mode::Execute);
        check_job(&m, &job()).unwrap();
        let mut j = job();
        j.requirements = vec!["scipy".into()];
        assert!(check_job(&m, &j).unwrap_err().to_string().contains("scipy not in allowlist"));
        let mut j = job();
        j.timeout_s = 31;
        assert!(check_job(&m, &j).is_err());
        let mut j = job();
        j.filename = "../x.py".into();
        assert!(check_job(&m, &j).is_err());
        let mut j = job();
        j.runtime = "python3.11".into();
        assert!(check_job(&m, &j).is_err());
        let mut j = job();
        j.files[0].blob_sha256 = "short".into();
        assert!(check_job(&m, &j).is_err());
    }

    fn manifest_with(limits: JobLimits) -> Manifest {
        secrets()
            .manifest(&SessionParams {
                mode: Mode::Execute,
                created_at_ms: 1000,
                ttl_ms: Some(1000),
                allowed_types: vec![ContentType::Text, ContentType::Py, ContentType::Zip],
                max_item_bytes: 1024 * 1024,
                job_limits: Some(limits),
                insecure_http_host: None,
            })
            .unwrap()
            .manifest
    }

    fn shell_job() -> JobSpec {
        JobSpec {
            kind: Some(JobKind::Shell),
            filename: "job.sh".into(),
            code: "pytest -x tests/\n".into(),
            requirements: vec![],
            ..job()
        }
    }

    #[test]
    fn shell_jobs_need_a_session_that_allows_them() {
        // Without `kinds`, a session runs python only, as before.
        let m = manifest(Mode::Execute);
        assert!(check_job(&m, &shell_job()).unwrap_err().to_string().contains("shell jobs are not allowed"));
        let sh = header(&m, ItemKind::Job, Some(ContentType::Sh), 10);
        assert!(check_header(&m, Role::Sender, &sh).is_err());

        let both = manifest_with(JobLimits {
            kinds: Some(vec![JobKind::Python, JobKind::Shell]),
            ..Default::default()
        });
        check_job(&both, &shell_job()).unwrap();
        check_job(&both, &JobSpec { requirements: vec![], ..job() }).unwrap();
        check_header(&both, Role::Sender, &header(&both, ItemKind::Job, Some(ContentType::Sh), 10)).unwrap();

        let shell_only = manifest_with(JobLimits { kinds: Some(vec![JobKind::Shell]), ..Default::default() });
        assert!(check_job(&shell_only, &JobSpec { requirements: vec![], ..job() }).is_err());
        let py = header(&shell_only, ItemKind::Job, Some(ContentType::Py), 10);
        assert!(check_header(&shell_only, Role::Sender, &py).is_err());

        let mut j = shell_job();
        j.code = "x".repeat(MAX_SHELL_CODE_BYTES + 1);
        assert!(check_job(&both, &j).is_err());
        let mut j = shell_job();
        j.requirements = vec!["numpy".into()];
        assert!(check_job(&both, &j).is_err(), "shell jobs install nothing");
        // A shell job's name is for display; any portable name does.
        let mut j = shell_job();
        j.filename = "make".into();
        check_job(&both, &j).unwrap();
    }

    #[test]
    fn cwd_and_tree_are_checked() {
        let m = manifest_with(JobLimits { kinds: Some(vec![JobKind::Shell]), ..Default::default() });
        let mut j = shell_job();
        j.cwd = Some("services/api".into());
        j.tree = Some(iref(1));
        check_job(&m, &j).unwrap();
        for bad in ["../x", "/abs", "a/./b", ".git", ""] {
            j.cwd = Some(bad.into());
            assert!(check_job(&m, &j).is_err(), "{bad:?}");
        }
        j.cwd = None;
        j.tree = Some(iref(9));
        assert!(check_job(&m, &j).unwrap_err().to_string().contains("one of its files"));
    }

    #[test]
    fn job_canonical_form_is_unchanged_without_the_new_fields() {
        let json = String::from_utf8(canonical_json(&job()).unwrap()).unwrap();
        for f in ["\"kind\"", "\"cwd\"", "\"tree\"", "\"fresh\""] {
            assert!(!json.contains(f), "{json}");
        }
        let j: JobSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(j.kind(), JobKind::Python);
        let sh = String::from_utf8(canonical_json(&shell_job()).unwrap()).unwrap();
        assert!(sh.contains(r#""kind":"shell""#), "{sh}");
    }

    #[test]
    fn manifests_keep_their_form_unless_kinds_or_workspace_are_set() {
        let m = manifest(Mode::Execute);
        let json = String::from_utf8(canonical_json(&m).unwrap()).unwrap();
        assert!(!json.contains("kinds") && !json.contains("workspace"), "{json}");
        let m = manifest_with(JobLimits {
            kinds: Some(vec![JobKind::Python, JobKind::Shell]),
            workspace: true,
            ..Default::default()
        });
        let json = String::from_utf8(canonical_json(&m).unwrap()).unwrap();
        assert!(
            json.contains(r#""kinds":["python","shell"]"#) && json.contains(r#""workspace":true"#),
            "{json}"
        );
        for kinds in [vec![], vec![JobKind::Shell, JobKind::Shell]] {
            let r = secrets().manifest(&SessionParams {
                mode: Mode::Execute,
                created_at_ms: 1000,
                ttl_ms: Some(1000),
                allowed_types: vec![ContentType::Py],
                max_item_bytes: 1024,
                job_limits: Some(JobLimits { kinds: Some(kinds), ..Default::default() }),
                insecure_http_host: None,
            });
            assert!(r.is_err());
        }
        let r = secrets().manifest(&SessionParams {
            mode: Mode::Execute,
            created_at_ms: 1000,
            ttl_ms: Some(1000),
            allowed_types: vec![ContentType::Py, ContentType::Sh],
            max_item_bytes: 1024,
            job_limits: Some(JobLimits::default()),
            insecure_http_host: None,
        });
        assert!(r.is_err(), "sh is not a content type");
    }

    #[test]
    fn progress_chunks() {
        use crate::payload::Stream;
        let beat = JobProgress {
            job: iref(1),
            elapsed_ms: 5,
            tail: None,
            tail_truncated: false,
            stream: None,
            offset: None,
            data: None,
            truncated: false,
        };
        check_progress(&beat).unwrap();
        let json = String::from_utf8(canonical_json(&beat).unwrap()).unwrap();
        assert!(!json.contains("stream") && !json.contains(",\"truncated\""), "{json}");
        let chunk = JobProgress {
            stream: Some(Stream::Stdout),
            offset: Some(0),
            data: Some("collected 212 items\n".into()),
            ..beat.clone()
        };
        check_progress(&chunk).unwrap();
        let json = String::from_utf8(canonical_json(&chunk).unwrap()).unwrap();
        assert!(json.contains(r#""stream":"stdout""#), "{json}");
        let mut bad = chunk.clone();
        bad.data = Some("x".repeat(MAX_CHUNK_BYTES + 1));
        assert!(check_progress(&bad).is_err());
        let mut bad = chunk.clone();
        bad.offset = None;
        assert!(check_progress(&bad).is_err());
        let mut bad = chunk.clone();
        bad.tail = Some("x".into());
        assert!(check_progress(&bad).is_err());
        let last = JobProgress { data: Some(String::new()), truncated: true, ..chunk };
        check_progress(&last).unwrap();
    }

    #[test]
    fn env_kinds_shell_and_tree() {
        use crate::cert::SandboxKind;
        use crate::payload::TreeInfo;
        let mut r = result();
        r.env = Some(JobEnv {
            python: "3.12.4".into(),
            packages: Default::default(),
            airlox: "0.2.0".into(),
            sandbox: SandboxKind::Docker,
            interpreter: "docker:ci@sha256:0123456789ab".into(),
            kinds: Some(vec![JobKind::Python, JobKind::Shell]),
            shell: Some("sh".into()),
            tree: Some(TreeInfo {
                head: Some("ab12".into()),
                dirty: true,
                count: 412,
                sha256: "c".repeat(64),
            }),
        });
        check_result(&r).unwrap();
        let mut bad = r.clone();
        bad.env.as_mut().unwrap().tree.as_mut().unwrap().head = Some("not hex".into());
        assert!(check_result(&bad).is_err());
        let mut bad = r;
        bad.env.as_mut().unwrap().kinds = Some(vec![]);
        assert!(check_result(&bad).is_err());
    }

    #[test]
    fn result_checks() {
        check_result(&result()).unwrap();
        let mut r = result();
        r.out_files[0].name = "../../../.bashrc".into();
        assert!(check_result(&r).is_err());
        let mut r = result();
        r.stdout = "x".repeat(MAX_STDIO_BYTES + 1);
        assert!(check_result(&r).is_err());
        let mut r = result();
        r.code_sha256 = "zz".into();
        assert!(check_result(&r).is_err());
        let mut r = result();
        r.status = JobStatus::Refused;
        r.reason = Some("nope".into());
        assert!(check_result(&r).is_err(), "refused with an exit code");
        r.exit_code = None;
        check_result(&r).unwrap();
    }

    #[test]
    fn a_result_reports_its_environment_in_the_signed_meta_only_when_it_has_one() {
        use crate::cert::SandboxKind;
        use crate::payload::JobEnv;
        // No env: the canonical form is what it was before the field existed.
        let plain = result();
        let json = String::from_utf8(canonical_json(&plain).unwrap()).unwrap();
        assert!(!json.contains("\"env\""), "{json}");
        let old: JobResult = serde_json::from_str(&json).unwrap();
        assert_eq!(old, plain);

        let mut r = result();
        r.env = Some(JobEnv {
            python: "3.12.4".into(),
            packages: [("cugrid".to_string(), "0.1.0".to_string()), ("numpy".into(), "2.1.0".into())].into(),
            airlox: "0.1.2".into(),
            sandbox: SandboxKind::Process,
            interpreter: "--python".into(),
            kinds: None,
            shell: None,
            tree: None,
        });
        check_result(&r).unwrap();
        let json = String::from_utf8(canonical_json(&r).unwrap()).unwrap();
        assert!(
            json.contains(r#""env":{"airlox":"0.1.2","interpreter":"--python","packages":{"cugrid":"0.1.0","numpy":"2.1.0"},"python":"3.12.4","sandbox":"process"}"#),
            "{json}"
        );
        assert_eq!(serde_json::from_str::<JobResult>(&json).unwrap(), r);
        // The env is signed with the rest: an unknown field is refused.
        let extra = json.replace(r#""python":"3.12.4""#, r#""python":"3.12.4","executable":"C:\\Users\\x""#);
        assert!(serde_json::from_str::<JobResult>(&extra).is_err());

        let mut bad = r.clone();
        bad.env.as_mut().unwrap().python = String::new();
        assert!(check_result(&bad).is_err());
        let mut bad = r.clone();
        bad.env.as_mut().unwrap().interpreter = "a\nb".into();
        assert!(check_result(&bad).is_err());
        let mut bad = r.clone();
        bad.env.as_mut().unwrap().packages.insert("Not_Normal".into(), "1".into());
        assert!(check_result(&bad).is_err());
        let mut bad = r;
        bad.env.as_mut().unwrap().packages =
            (0..=MAX_ENV_PACKAGES).map(|i| (format!("p{i}"), "1".into())).collect();
        assert!(check_result(&bad).is_err());
    }

    #[test]
    fn allowlist_entries_have_one_canonical_spelling() {
        let canon = |s: &str| canonical_allowlist_entry(s).unwrap();
        // Names alone are as they always were.
        assert_eq!(canon("pyPowerGEM"), "pypowergem");
        assert_eq!(canon("Foo__Bar.baz"), "foo-bar-baz");
        assert_eq!(canon("cugrid==0.1.0"), "cugrid==0.1.0");
        assert_eq!(canon(" CuGrid >= 0.1.0.dev0 "), "cugrid>=0.1.0.dev0");
        assert_eq!(canon("numpy>=1.26, <3"), "numpy>=1.26,<3");
        assert_eq!(canon("py_power.gem~=2.1"), "py-power-gem~=2.1");
        let p = AllowedPackage::parse("numpy>=1.26,<3").unwrap();
        assert_eq!(p.name, "numpy");
        assert!(p.allows_version("2.2.1") && !p.allows_version("3.0") && !p.allows_version("1.0"));
        assert!(AllowedPackage::parse("numpy").unwrap().allows_version("anything"));
        for bad in [
            "numpy[extra]>=1",
            "numpy; python_version<'3.13'",
            "numpy @ https://example.com/numpy.whl",
            "numpy 1.0",
            "numpy>=",
            "numpy=>1",
            "numpy>=1.x",
            ">=1.0",
            "==1.0",
            "numpy>=1,<",
            "",
        ] {
            assert!(canonical_allowlist_entry(bad).is_err(), "{bad:?}");
        }
        assert!(canonical_allowlist_entry(&format!("numpy=={}", "1".repeat(300))).is_err());
        assert_eq!(allowlist_name("cugrid==0.1.0"), "cugrid");
        assert_eq!(allowlist_name("py-power.gem>=1,<2"), "py-power.gem");
        assert_eq!(allowlist_name("numpy"), "numpy");
    }

    #[test]
    fn requirements_name_allowlisted_packages_whatever_their_pins() {
        let limits = JobLimits {
            packages: vec!["cugrid==0.1.0".into(), "numpy>=1.26,<3".into(), "pandas".into()],
            ..Default::default()
        };
        let m = secrets()
            .manifest(&SessionParams {
                mode: Mode::Execute,
                created_at_ms: 1000,
                ttl_ms: Some(1000),
                allowed_types: vec![ContentType::Py],
                max_item_bytes: 1024 * 1024,
                job_limits: Some(limits),
                insecure_http_host: None,
            })
            .unwrap()
            .manifest;
        let mut j = job();
        j.requirements = vec!["CuGrid".into(), "numpy".into(), "pandas".into()];
        check_job(&m, &j).unwrap();
        // A name that merely starts with an allowlisted one is another package.
        j.requirements = vec!["cugrid-extra".into()];
        assert!(check_job(&m, &j).unwrap_err().to_string().contains("not in allowlist"));
        // Versions belong to the allowlist, not to the job.
        j.requirements = vec!["cugrid==0.1.0".into()];
        let e = check_job(&m, &j).unwrap_err().to_string();
        assert!(e.contains("requirements name packages only"), "{e}");
    }

    #[test]
    fn result_binds_to_job_and_runner() {
        let runner = Keypair::from_seed(&[5u8; 32]).public();
        let intruder = Keypair::from_seed(&[6u8; 32]).public();
        let mut j = job();
        j.target = Target::Runner { participant_pub: runner, name: "runner-01".into() };
        let r = result();
        check_result_matches_job(&iref(3), &j, runner, &r).unwrap();
        assert!(check_result_matches_job(&iref(3), &j, intruder, &r).is_err());
        assert!(check_result_matches_job(&iref(7), &j, runner, &r).is_err());
        check_result_author(None, intruder).unwrap();
        check_result_author(Some(&[runner]), runner).unwrap();
        assert!(check_result_author(Some(&[runner]), intruder).is_err());
        assert!(check_result_author(Some(&[]), runner).is_err());
    }

    #[test]
    fn targets() {
        let me = Keypair::from_seed(&[5u8; 32]).public();
        let other = Keypair::from_seed(&[6u8; 32]).public();
        let labels = vec!["cpu".to_string(), "py3.12".to_string()];
        assert!(target_matches(&Target::Any, me, &[]));
        assert!(target_matches(&Target::Labels { labels: vec!["cpu".into()] }, me, &labels));
        assert!(!target_matches(&Target::Labels { labels: vec!["gpu".into()] }, me, &labels));
        assert!(target_matches(&Target::Runner { participant_pub: me, name: "r".into() }, me, &[]));
        assert!(!target_matches(&Target::Runner { participant_pub: other, name: "r".into() }, me, &[]));
    }

    #[test]
    fn cancel_rules() {
        let a = Keypair::from_seed(&[1u8; 32]).public();
        let b = Keypair::from_seed(&[2u8; 32]).public();
        assert!(may_cancel(Role::Sender, a, a));
        assert!(!may_cancel(Role::Sender, a, b));
        assert!(may_cancel(Role::Owner, a, b));
        assert!(!may_cancel(Role::Runner, a, a));
    }

    #[test]
    fn package_normalization() {
        assert_eq!(normalize_package("Foo__Bar.baz").unwrap(), "foo-bar-baz");
        assert!(normalize_package("-x").is_err());
        assert!(normalize_package("x y").is_err());
    }

    #[test]
    fn file_checks() {
        check_file(ContentType::Md, "README.md", "text/markdown", b"# hi").unwrap();
        assert!(check_file(ContentType::Md, "README.md", "text/markdown", &[0xff, 0xfe]).is_err());
        assert!(check_file(ContentType::Image, "a.png", "image/png", b"GIF89a").is_err());
        assert!(check_file(ContentType::Py, "a/b.py", "text/x-python", b"").is_err());
        assert!(check_file(ContentType::Py, "a.py:evil", "text/x-python", b"").is_err());
        assert!(check_file(ContentType::Py, ".bashrc.py", "text/x-python", b"").is_err());
        assert!(check_file(ContentType::Py, "x\u{202e}gnp.py", "text/x-python", b"").is_err());
    }

    #[test]
    fn zip_payloads_get_full_archive_rules() {
        use std::io::Write;
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        w.start_file("../../escape.txt", zip::write::SimpleFileOptions::default()).unwrap();
        w.write_all(b"x").unwrap();
        let evil = w.finish().unwrap().into_inner();
        assert!(check_file(ContentType::Zip, "data.zip", "application/zip", &evil).is_err());
    }
}
