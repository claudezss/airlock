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
    Event, JobResult, JobSpec, JobStatus, Meta, Payload, Target, MAX_OUT_FILES, MAX_REASON_CHARS,
    MAX_STDIO_BYTES,
};
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
        Role::Runner => matches!(kind, Result | File),
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
    if h.created_at_ms < m.created_at_ms || h.created_at_ms >= m.expires_at_ms {
        return Err(Error::policy("item timestamp is outside the session lifetime"));
    }
    match h.kind {
        ItemKind::Text => require_type(m, ContentType::Text)?,
        ItemKind::File => require_type(m, h.subkind.expect("validated"))?,
        ItemKind::Job => {
            require_execute(m)?;
            require_type(m, ContentType::Py)?;
        }
        ItemKind::Result => require_execute(m)?,
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
        Meta::Text { .. } => Ok(()),
        Meta::File { name, mime } => check_file(h.subkind.expect("validated"), name, mime, &p.body),
        Meta::Job(spec) => check_job(m, spec),
        Meta::Result(r) => check_result(r),
        Meta::Event(e) => check_event(author_role, e),
    }
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
        ContentType::Text => false,
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

/// Checks a runner must pass before running a job.
pub fn check_job(m: &Manifest, job: &JobSpec) -> Result<()> {
    require_execute(m)?;
    let limits = m.job_limits.as_ref().expect("execute manifests carry job_limits");
    check_file_name(&job.filename)?;
    if ext(&job.filename) != "py" {
        return Err(Error::policy("job entry file must end in .py"));
    }
    if job.code.len() > MAX_CODE_BYTES {
        return Err(Error::policy("job code exceeds 1 MiB"));
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
    for r in &job.requirements {
        let n = normalize_package(r)?;
        if !limits.packages.contains(&n) {
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
    use crate::encoding::b64e;
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
                ttl_ms: 1000,
                allowed_types: vec![ContentType::Text, ContentType::Py, ContentType::Md, ContentType::Zip],
                max_item_bytes: 1024 * 1024,
                job_limits: (mode == Mode::Execute).then_some(limits),
            })
            .unwrap()
            .manifest
    }

    fn iref(byte: u8) -> ItemRef {
        ItemRef { id: b64e(&[byte; 16]), blob_sha256: b64e(&[byte; 32]) }
    }

    fn job() -> JobSpec {
        JobSpec {
            filename: "summarize.py".into(),
            code: "print(1)".into(),
            runtime: "python3.12".into(),
            timeout_s: 30,
            memory_mb: None,
            files: vec![iref(1)],
            requirements: vec!["Pandas".into()],
            target: Target::Any,
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
