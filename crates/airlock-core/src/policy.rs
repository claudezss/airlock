//! Policy checks.
//!
//! Two layers, because the server never sees plaintext:
//! - [`check_header`] runs anywhere, including the server.
//! - [`check_payload`] and [`check_job`] run on clients and runners after decryption.

use crate::cert::is_runner_token;
use crate::item::{is_item_id, ItemHeader, ItemKind};
use crate::payload::{Event, JobSpec, Meta, Payload, Target};
use crate::session::{ContentType, Manifest, Mode, Role};
use crate::validate::sniff;
use crate::{Error, Result};

pub const MAX_CODE_BYTES: usize = 1024 * 1024;
pub const MAX_JOB_FILES: usize = 32;

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

/// Server-enforceable checks on a header whose author holds `author_role`.
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
        Meta::Text { .. } | Meta::Result(_) => Ok(()),
        Meta::File { name, mime } => check_file(h.subkind.expect("validated"), name, mime, &p.body),
        Meta::Job(spec) => check_job(m, spec),
        Meta::Event(e) => match (author_role, e) {
            (Role::Owner, _) => Ok(()),
            (Role::Sender, Event::JobCancel { .. }) => Ok(()),
            _ => Err(Error::policy("only the owner may post this event")),
        },
    }
}

/// A bare file name: no separators, no traversal, at most 255 bytes.
pub fn check_file_name(name: &str) -> Result<()> {
    let bad = name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.starts_with('.') && name.len() == 1
        || name.chars().any(|c| c == '/' || c == '\\' || c == '\0' || c.is_control());
    if bad {
        return Err(Error::policy(format!("bad file name {name:?}")));
    }
    Ok(())
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
        ContentType::Zip => e == "zip" && mime == "application/zip" && sniff::is_zip(body),
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
    if job.files.len() > MAX_JOB_FILES || !job.files.iter().all(|f| is_item_id(f)) {
        return Err(Error::policy("files must be up to 32 item ids"));
    }
    for r in &job.requirements {
        let n = normalize_package(r)?;
        if !limits.packages.contains(&n) {
            return Err(Error::policy(format!("{r} not in allowlist")));
        }
    }
    match &job.target {
        Target::Runner { name } if !is_runner_token(name) => {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{seal, NewItem};
    use crate::keys::Keypair;
    use crate::session::{JobLimits, SessionParams, SessionSecrets};

    fn manifest(mode: Mode) -> Manifest {
        let limits = JobLimits { packages: vec!["numpy".into(), "pandas".into()], ..Default::default() };
        SessionSecrets::from_owner_seed([1u8; 32])
            .manifest(&SessionParams {
                mode,
                created_at_ms: 1000,
                ttl_ms: 1000,
                allowed_types: vec![ContentType::Text, ContentType::Py, ContentType::Md],
                max_item_bytes: 1024,
                job_limits: (mode == Mode::Execute).then_some(limits),
            })
            .unwrap()
            .manifest
    }

    fn job() -> JobSpec {
        JobSpec {
            filename: "summarize.py".into(),
            code: "print(1)".into(),
            runtime: "python3.12".into(),
            timeout_s: 30,
            memory_mb: None,
            files: vec![],
            requirements: vec!["Pandas".into()],
            target: Target::Any,
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
    fn roles_and_types() {
        let m = manifest(Mode::Execute);
        let job_h = header(&m, ItemKind::Job, Some(ContentType::Py), 10);
        check_header(&m, Role::Sender, &job_h).unwrap();
        assert!(check_header(&m, Role::Observer, &job_h).is_err());
        assert!(check_header(&m, Role::Runner, &job_h).is_err());
        let zip_h = header(&m, ItemKind::File, Some(ContentType::Zip), 10);
        assert!(check_header(&m, Role::Sender, &zip_h).is_err());
        let big = header(&m, ItemKind::Text, None, 2000);
        assert!(check_header(&m, Role::Sender, &big).is_err());
        let relay = manifest(Mode::Relay);
        let job_r = header(&relay, ItemKind::Job, Some(ContentType::Py), 10);
        assert!(check_header(&relay, Role::Sender, &job_r).is_err());
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
    }
}
