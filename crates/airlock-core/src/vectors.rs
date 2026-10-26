//! Deterministic test vectors (`vectors/v1.json`).
//!
//! Every binding must reproduce the derived values and pass the verification
//! steps using only the inputs in the file. Regenerate with:
//!
//! ```text
//! cargo run -p airlock-core --example gen_vectors > crates/airlock-core/vectors/v1.json
//! ```

use serde_json::{json, Value};

use crate::cert::{issue_cert, sign_join, ClientKind, JoinRequest, RunnerInfo, SandboxKind};
use crate::encoding::{b64e, canonical_json};
use crate::invite::Invite;
use crate::item::{item_key, seal_with_nonce, ItemKind, NewItem};
use crate::keys::Keypair;
use crate::payload::{JobResult, JobSpec, JobStatus, OutFile, Payload, Target};
use crate::session::{ContentType, JobLimits, Mode, Role, SessionParams, SessionSecrets};
use crate::Result;

pub const BASE_URL: &str = "https://airlock.example";

/// (name, author, author role, kind, subkind, refs, payload, item id)
type ItemCase<'a> =
    (&'a str, &'a Keypair, Role, ItemKind, Option<ContentType>, Vec<String>, Payload, &'a str);

fn s(b: Vec<u8>) -> String {
    String::from_utf8(b).expect("utf-8")
}

pub fn generate() -> Result<Value> {
    let owner_seed: [u8; 32] = std::array::from_fn(|i| i as u8);
    let secrets = SessionSecrets::from_owner_seed(owner_seed);
    let params = SessionParams {
        mode: Mode::Execute,
        created_at_ms: 1_761_400_000_000,
        ttl_ms: 3_600_000,
        allowed_types: vec![
            ContentType::Text,
            ContentType::Py,
            ContentType::Md,
            ContentType::Zip,
            ContentType::Image,
        ],
        max_item_bytes: 26_214_400,
        job_limits: Some(JobLimits {
            packages: vec!["matplotlib".into(), "numpy".into(), "pandas".into()],
            ..JobLimits::default()
        }),
    };
    let signed = secrets.manifest(&params)?;
    let sid = signed.manifest.session_id.clone();
    let key = secrets.session_key();

    let participants = [
        (Role::Owner, [0x33u8; 32]),
        (Role::Sender, [0x11u8; 32]),
        (Role::Runner, [0x22u8; 32]),
        (Role::Observer, [0x44u8; 32]),
    ];
    let mut certs = Vec::new();
    for (role, seed) in &participants {
        let p = Keypair::from_seed(seed);
        let c = issue_cert(&secrets.role_keypair(*role), &sid, *role, p.public(), params.created_at_ms + 1)?;
        certs.push(json!({
            "role": role.as_str(),
            "participant_seed": b64e(seed),
            "participant_pub": p.public().to_b64(),
            "participant_fingerprint": p.public().fingerprint(),
            "canonical": s(canonical_json(&c.cert)?),
            "signed": c,
        }));
    }

    let runner_p = Keypair::from_seed(&participants[2].1);
    let runner_cert = issue_cert(
        &secrets.role_keypair(Role::Runner),
        &sid,
        Role::Runner,
        runner_p.public(),
        params.created_at_ms + 1,
    )?;
    let join = sign_join(
        &runner_p,
        JoinRequest {
            v: 1,
            session_id: sid.clone(),
            cert: runner_cert,
            display_name: "runner-01".into(),
            kind: ClientKind::Runner,
            runner: Some(RunnerInfo {
                name: "runner-01".into(),
                labels: vec!["cpu".into(), "py3.12".into()],
                host: "build-box".into(),
                sandbox: SandboxKind::Docker,
                network_unblocked: false,
            }),
            created_at_ms: params.created_at_ms + 2,
        },
    )?;

    let sender = Keypair::from_seed(&participants[1].1);
    let job_spec = JobSpec {
        filename: "summarize.py".into(),
        code: "print(sum(range(10)))\n".into(),
        runtime: "python3.12".into(),
        timeout_s: 30,
        memory_mb: None,
        files: vec!["AQEBAQEBAQEBAQEBAQEBAQ".into()],
        requirements: vec!["pandas".into()],
        target: Target::Runner { name: "runner-01".into() },
    };
    let result = JobResult {
        job_id: "AwMDAwMDAwMDAwMDAwMDAw".into(),
        exit_code: Some(0),
        status: JobStatus::Completed,
        reason: None,
        wall_ms: 1840,
        peak_mem_mb: 212,
        stdout: "45\n".into(),
        stderr: String::new(),
        stdout_truncated: false,
        stderr_truncated: false,
        out_files: vec![OutFile {
            name: "chart.png".into(),
            size: 38_912,
            item_id: "BAQEBAQEBAQEBAQEBAQEBA".into(),
        }],
        code_sha256: crate::encoding::hex(&crate::encoding::sha256(job_spec.code.as_bytes())),
        input_sha256: crate::encoding::hex(&crate::encoding::sha256(b"")),
    };
    let item_cases: Vec<ItemCase<'_>> = vec![
        (
            "text",
            &sender,
            Role::Sender,
            ItemKind::Text,
            None,
            vec![],
            Payload::text("Cleaned dataset attached."),
            "AAAAAAAAAAAAAAAAAAAAAA",
        ),
        (
            "markdown_file",
            &sender,
            Role::Sender,
            ItemKind::File,
            Some(ContentType::Md),
            vec![],
            Payload::file("README.md", "text/markdown", b"# Orders\n\nDeduplicated export.\n".to_vec()),
            "AQEBAQEBAQEBAQEBAQEBAQ",
        ),
        (
            "job",
            &sender,
            Role::Sender,
            ItemKind::Job,
            Some(ContentType::Py),
            vec!["AQEBAQEBAQEBAQEBAQEBAQ".into()],
            Payload::job(job_spec),
            "AwMDAwMDAwMDAwMDAwMDAw",
        ),
        (
            "result",
            &runner_p,
            Role::Runner,
            ItemKind::Result,
            None,
            vec!["AwMDAwMDAwMDAwMDAwMDAw".into()],
            Payload::result(result),
            "BQUFBQUFBQUFBQUFBQUFBQ",
        ),
    ];

    let mut items = Vec::new();
    for (i, (name, author, role, kind, subkind, refs, payload, id)) in item_cases.into_iter().enumerate() {
        let new = NewItem {
            id: id.into(),
            session_id: sid.clone(),
            kind,
            subkind,
            created_at_ms: params.created_at_ms + 10 + i as u64,
            refs,
        };
        let nonce = [0xA0 + i as u8; 12];
        let encoded = payload.encode()?;
        let sealed = seal_with_nonce(&key, author, new.clone(), &encoded, nonce)?;
        items.push(json!({
            "name": name,
            "author_role": role.as_str(),
            "author_seed": b64e(&author.seed()),
            "new_item": new,
            "nonce": b64e(&nonce),
            "payload": b64e(&encoded),
            "payload_meta_canonical": s(canonical_json(&payload.meta)?),
            "item_key": b64e(&item_key(&key, &sid, id)),
            "header_canonical": s(sealed.header().canonical_bytes()?),
            "envelope": sealed.envelope,
            "blob": b64e(&sealed.blob),
        }));
    }

    // Negative cases built from the first item.
    let base = seal_with_nonce(
        &key,
        &sender,
        NewItem {
            id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            session_id: sid.clone(),
            kind: ItemKind::Text,
            subkind: None,
            created_at_ms: params.created_at_ms + 10,
            refs: vec![],
        },
        &Payload::text("Cleaned dataset attached.").encode()?,
        [0xA0; 12],
    )?;
    let mut flipped = base.blob.clone();
    *flipped.last_mut().expect("non-empty") ^= 0x01;
    let mut relabeled = base.envelope.clone();
    relabeled.header.created_at_ms += 1;

    Ok(json!({
        "version": 1,
        "description": "Airlock protocol v1 test vectors. All binary values are base64url without padding.",
        "inputs": {
            "owner_seed": b64e(&owner_seed),
            "base_url": BASE_URL,
            "session_params": params,
        },
        "session": {
            "session_id": sid,
            "session_key": b64e(&key),
            "owner_pub": secrets.owner().public().to_b64(),
            "role_seeds": {
                "sender": b64e(&secrets.role_seed(Role::Sender)),
                "runner": b64e(&secrets.role_seed(Role::Runner)),
                "observer": b64e(&secrets.role_seed(Role::Observer)),
            },
        },
        "manifest": {
            "canonical": s(signed.manifest.canonical_bytes()?),
            "signed": signed,
        },
        "invites": {
            "owner": Invite::owner(BASE_URL, &secrets)?.to_url(),
            "sender": Invite::member(BASE_URL, &secrets, Role::Sender)?.to_url(),
            "runner": Invite::member(BASE_URL, &secrets, Role::Runner)?.to_url(),
            "observer": Invite::member(BASE_URL, &secrets, Role::Observer)?.to_url(),
        },
        "certs": certs,
        "join": {
            "canonical": s(canonical_json(&join.join)?),
            "signed": join,
        },
        "items": items,
        "negative_items": [
            {"name": "flipped_blob_byte", "envelope": base.envelope, "blob": b64e(&flipped), "expect": "signature"},
            {"name": "header_changed_after_signing", "envelope": relabeled, "blob": b64e(&base.blob), "expect": "signature"},
            {"name": "wrong_session_key", "envelope": base.envelope, "blob": b64e(&base.blob),
             "session_key": b64e(&[0u8; 32]), "expect": "decrypt"},
        ],
    }))
}
