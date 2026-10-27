//! Invite links.
//!
//! ```text
//! owner:  {base}/s/{session_id}#v=1&r=owner&ok={owner_seed}
//! member: {base}/s/{session_id}#v=1&r={send|run|view}&k={session_key}&rk={role_seed}
//! ```
//!
//! All binary values are base64url without padding. The fragment never
//! reaches the server.

use crate::encoding::{b64d_32, b64e};
use crate::keys::Keypair;
use crate::session::{derive_session_id, is_session_id, Manifest, Role, SessionSecrets};
use crate::{Error, Result};

#[derive(Clone, PartialEq, Eq)]
pub enum InviteSecret {
    Owner { owner_seed: [u8; 32] },
    Member { session_key: [u8; 32], role_seed: [u8; 32] },
}

impl Drop for InviteSecret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        match self {
            InviteSecret::Owner { owner_seed } => owner_seed.zeroize(),
            InviteSecret::Member { session_key, role_seed } => {
                session_key.zeroize();
                role_seed.zeroize();
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Invite {
    pub base_url: String,
    pub session_id: String,
    pub role: Role,
    pub secret: InviteSecret,
}

impl std::fmt::Debug for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invite")
            .field("base_url", &self.base_url)
            .field("session_id", &self.session_id)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

/// `scheme://host[:port][/path]`, with the scheme `https` or `http`, and
/// the lowercased host. Whether `http` may be used is decided against the
/// manifest ([`check_transport`]), which the link alone cannot vouch for.
fn split_base(base_url: &str) -> Result<(String, &str, String)> {
    let b = base_url.trim_end_matches('/');
    let (scheme, rest) =
        b.split_once("://").ok_or_else(|| Error::invalid("base_url", "must start with https://"))?;
    if b.contains('#') || b.contains('?') || b.contains('@') || b.chars().any(|c| c.is_whitespace()) {
        return Err(Error::invalid("base_url", "must not contain a query, fragment, userinfo or spaces"));
    }
    // HTTP clients read `\` as `/` and decode `%`: the host they connect to
    // must be the host checked here.
    if b.contains('\\') || b.contains('%') || !b.is_ascii() {
        return Err(Error::invalid(
            "base_url",
            "must be plain ASCII, without backslashes or percent-escapes",
        ));
    }
    let authority = rest.split('/').next().unwrap_or("");
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next().map(|h| format!("[{h}]")).unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or("").to_ascii_lowercase()
    };
    if host.is_empty() {
        return Err(Error::invalid("base_url", "missing host"));
    }
    match scheme {
        "https" | "http" => Ok((b.to_string(), scheme, host)),
        _ => Err(Error::invalid("base_url", "must start with https://")),
    }
}

fn normalize_base(base_url: &str) -> Result<String> {
    split_base(base_url).map(|(b, _, _)| b)
}

fn is_loopback(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost") || host == "127.0.0.1" || host == "[::1]"
}

/// May a participant reach the relay at `base_url`? Over `https://`, yes;
/// over `http://` only on this machine (loopback) or on the one host the
/// session's owner named in the signed manifest (`insecure_http_host`).
pub fn check_transport(base_url: &str, insecure_http_host: Option<&str>) -> Result<()> {
    let (_, scheme, host) = split_base(base_url)?;
    if scheme == "https" || is_loopback(&host) || insecure_http_host == Some(host.as_str()) {
        return Ok(());
    }
    Err(Error::invalid(
        "base_url",
        match insecure_http_host {
            Some(h) => format!("http:// is only allowed for localhost and {h}, which this session names"),
            None => "http:// is only allowed for localhost, unless the session's owner names the relay \
                     host with --insecure-http-host"
                .to_string(),
        },
    ))
}

/// A host an owner may allow over `http://`: a DNS name or a dotted-quad
/// IPv4 address, lowercase, without scheme, port or path. Loopback needs no
/// opt-in. Numeric forms HTTP clients read as IPv4 (`2130706433`, `0x7f.1`,
/// `10.1`) must be written as four decimal octets, and loopback, link-local,
/// unspecified, broadcast and multicast addresses are refused.
pub fn check_insecure_http_host(h: &str) -> Result<()> {
    let bad = |why: &str| Err(Error::invalid("insecure_http_host", format!("{h:?} {why}")));
    let labels_ok = h.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    });
    if h.is_empty() || h.len() > 253 || !labels_ok {
        return bad("must be a lowercase host name such as airlox-relay.ns.svc, without scheme or port");
    }
    if is_loopback(h) {
        return Err(Error::invalid("insecure_http_host", "localhost needs no opt-in: leave it out"));
    }
    // As in the URL standard: a host whose last label is a number is IPv4.
    let last = h.rsplit('.').next().unwrap_or("");
    let numeric = !last.is_empty()
        && (last.bytes().all(|c| c.is_ascii_digit())
            || last.strip_prefix("0x").is_some_and(|x| x.bytes().all(|c| c.is_ascii_hexdigit())));
    if numeric {
        let Ok(ip) = h.parse::<std::net::Ipv4Addr>() else {
            return bad("is read as an IPv4 address: write it as four decimal numbers, like 10.0.0.7");
        };
        if ip.is_loopback()
            || ip.is_link_local()
            || ip.is_unspecified()
            || ip.is_broadcast()
            || ip.is_multicast()
        {
            return bad("is a loopback, link-local or otherwise special address");
        }
    }
    Ok(())
}

impl Invite {
    pub fn owner(base_url: &str, s: &SessionSecrets) -> Result<Self> {
        Ok(Invite {
            base_url: normalize_base(base_url)?,
            session_id: s.session_id(),
            role: Role::Owner,
            secret: InviteSecret::Owner { owner_seed: s.owner_seed() },
        })
    }

    pub fn member(base_url: &str, s: &SessionSecrets, role: Role) -> Result<Self> {
        if role == Role::Owner {
            return Err(Error::invalid("invite role", "use Invite::owner for the owner link"));
        }
        Ok(Invite {
            base_url: normalize_base(base_url)?,
            session_id: s.session_id(),
            role,
            secret: InviteSecret::Member { session_key: s.session_key(), role_seed: s.role_seed(role) },
        })
    }

    pub fn to_url(&self) -> String {
        let frag = match &self.secret {
            InviteSecret::Owner { owner_seed } => format!("v=1&r=owner&ok={}", b64e(owner_seed)),
            InviteSecret::Member { session_key, role_seed } => {
                format!("v=1&r={}&k={}&rk={}", self.role.url_name(), b64e(session_key), b64e(role_seed))
            }
        };
        format!("{}/s/{}#{}", self.base_url, self.session_id, frag)
    }

    pub fn parse(url: &str) -> Result<Self> {
        let (left, frag) =
            url.split_once('#').ok_or_else(|| Error::invalid("invite", "missing #fragment"))?;
        let (base, sid) =
            left.rsplit_once("/s/").ok_or_else(|| Error::invalid("invite", "missing /s/<session_id>"))?;
        let sid = sid.trim_end_matches('/');
        if !is_session_id(sid) {
            return Err(Error::invalid("invite", "malformed session id"));
        }
        let base_url = normalize_base(base)?;

        let (mut v, mut r, mut k, mut rk, mut ok) = (None, None, None, None, None);
        for pair in frag.split('&').filter(|p| !p.is_empty()) {
            let (key, val) =
                pair.split_once('=').ok_or_else(|| Error::invalid("invite", "malformed fragment"))?;
            let slot = match key {
                "v" => &mut v,
                "r" => &mut r,
                "k" => &mut k,
                "rk" => &mut rk,
                "ok" => &mut ok,
                _ => continue, // tolerate future keys
            };
            if slot.replace(val).is_some() {
                return Err(Error::invalid("invite", format!("duplicate key {key}")));
            }
        }
        if v != Some("1") {
            return Err(Error::invalid("invite", "unsupported or missing version"));
        }
        let role = Role::from_url_name(r.ok_or_else(|| Error::invalid("invite", "missing role"))?)?;
        let secret = match role {
            Role::Owner => {
                if k.is_some() || rk.is_some() {
                    return Err(Error::invalid("invite", "owner link must only carry ok"));
                }
                let owner_seed = b64d_32(ok.ok_or_else(|| Error::invalid("invite", "missing ok"))?)?;
                let derived = derive_session_id(&Keypair::from_seed(&owner_seed).public());
                if derived != sid {
                    return Err(Error::invalid("invite", "owner seed does not match session id"));
                }
                InviteSecret::Owner { owner_seed }
            }
            _ => {
                if ok.is_some() {
                    return Err(Error::invalid("invite", "member link must not carry ok"));
                }
                InviteSecret::Member {
                    session_key: b64d_32(k.ok_or_else(|| Error::invalid("invite", "missing k"))?)?,
                    role_seed: b64d_32(rk.ok_or_else(|| Error::invalid("invite", "missing rk"))?)?,
                }
            }
        };
        Ok(Invite { base_url, session_id: sid.to_string(), role, secret })
    }

    pub fn session_key(&self) -> [u8; 32] {
        match &self.secret {
            InviteSecret::Owner { owner_seed } => SessionSecrets::from_owner_seed(*owner_seed).session_key(),
            InviteSecret::Member { session_key, .. } => *session_key,
        }
    }

    /// The key this invite's holder uses to issue its own role certificate.
    pub fn role_keypair(&self) -> Keypair {
        match &self.secret {
            InviteSecret::Owner { owner_seed } => Keypair::from_seed(owner_seed),
            InviteSecret::Member { role_seed, .. } => Keypair::from_seed(role_seed),
        }
    }

    /// The owner's full secrets, if this is the owner link.
    pub fn owner_secrets(&self) -> Option<SessionSecrets> {
        match &self.secret {
            InviteSecret::Owner { owner_seed } => Some(SessionSecrets::from_owner_seed(*owner_seed)),
            InviteSecret::Member { .. } => None,
        }
    }

    /// Confirm the invite belongs to this (already verified) manifest.
    pub fn check_against(&self, m: &Manifest) -> Result<()> {
        if self.session_id != m.session_id {
            return Err(Error::invalid("invite", "session id does not match manifest"));
        }
        if self.role_keypair().public() != m.role_key(self.role) {
            return Err(Error::invalid("invite", "role key does not match manifest"));
        }
        check_transport(&self.base_url, m.insecure_http_host.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_owner_and_members() {
        let s = SessionSecrets::from_owner_seed([3u8; 32]);
        let o = Invite::owner("https://airlox.example/", &s).unwrap();
        let url = o.to_url();
        assert!(url.starts_with("https://airlox.example/s/ax_"));
        assert_eq!(Invite::parse(&url).unwrap(), o);
        for role in Role::MEMBERS {
            let i = Invite::member("https://airlox.example", &s, role).unwrap();
            let back = Invite::parse(&i.to_url()).unwrap();
            assert_eq!(back, i);
            assert_eq!(back.session_key(), s.session_key());
            assert_eq!(back.role_keypair().public(), s.role_keypair(role).public());
        }
    }

    #[test]
    fn rejects_bad_links() {
        let s = SessionSecrets::from_owner_seed([3u8; 32]);
        let good = Invite::member("https://a.example", &s, Role::Sender).unwrap().to_url();
        assert!(Invite::parse(&good.replace("v=1", "v=2")).is_err());
        assert!(Invite::parse(&good.replace("#", "?")).is_err());
        assert!(Invite::parse(&format!("{good}&r=view")).is_err());
        assert!(Invite::parse(&good.replace("https://a.example", "ftp://a.example")).is_err());
        assert!(Invite::parse(&good.replace("https://a.example", "https://")).is_err());
        let other = SessionSecrets::from_owner_seed([4u8; 32]);
        let forged = Invite::owner("https://a.example", &other)
            .unwrap()
            .to_url()
            .replace(&other.session_id(), &s.session_id());
        assert!(Invite::parse(&forged).is_err());
    }

    #[test]
    fn http_needs_loopback_or_the_host_the_manifest_names() {
        use crate::session::{ContentType, Mode, SessionParams};
        let s = SessionSecrets::from_owner_seed([3u8; 32]);
        let manifest = |host: Option<&str>| {
            let p = SessionParams {
                mode: Mode::Relay,
                created_at_ms: 1_700_000_000_000,
                ttl_ms: Some(3_600_000),
                allowed_types: vec![ContentType::Text],
                max_item_bytes: 1024,
                job_limits: None,
                insecure_http_host: host.map(String::from),
            };
            s.manifest(&p).unwrap().manifest
        };
        let plain = manifest(None);
        let named = manifest(Some("airlox-relay.ns.svc"));
        let link =
            |base: &str| Invite::parse(&Invite::member(base, &s, Role::Sender).unwrap().to_url()).unwrap();
        for base in ["https://a.example", "http://localhost:8080", "http://127.0.0.1:1", "http://[::1]:1"] {
            link(base).check_against(&plain).unwrap();
        }
        // The link parses, but only a manifest that names the host lets it through.
        let cluster = link("http://airlox-relay.ns.svc:8080");
        assert!(cluster.check_against(&plain).is_err());
        cluster.check_against(&named).unwrap();
        link("http://AIRLOX-RELAY.ns.svc").check_against(&named).unwrap();
        assert!(link("http://evil.example").check_against(&named).is_err());
        assert!(link("http://airlox-relay.ns.svc.evil.example").check_against(&named).is_err());
        // What a client would connect to must be the host checked.
        for base in
            ["http://evil.example\\.localhost", "http://evil.example%2f.localhost", "http://evil.éxample"]
        {
            assert!(Invite::member(base, &s, Role::Sender).is_err(), "{base:?}");
        }
        // What an owner may name.
        for ok in ["airlox-relay.ns.svc", "relay", "10.0.0.7", "a-b.c"] {
            check_insecure_http_host(ok).unwrap();
        }
        for bad in
            ["", "http://relay", "relay:8080", "Relay", "relay/x", "-a.b", "a..b", "localhost", "[::1]"]
        {
            assert!(check_insecure_http_host(bad).is_err(), "{bad:?}");
        }
    }
}
