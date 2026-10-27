//! Server configuration: flags with `AIRLOX_*` environment fallbacks.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "airlox-server",
    version,
    about = "Airlox relay: a transit buffer for encrypted agent sessions"
)]
pub struct Config {
    /// Data directory: one subdirectory per session.
    #[arg(long, env = "AIRLOX_DATA", default_value = "./airlox-data")]
    pub data: PathBuf,
    /// Wipe the data directory at start; nothing survives a restart.
    #[arg(long, env = "AIRLOX_EPHEMERAL")]
    pub ephemeral: bool,
    #[arg(long, env = "AIRLOX_LISTEN", default_value = "127.0.0.1:8080")]
    pub listen: SocketAddr,
    /// Take the client address from the last X-Forwarded-For entry, which the
    /// proxy in front of the relay appends. Only set this behind such a proxy.
    #[arg(long, env = "AIRLOX_TRUST_PROXY")]
    pub trust_proxy: bool,

    /// Longest session lifetime accepted. `never` also accepts sessions that
    /// never expire (they end when closed, or after `--idle-ttl-unexpiring`).
    #[arg(long = "max-ttl", env = "AIRLOX_MAX_TTL", default_value = "never", value_parser = parse_duration_or_never)]
    pub max_ttl_ms: u64,
    /// Largest per-item limit a manifest may set.
    #[arg(long, env = "AIRLOX_MAX_ITEM_BYTES", default_value = "25MiB", value_parser = parse_size)]
    pub max_item_bytes: u64,
    /// Ciphertext a session may have held on the relay at once.
    #[arg(long, env = "AIRLOX_MAX_SESSION_BYTES", default_value = "200MiB", value_parser = parse_size)]
    pub max_session_bytes: u64,
    /// Total bytes uploaded plus downloaded per session.
    #[arg(long, env = "AIRLOX_MAX_SESSION_TRANSFER", default_value = "1GiB", value_parser = parse_size)]
    pub max_session_transfer: u64,
    #[arg(long, env = "AIRLOX_MAX_ITEMS", default_value_t = 5000)]
    pub max_items: usize,
    /// Session log size (joins and item envelopes). Bounds per-session memory.
    #[arg(long, env = "AIRLOX_MAX_LOG_BYTES", default_value = "4MiB", value_parser = parse_size)]
    pub max_log_bytes: u64,
    /// Purge a session after this long without joins, items, acks or downloads.
    #[arg(long = "idle-ttl", env = "AIRLOX_IDLE_TTL", default_value = "2h", value_parser = parse_duration_ms)]
    pub idle_ttl_ms: u64,
    /// The same, for sessions that never expire; `never` keeps them until
    /// they are closed.
    #[arg(
        long = "idle-ttl-unexpiring",
        env = "AIRLOX_IDLE_TTL_UNEXPIRING",
        default_value = "30d",
        value_parser = parse_duration_or_never
    )]
    pub idle_ttl_unexpiring_ms: u64,
    /// Ciphertext the uploads from one address may have held on the relay at
    /// once, over all sessions (an IPv6 address counts by its /64).
    #[arg(long, env = "AIRLOX_MAX_BYTES_PER_IP", default_value = "unlimited", value_parser = parse_size_or_unlimited)]
    pub max_bytes_per_ip: u64,
    #[arg(long, env = "AIRLOX_MAX_SESSIONS_PER_IP", default_value_t = 20)]
    pub max_sessions_per_ip: usize,
    #[arg(long, env = "AIRLOX_MAX_SESSIONS", default_value_t = 1000)]
    pub max_sessions: usize,
    /// Refuse new sessions and uploads above this volume usage (percent).
    #[arg(long, env = "AIRLOX_DISK_HIGH_WATERMARK", default_value_t = 90)]
    pub disk_high_watermark: u8,
    /// Longest a blob stays on the relay after upload.
    #[arg(long = "blob-hold", env = "AIRLOX_BLOB_HOLD", default_value = "1h", value_parser = parse_duration_ms)]
    pub blob_hold_ms: u64,
    /// How long a blob stays after its last recipient acked.
    #[arg(long = "blob-grace", env = "AIRLOX_BLOB_GRACE", default_value = "5m", value_parser = parse_duration_ms)]
    pub blob_grace_ms: u64,
    /// How long a runner has to claim an assigned job before it fails.
    #[arg(long = "claim-timeout", env = "AIRLOX_CLAIM_TIMEOUT", default_value = "5s", value_parser = parse_duration_ms)]
    pub claim_timeout_ms: u64,
    /// A runner without a heartbeat for this long is offline, and its job fails.
    #[arg(long = "runner-timeout", env = "AIRLOX_RUNNER_TIMEOUT", default_value = "30s", value_parser = parse_duration_ms)]
    pub runner_timeout_ms: u64,
    /// How long a one-time transfer code stays claimable.
    #[arg(long = "drop-ttl", env = "AIRLOX_DROP_TTL", default_value = "10m", value_parser = parse_duration_ms)]
    pub drop_ttl_ms: u64,
    /// Transfer codes open at once, relay-wide (they are held in memory).
    #[arg(long, env = "AIRLOX_MAX_DROPS", default_value_t = 1000)]
    pub max_drops: usize,
    #[arg(long, env = "AIRLOX_MAX_DROPS_PER_IP", default_value_t = 10)]
    pub max_drops_per_ip: usize,
    /// How often expiry, idle and eviction timers are checked.
    #[arg(long = "sweep-interval", env = "AIRLOX_SWEEP_INTERVAL", default_value = "1s", value_parser = parse_duration_ms)]
    pub sweep_interval_ms: u64,
}

impl Config {
    /// Defaults with the given data directory, for embedding and tests.
    pub fn with_data(data: impl Into<PathBuf>) -> Self {
        let mut c = Config::parse_from(["airlox-server"]);
        c.data = data.into();
        c
    }
}

/// `1500ms`, `30s`, `5m`, `24h`, `7d`.
pub fn parse_duration_ms(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().map_err(|_| format!("bad duration {s:?}"))?;
    let mult = match unit {
        "ms" => 1,
        "s" | "" => 1000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => return Err(format!("bad duration unit in {s:?} (use ms, s, m, h, d)")),
    };
    n.checked_mul(mult).ok_or_else(|| format!("duration {s:?} too large"))
}

/// A duration, or `never` (`u64::MAX`).
pub fn parse_duration_or_never(s: &str) -> Result<u64, String> {
    if s.trim() == "never" {
        return Ok(u64::MAX);
    }
    parse_duration_ms(s)
}

/// A size, or `unlimited` (`u64::MAX`).
pub fn parse_size_or_unlimited(s: &str) -> Result<u64, String> {
    if s.trim() == "unlimited" {
        return Ok(u64::MAX);
    }
    parse_size(s)
}

/// `1024`, `64KiB`, `25MiB`, `1GiB` (also `KB`/`MB`/`GB` as powers of 1000).
pub fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().map_err(|_| format!("bad size {s:?}"))?;
    let mult: u64 = match unit {
        "" | "B" => 1,
        "KiB" => 1 << 10,
        "MiB" => 1 << 20,
        "GiB" => 1 << 30,
        "KB" => 1_000,
        "MB" => 1_000_000,
        "GB" => 1_000_000_000,
        _ => return Err(format!("bad size unit in {s:?} (use B, KiB, MiB, GiB)")),
    };
    n.checked_mul(mult).ok_or_else(|| format!("size {s:?} too large"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_units() {
        assert_eq!(parse_duration_ms("1500ms").unwrap(), 1500);
        assert_eq!(parse_duration_ms("5m").unwrap(), 300_000);
        assert_eq!(parse_duration_ms("24h").unwrap(), 86_400_000);
        assert!(parse_duration_ms("5 weeks").is_err());
        assert_eq!(parse_size("25MiB").unwrap(), 25 << 20);
        assert_eq!(parse_size("1GiB").unwrap(), 1 << 30);
        assert!(parse_size("1TiB").is_err());
        assert_eq!(parse_duration_or_never("never").unwrap(), u64::MAX);
        assert_eq!(parse_size_or_unlimited("2GiB").unwrap(), 2 << 30);
        let c = Config::with_data("/tmp/x");
        assert_eq!(c.blob_hold_ms, 3_600_000);
        assert_eq!(c.max_session_bytes, 200 << 20);
        assert_eq!((c.max_ttl_ms, c.max_bytes_per_ip), (u64::MAX, u64::MAX));
    }
}
