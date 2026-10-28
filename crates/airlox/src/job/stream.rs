//! A running job's output, streamed (protocol §7, progress chunks).
//!
//! The shim writes stdout and stderr to files in the meta dir. While the job
//! runs, [`spawn`] tails them and posts `progress` items that carry a
//! `stream`, the byte `offset` of `data` in that stream and up to 64 KiB of
//! text. [`Streamer`] decides what goes out and when, from the bytes it is
//! fed and the time it is given:
//!
//! - a chunk goes when 64 KiB are pending, or once the oldest pending byte
//!   has waited a second;
//! - never more than `per_minute` chunks in any minute: past that, bytes
//!   wait and go out together (coalesced) when the budget allows;
//! - both streams together stop at `max_bytes`: the pending bytes go out,
//!   then one last chunk with `truncated: true`, and nothing after.
//!
//! Chunks are display. The signed result carries the output and is the
//! authority.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use airlox_core::item::{ItemKind, ItemRef};
use airlox_core::payload::{JobProgress, Payload, Stream, MAX_CHUNK_BYTES};

use super::{redact, AbortOnDrop, Poster};
use crate::job::Ctx;

/// How long output may wait for a fuller chunk.
const FLUSH_AFTER: Duration = Duration::from_secs(1);
/// How often the files are looked at.
const POLL: Duration = Duration::from_millis(250);
/// The most read from one file in one look.
const READ_PER_POLL: u64 = 1 << 20;

pub const STDOUT_FILE: &str = "stdout.txt";
pub const STDERR_FILE: &str = "stderr.txt";

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Chunks per minute.
    pub per_minute: u32,
    /// Bytes of both streams together.
    pub max_bytes: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Chunk {
    pub stream: Stream,
    /// Where `data` starts in its stream, in bytes of the job's output.
    pub offset: u64,
    pub data: String,
    /// The last chunk: streaming stopped at the byte cap.
    pub truncated: bool,
}

#[derive(Default)]
struct Pending {
    /// Bytes of this stream already sent.
    offset: u64,
    buf: Vec<u8>,
    /// Since when `buf` has held bytes that were not sent.
    since: Option<Instant>,
}

pub struct Streamer {
    limits: Limits,
    pending: [Pending; 2],
    /// Bytes of both streams sent or pending.
    counted: u64,
    /// When the chunks of the last minute went out.
    posts: VecDeque<Instant>,
    /// The stream whose bytes went past the cap.
    capped: Option<Stream>,
    done: bool,
}

fn idx(s: Stream) -> usize {
    match s {
        Stream::Stdout => 0,
        Stream::Stderr => 1,
    }
}

const STREAMS: [Stream; 2] = [Stream::Stdout, Stream::Stderr];

/// The text at the start of `buf`, at most `max` bytes, and how many bytes of
/// `buf` it covers. Cut at a character boundary: a sequence still arriving at
/// the end of `buf` waits for more bytes, unless `last` says there are none,
/// and bytes that are not UTF-8 at all become U+FFFD (so a chunk's length can
/// exceed the bytes it covers, never `max`).
fn utf8_chunk(buf: &[u8], max: usize, last: bool) -> (String, usize) {
    let (mut out, mut used) = (String::new(), 0);
    while used < buf.len() {
        let rest = &buf[used..];
        let (valid, bad) = match std::str::from_utf8(rest) {
            Ok(s) => (s, Some(0)),
            Err(e) => {
                let valid = std::str::from_utf8(&rest[..e.valid_up_to()]).unwrap_or_default();
                match e.error_len() {
                    Some(n) => (valid, Some(n)),
                    None if last => (valid, Some(rest.len() - valid.len())),
                    None => (valid, None),
                }
            }
        };
        let mut take = valid.len().min(max - out.len());
        while !valid.is_char_boundary(take) {
            take -= 1;
        }
        out.push_str(&valid[..take]);
        used += take;
        if take < valid.len() {
            break; // full
        }
        match bad {
            Some(0) | None => break,
            Some(n) => {
                if out.len() + '\u{fffd}'.len_utf8() > max {
                    break;
                }
                out.push('\u{fffd}');
                used += n;
            }
        }
    }
    (out, used)
}

impl Streamer {
    pub fn new(limits: Limits) -> Self {
        Streamer {
            limits,
            pending: Default::default(),
            counted: 0,
            posts: VecDeque::new(),
            capped: None,
            done: false,
        }
    }

    /// Where to read `stream`'s file from next, or `None` once nothing more
    /// will be sent.
    pub fn read_from(&self, stream: Stream) -> Option<u64> {
        let p = &self.pending[idx(stream)];
        (!self.done && self.capped.is_none()).then(|| p.offset + p.buf.len() as u64)
    }

    pub fn finished(&self) -> bool {
        self.done
    }

    /// New bytes of `stream`, read from [`Self::read_from`].
    pub fn feed(&mut self, stream: Stream, bytes: &[u8], now: Instant) {
        if self.done || self.capped.is_some() || bytes.is_empty() {
            return;
        }
        let room = self.limits.max_bytes.saturating_sub(self.counted);
        let take = (bytes.len() as u64).min(room) as usize;
        let p = &mut self.pending[idx(stream)];
        if take > 0 {
            p.buf.extend_from_slice(&bytes[..take]);
            p.since.get_or_insert(now);
            self.counted += take as u64;
        }
        if take < bytes.len() {
            self.capped = Some(stream);
        }
    }

    /// The chunks to post at `now`.
    pub fn due(&mut self, now: Instant) -> Vec<Chunk> {
        let mut out = Vec::new();
        while !self.done {
            while self.posts.front().is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60)) {
                self.posts.pop_front();
            }
            if self.posts.len() >= self.limits.per_minute as usize {
                break;
            }
            let last = self.capped.is_some();
            let ready = STREAMS.into_iter().find_map(|s| {
                let p = &self.pending[idx(s)];
                let waited = p.since.is_some_and(|t| now.duration_since(t) >= FLUSH_AFTER);
                if p.buf.is_empty() || !(last || waited || p.buf.len() >= MAX_CHUNK_BYTES) {
                    return None;
                }
                let (data, used) = utf8_chunk(&p.buf, MAX_CHUNK_BYTES, last);
                (used > 0).then_some((s, data, used))
            });
            let chunk = match (ready, self.capped) {
                (Some((s, data, used)), _) => {
                    let p = &mut self.pending[idx(s)];
                    let offset = p.offset;
                    p.buf.drain(..used);
                    p.offset += used as u64;
                    p.since = (!p.buf.is_empty()).then_some(now);
                    Chunk { stream: s, offset, data, truncated: false }
                }
                // Everything before the cap is out: say that this is where it stops.
                (None, Some(s)) if self.pending.iter().all(|p| p.buf.is_empty()) => {
                    self.done = true;
                    Chunk { stream: s, offset: self.pending[idx(s)].offset, data: String::new(), truncated: true }
                }
                _ => break,
            };
            self.posts.push_back(now);
            out.push(chunk);
        }
        out
    }
}

/// Tail the job's stdout and stderr (in `meta`) and post them as chunks until
/// the returned guard is dropped. `None` when streaming is off.
pub(super) fn spawn(
    ctx: &Arc<Ctx>,
    poster: &Poster,
    job_ref: &ItemRef,
    meta: PathBuf,
    hidden: Arc<Vec<(PathBuf, &'static str)>>,
) -> Option<AbortOnDrop> {
    if ctx.progress_rate == 0 {
        return None;
    }
    let limits = Limits { per_minute: ctx.progress_rate, max_bytes: ctx.stream_max_bytes };
    let (ctx, poster, job_ref) = (ctx.clone(), poster.clone(), job_ref.clone());
    Some(AbortOnDrop(tokio::spawn(async move {
        let start = tokio::time::Instant::now();
        let mut st = Streamer::new(limits);
        let mut tick = tokio::time::interval(POLL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut warned = false;
        while !st.finished() {
            tick.tick().await;
            let now = Instant::now();
            for (stream, file) in [(Stream::Stdout, STDOUT_FILE), (Stream::Stderr, STDERR_FILE)] {
                let Some(from) = st.read_from(stream) else { continue };
                let path = meta.join(file);
                let read = tokio::task::spawn_blocking(move || {
                    crate::sandbox::read_sandbox_range(&path, from, READ_PER_POLL)
                })
                .await;
                if let Ok(Ok(bytes)) = read {
                    st.feed(stream, &bytes, now);
                }
            }
            for c in st.due(now) {
                let p = JobProgress {
                    job: job_ref.clone(),
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    tail: None,
                    tail_truncated: false,
                    stream: Some(c.stream),
                    offset: Some(c.offset),
                    data: Some(redact::hide(&c.data, &hidden)),
                    truncated: c.truncated,
                };
                let refs = vec![job_ref.clone()];
                // One try: output is display, and the result has all of it.
                let posted = poster
                    .post(&ctx.keypair, ItemKind::Progress, None, refs, Payload::progress(p), Duration::ZERO)
                    .await;
                if let Err(e) = posted {
                    if !std::mem::replace(&mut warned, true) {
                        tracing::warn!(job = %job_ref.id, "could not post output as it ran (the result will have it): {e:#}");
                    }
                }
            }
        }
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(per_minute: u32, max_bytes: u64) -> Limits {
        Limits { per_minute, max_bytes }
    }

    fn at(t0: Instant, ms: u64) -> Instant {
        t0 + Duration::from_millis(ms)
    }

    #[test]
    fn small_output_waits_a_second_then_goes_once() {
        let t0 = Instant::now();
        let mut s = Streamer::new(limits(120, 1 << 20));
        s.feed(Stream::Stdout, b"collected 212 items\n", at(t0, 10));
        assert!(s.due(at(t0, 900)).is_empty());
        s.feed(Stream::Stdout, b"tests/test_a.py ..\n", at(t0, 950));
        let c = s.due(at(t0, 1010));
        assert_eq!(c.len(), 1);
        assert_eq!((c[0].stream, c[0].offset, c[0].data.as_str()), (Stream::Stdout, 0, "collected 212 items\ntests/test_a.py ..\n"));
        assert!(s.due(at(t0, 1020)).is_empty(), "sent bytes are not sent again");
        s.feed(Stream::Stdout, b"more\n", at(t0, 1100));
        assert!(s.due(at(t0, 2000)).is_empty());
        let c = s.due(at(t0, 2200));
        assert_eq!((c[0].offset, c[0].data.as_str()), (39, "more\n"));
        assert_eq!(s.read_from(Stream::Stdout), Some(44));
    }

    #[test]
    fn a_full_chunk_goes_at_once_and_streams_are_separate() {
        let t0 = Instant::now();
        let mut s = Streamer::new(limits(120, 1 << 20));
        s.feed(Stream::Stdout, &vec![b'a'; MAX_CHUNK_BYTES + 10], t0);
        s.feed(Stream::Stderr, b"warning\n", t0);
        let c = s.due(at(t0, 1));
        assert_eq!(c.len(), 1);
        assert_eq!((c[0].stream, c[0].data.len()), (Stream::Stdout, MAX_CHUNK_BYTES));
        // The rest of stdout and stderr wait their second.
        let c = s.due(at(t0, 1100));
        assert_eq!(c.len(), 2, "{c:?}");
        assert_eq!((c[0].stream, c[0].offset, c[0].data.len()), (Stream::Stdout, MAX_CHUNK_BYTES as u64, 10));
        assert_eq!((c[1].stream, c[1].offset, c[1].data.as_str()), (Stream::Stderr, 0, "warning\n"));
    }

    #[test]
    fn chunks_are_cut_at_character_boundaries_and_resume_there() {
        let t0 = Instant::now();
        let mut s = Streamer::new(limits(120, 1 << 20));
        // Euro signs are three bytes: a full chunk cannot end inside one.
        let text = "€".repeat(MAX_CHUNK_BYTES / 3 + 5);
        s.feed(Stream::Stdout, text.as_bytes(), t0);
        let c = s.due(at(t0, 1));
        assert_eq!(c[0].data.len(), MAX_CHUNK_BYTES - 1);
        assert!(c[0].data.chars().all(|ch| ch == '€'));
        let c2 = s.due(at(t0, 1200));
        assert_eq!(c2[0].offset, (MAX_CHUNK_BYTES - 1) as u64);
        assert_eq!(c2[0].data, "€".repeat(5));
        // A character split across two reads is carried to the next chunk.
        let mut s = Streamer::new(limits(120, 1 << 20));
        let bytes = "ab€".as_bytes();
        s.feed(Stream::Stdout, &bytes[..4], t0);
        let c = s.due(at(t0, 1100));
        assert_eq!((c[0].offset, c[0].data.as_str()), (0, "ab"));
        s.feed(Stream::Stdout, &bytes[4..], at(t0, 1150));
        let c = s.due(at(t0, 2200));
        assert_eq!((c[0].offset, c[0].data.as_str()), (2, "€"));
        // Only an incomplete character waiting: nothing to send yet.
        let mut s = Streamer::new(limits(120, 1 << 20));
        s.feed(Stream::Stdout, &"€".as_bytes()[..2], t0);
        assert!(s.due(at(t0, 5000)).is_empty());
    }

    #[test]
    fn bytes_that_are_not_utf8_become_replacement_characters_keeping_offsets() {
        let t0 = Instant::now();
        let mut s = Streamer::new(limits(120, 1 << 20));
        s.feed(Stream::Stdout, b"ok\xff\xfeend", t0);
        let c = s.due(at(t0, 1100));
        assert_eq!(c[0].data, "ok\u{fffd}\u{fffd}end");
        s.feed(Stream::Stdout, b"x", at(t0, 1200));
        let c = s.due(at(t0, 2300));
        assert_eq!((c[0].offset, c[0].data.as_str()), (7, "x"));
        // A chunk stays within 64 KiB even when every byte expands to three.
        let mut s = Streamer::new(limits(120, 1 << 20));
        s.feed(Stream::Stdout, &vec![0xff; MAX_CHUNK_BYTES], t0);
        let c = s.due(at(t0, 1));
        assert!(c[0].data.len() <= MAX_CHUNK_BYTES && c[0].data.chars().all(|ch| ch == '\u{fffd}'));
        assert_eq!(c[0].offset, 0);
        assert_eq!(s.read_from(Stream::Stdout), Some(MAX_CHUNK_BYTES as u64));
    }

    #[test]
    fn an_unfinished_character_at_the_very_end_is_not_lost_when_nothing_follows() {
        let (out, used) = utf8_chunk(&"a€".as_bytes()[..3], 100, false);
        assert_eq!((out.as_str(), used), ("a", 1));
        let (out, used) = utf8_chunk(&"a€".as_bytes()[..3], 100, true);
        assert_eq!((out.as_str(), used), ("a\u{fffd}", 3));
    }

    #[test]
    fn past_the_rate_output_waits_and_goes_in_fewer_bigger_chunks() {
        let t0 = Instant::now();
        let mut s = Streamer::new(limits(3, 1 << 20));
        let mut sent = Vec::new();
        // A line every 300 ms: one chunk a second would be 60 a minute.
        for i in 0..=100u64 {
            let t = at(t0, i * 300);
            s.feed(Stream::Stdout, format!("line {i}\n").as_bytes(), t);
            sent.extend(s.due(t));
        }
        // 30 seconds in, only three chunks may have gone, the first at 1.2 s.
        assert_eq!(sent.len(), 3, "{:?}", sent.iter().map(|c| c.offset).collect::<Vec<_>>());
        assert_eq!(sent[0].offset, 0);
        // Nothing is lost: the next minute's budget carries the backlog in one.
        let c = s.due(at(t0, 62_000));
        assert_eq!(c.len(), 1);
        let total: usize = sent.iter().chain(&c).map(|c| c.data.len()).sum();
        let expected: usize = (0..=100).map(|i| format!("line {i}\n").len()).sum();
        assert_eq!(total, expected);
        let mut next = 0;
        for c in sent.iter().chain(&c) {
            assert_eq!(c.offset, next);
            next += c.data.len() as u64;
        }
    }

    #[test]
    fn the_byte_cap_ends_with_one_truncated_chunk() {
        let t0 = Instant::now();
        let mut s = Streamer::new(limits(120, 100));
        s.feed(Stream::Stdout, &[b'a'; 60], t0);
        s.feed(Stream::Stderr, &[b'b'; 30], t0);
        assert_eq!(s.read_from(Stream::Stdout), Some(60));
        // 10 bytes of room left; this read is cut there and the cap is hit.
        s.feed(Stream::Stdout, &[b'c'; 40], at(t0, 100));
        assert_eq!(s.read_from(Stream::Stdout), None);
        assert_eq!(s.read_from(Stream::Stderr), None);
        let c = s.due(at(t0, 101));
        let kinds: Vec<_> = c.iter().map(|c| (c.stream, c.offset, c.data.len(), c.truncated)).collect();
        assert_eq!(
            kinds,
            [
                (Stream::Stdout, 0, 70, false),
                (Stream::Stderr, 0, 30, false),
                (Stream::Stdout, 70, 0, true)
            ]
        );
        assert!(s.finished());
        s.feed(Stream::Stdout, b"more", at(t0, 5000));
        assert!(s.due(at(t0, 9000)).is_empty(), "nothing after the truncated chunk");
    }

    #[test]
    fn the_final_chunk_waits_for_budget_like_any_other() {
        let t0 = Instant::now();
        let mut s = Streamer::new(limits(1, 10));
        s.feed(Stream::Stdout, &[b'a'; 20], t0);
        let c = s.due(at(t0, 1));
        assert_eq!(c.len(), 1);
        assert!(!c[0].truncated && !s.finished());
        assert!(s.due(at(t0, 30_000)).is_empty());
        let c = s.due(at(t0, 61_000));
        assert_eq!(c.len(), 1);
        assert!(c[0].truncated && c[0].data.is_empty() && c[0].offset == 10);
    }

    #[test]
    fn chunks_pass_the_core_policy() {
        let t0 = Instant::now();
        let mut s = Streamer::new(limits(120, 1 << 20));
        s.feed(Stream::Stdout, "é".repeat(MAX_CHUNK_BYTES).as_bytes(), t0);
        let job = ItemRef { id: airlox_core::encoding::b64e(&[1; 16]), blob_sha256: airlox_core::encoding::b64e(&[1; 32]) };
        for c in s.due(at(t0, 5000)).into_iter().chain([Chunk {
            stream: Stream::Stderr,
            offset: 3,
            data: String::new(),
            truncated: true,
        }]) {
            let p = JobProgress {
                job: job.clone(),
                elapsed_ms: 1,
                tail: None,
                tail_truncated: false,
                stream: Some(c.stream),
                offset: Some(c.offset),
                data: Some(c.data),
                truncated: c.truncated,
            };
            airlox_core::policy::check_progress(&p).unwrap();
        }
    }
}
