//! A minimal incremental Server-Sent Events parser.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event: String,
    pub data: String,
    pub id: Option<String>,
}

/// Longest line kept while waiting for its end; a stream that sends more
/// without a newline is cut off there.
const MAX_LINE: usize = 1 << 20;

/// Largest event (all its `data:` lines together). A relay that keeps
/// sending lines without ending the event gets the event dropped, not
/// buffered without bound.
const MAX_EVENT: usize = 4 << 20;

#[derive(Default)]
pub struct SseParser {
    /// Bytes, not text: a chunk may end inside a multi-byte character.
    buf: Vec<u8>,
    event: Option<String>,
    data: Option<String>,
    id: Option<String>,
    /// The event in progress grew past `MAX_EVENT`; skip it to its end.
    overflow: bool,
}

impl SseParser {
    /// Feed a chunk; returns every event it completed.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        while let Some(i) = self.buf.iter().position(|&b| b == b'\n') {
            let raw: Vec<u8> = self.buf.drain(..=i).collect();
            let line = String::from_utf8_lossy(&raw);
            let line = line.trim_end_matches(['\n', '\r']);
            if line.is_empty() {
                if let (Some(event), Some(data), false) = (self.event.take(), self.data.take(), self.overflow)
                {
                    out.push(SseEvent { event, data, id: self.id.take() });
                }
                self.reset();
                continue;
            }
            if line.starts_with(':') || self.overflow {
                continue;
            }
            let (name, value) = line.split_once(':').unwrap_or((line, ""));
            let value = value.strip_prefix(' ').unwrap_or(value).to_string();
            match name {
                "event" => self.event = Some(value),
                "data" => {
                    let data = match self.data.take() {
                        Some(d) => d + "\n" + &value,
                        None => value,
                    };
                    if data.len() > MAX_EVENT {
                        self.overflow = true;
                    } else {
                        self.data = Some(data);
                    }
                }
                "id" => self.id = Some(value),
                _ => {}
            }
        }
        if self.buf.len() > MAX_LINE {
            self.buf.clear();
            self.reset();
            self.overflow = true; // the rest of this line belongs to a dropped event
        }
        out
    }

    fn reset(&mut self) {
        self.event = None;
        self.data = None;
        self.id = None;
        self.overflow = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_split_chunks_and_comments() {
        let mut p = SseParser::default();
        assert!(p.push(b": keep-alive\n\nevent: job_ass").is_empty());
        let evs = p.push(b"igned\ndata: {\"job\":\"x\"}\n\nevent: rejected\ndata: {}\n\n");
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].event, "job_assigned");
        assert_eq!(evs[0].data, r#"{"job":"x"}"#);
        assert_eq!(evs[1].event, "rejected");
    }

    #[test]
    fn keeps_characters_split_across_chunks() {
        let mut p = SseParser::default();
        let msg = "event: participant\ndata: {\"name\":\"Zoë ✓\"}\n\n".as_bytes();
        let cut = msg.iter().position(|&b| b == 0xC3).unwrap() + 1; // inside "ë"
        assert!(p.push(&msg[..cut]).is_empty());
        let evs = p.push(&msg[cut..]);
        assert_eq!(evs[0].data, "{\"name\":\"Zoë ✓\"}");
    }

    #[test]
    fn drops_overlong_lines() {
        let mut p = SseParser::default();
        assert!(p.push(&vec![b'x'; MAX_LINE + 1]).is_empty());
        let evs = p.push(b"\n\nevent: a\ndata: 1\n\n");
        assert_eq!(evs, vec![SseEvent { event: "a".into(), data: "1".into(), id: None }]);
    }

    #[test]
    fn drops_overlong_events_without_growing() {
        let mut p = SseParser::default();
        let line = format!("data: {}\n", "x".repeat(64 * 1024));
        p.push(b"event: item\n");
        for _ in 0..(MAX_EVENT / line.len() + 10) {
            assert!(p.push(line.as_bytes()).is_empty());
        }
        assert!(p.data.as_ref().map_or(0, |d| d.len()) <= MAX_EVENT);
        // The event is dropped at its end, and the next one is read normally.
        assert!(p.push(b"\n").is_empty());
        let evs = p.push(b"event: a\ndata: 1\n\n");
        assert_eq!(evs, vec![SseEvent { event: "a".into(), data: "1".into(), id: None }]);
    }
}
