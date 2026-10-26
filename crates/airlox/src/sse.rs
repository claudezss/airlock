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

#[derive(Default)]
pub struct SseParser {
    /// Bytes, not text: a chunk may end inside a multi-byte character.
    buf: Vec<u8>,
    event: Option<String>,
    data: Option<String>,
    id: Option<String>,
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
                if let (Some(event), Some(data)) = (self.event.take(), self.data.take()) {
                    out.push(SseEvent { event, data, id: self.id.take() });
                }
                self.event = None;
                self.data = None;
                self.id = None;
                continue;
            }
            if line.starts_with(':') {
                continue;
            }
            let (name, value) = line.split_once(':').unwrap_or((line, ""));
            let value = value.strip_prefix(' ').unwrap_or(value).to_string();
            match name {
                "event" => self.event = Some(value),
                "data" => {
                    self.data = Some(match self.data.take() {
                        Some(d) => d + "\n" + &value,
                        None => value,
                    })
                }
                "id" => self.id = Some(value),
                _ => {}
            }
        }
        if self.buf.len() > MAX_LINE {
            self.buf.clear();
            self.event = None;
            self.data = None;
            self.id = None;
        }
        out
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
        let evs = p.push(b"\nevent: a\ndata: 1\n\n");
        assert_eq!(evs, vec![SseEvent { event: "a".into(), data: "1".into(), id: None }]);
    }
}
