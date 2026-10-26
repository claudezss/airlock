//! A minimal incremental Server-Sent Events parser.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event: String,
    pub data: String,
    pub id: Option<String>,
}

#[derive(Default)]
pub struct SseParser {
    buf: String,
    event: Option<String>,
    data: Option<String>,
    id: Option<String>,
}

impl SseParser {
    /// Feed a chunk; returns every event it completed.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        self.buf.push_str(&String::from_utf8_lossy(chunk));
        let mut out = Vec::new();
        while let Some(i) = self.buf.find('\n') {
            let line: String = self.buf.drain(..=i).collect();
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
}
