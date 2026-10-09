//! A server-sent events parser: bytes in, whole events out.

/// One dispatched event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Event {
    /// `id:`, when the event carried one.
    pub id: Option<String>,
    /// `event:`; `message` when absent.
    pub event: String,
    /// `data:` lines joined with `\n`.
    pub data: String,
}

/// Incremental parser. Feed it chunks; it hands back complete events.
#[derive(Debug, Default)]
pub struct Parser {
    buf: Vec<u8>,
    id: Option<String>,
    event: Option<String>,
    data: Vec<String>,
}

impl Parser {
    /// Feed one chunk; returns every event it completed.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<Event> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        while let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
            let mut line: Vec<u8> = self.buf.drain(..=pos).collect();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            let line = String::from_utf8_lossy(&line).into_owned();
            if line.is_empty() {
                if !self.data.is_empty() || self.event.is_some() {
                    out.push(Event {
                        id: self.id.clone(),
                        event: self.event.take().unwrap_or_else(|| "message".into()),
                        data: std::mem::take(&mut self.data).join("\n"),
                    });
                }
                continue;
            }
            if line.starts_with(':') {
                continue; // keep-alive comment
            }
            let (field, value) = line.split_once(':').unwrap_or((&line, ""));
            let value = value.strip_prefix(' ').unwrap_or(value);
            match field {
                "id" => self.id = Some(value.to_owned()),
                "event" => self.event = Some(value.to_owned()),
                "data" => self.data.push(value.to_owned()),
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
    fn events_split_across_chunks_come_out_whole() {
        let mut p = Parser::default();
        assert!(p.feed(b": keep-alive\n\nid: 7\nevent: mess").is_empty());
        let out = p.feed(b"age\ndata: {\"a\":1}\r\n\r\nid: 8\ndata: x\n\n");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].id.as_deref(), Some("7"));
        assert_eq!(out[0].event, "message");
        assert_eq!(out[0].data, "{\"a\":1}");
        assert_eq!(out[1].id.as_deref(), Some("8"));
    }
}
