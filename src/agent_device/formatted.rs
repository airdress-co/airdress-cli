//! A session's markdown, as the app's blocks (SPEC-166 phase I, D-20).
//!
//! A coding session answers in markdown. The app's message model is typed
//! blocks, and it renders `rich_text` and `code` formatted, but it never
//! guesses that plain text is markdown. So the sender says so: the device
//! host parses a signed session reply here and puts the result beside the
//! text, as the text block's `formatted` array:
//!
//! ```text
//! {"type": "text", "text": "bob: **Done.** …", "by_session": {…},
//!  "formatted": [{"type": "rich_text", "kind": "paragraph", "spans": […]}, …]}
//! ```
//!
//! The text stays what the session signed (the signature is unchanged), so
//! an app that predates `formatted` shows the reply as before: plain, under
//! the session's name. An app that knows it shows these blocks instead,
//! once the signature over the text has verified, and takes each block's
//! `source` to be that text (without the session's `name: ` prefix). That
//! is why no block carries `source` on the wire: repeating the whole
//! markdown in every block would make a long list quadratic in size.
//!
//! The mapping is the app's own (`ast_to_blocks.dart` in airdress-chat),
//! so a reply looks the same whether a model's answer was parsed on the
//! phone or a session's on the machine. `tests/vectors/markdown_blocks.json`
//! holds the cases both sides are tested against. Like the app's mapper,
//! this can only emit the blocks it has a case for: no HTML is
//! interpreted, an image is its alt text and never a request, and a link
//! keeps its target only for `http`, `https` and `mailto`.

use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd};
use serde_json::{json, Map, Value};

/// Ceiling on blocks, as in the app: well above any real answer, and a
/// pathological one cannot exhaust a renderer.
pub const MAX_BLOCKS: usize = 2000;

/// The `formatted` blocks for `markdown`, or `None` when it has nothing a
/// plain text block does not show as well: only plain paragraphs. A
/// message without markdown stays one `text` block.
pub fn formatted(markdown: &str) -> Option<Vec<Value>> {
    if markdown.trim().is_empty() {
        return None;
    }
    let blocks = Mapper::default().run(markdown);
    if blocks.iter().all(Out::is_plain_paragraph) {
        return None;
    }
    Some(blocks.iter().map(Out::to_json).collect())
}

/// The text a session's reply is formatted from: its `name: ` prefix
/// (SPEC-166 FR-13) is the name the app already shows above it, and left
/// in, it would turn a heading or a list on the first line into a
/// paragraph.
pub fn body_of<'a>(text: &'a str, session_name: &str) -> &'a str {
    text.strip_prefix(session_name)
        .and_then(|rest| rest.strip_prefix(": "))
        .unwrap_or(text)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Span {
    text: String,
    bold: bool,
    italic: bool,
    strike: bool,
    code: bool,
    href: Option<String>,
}

impl Span {
    fn same_style(&self, other: &Self) -> bool {
        self.bold == other.bold
            && self.italic == other.italic
            && self.strike == other.strike
            && self.code == other.code
            && self.href == other.href
    }

    fn is_plain(&self) -> bool {
        !self.bold && !self.italic && !self.strike && !self.code && self.href.is_none()
    }

    fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("text".into(), Value::String(self.text.clone()));
        for (key, on) in [
            ("bold", self.bold),
            ("italic", self.italic),
            ("strike", self.strike),
            ("code", self.code),
        ] {
            if on {
                m.insert(key.into(), Value::Bool(true));
            }
        }
        if let Some(h) = &self.href {
            m.insert("href".into(), Value::String(h.clone()));
        }
        Value::Object(m)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Paragraph,
    Heading,
    ListItem,
    Quote,
}

#[derive(Debug)]
struct Run {
    kind: Kind,
    level: u8,
    depth: usize,
    ordinal: Option<u64>,
    checked: Option<bool>,
    spans: Vec<Span>,
    /// Text after a nested list or a code block inside a list item: kept
    /// as a run of its own, and dropped when it holds nothing.
    continuation: bool,
}

impl Run {
    fn new(kind: Kind, depth: usize) -> Self {
        Self {
            kind,
            level: 0,
            depth,
            ordinal: None,
            checked: None,
            spans: Vec::new(),
            continuation: false,
        }
    }

    fn is_blank(&self) -> bool {
        self.spans.iter().all(|s| s.text.trim().is_empty())
    }

    fn push(&mut self, span: Span) {
        if span.text.is_empty() {
            return;
        }
        match self.spans.last_mut() {
            Some(last) if last.same_style(&span) => last.text.push_str(&span.text),
            _ => self.spans.push(span),
        }
    }
}

#[derive(Debug)]
enum Out {
    Rich(Run),
    Code {
        code: String,
        language: Option<String>,
    },
    Divider,
}

impl Out {
    fn is_plain_paragraph(&self) -> bool {
        matches!(self, Self::Rich(r)
            if r.kind == Kind::Paragraph && r.depth == 0 && r.spans.iter().all(Span::is_plain))
    }

    fn to_json(&self) -> Value {
        match self {
            Self::Rich(r) => {
                let mut m = Map::new();
                m.insert("type".into(), json!("rich_text"));
                m.insert(
                    "kind".into(),
                    json!(match r.kind {
                        Kind::Paragraph => "paragraph",
                        Kind::Heading => "heading",
                        Kind::ListItem => "list_item",
                        Kind::Quote => "quote",
                    }),
                );
                if r.level != 0 {
                    m.insert("level".into(), json!(r.level));
                }
                if r.depth != 0 {
                    m.insert("depth".into(), json!(r.depth));
                }
                if let Some(n) = r.ordinal {
                    m.insert("ordinal".into(), json!(n));
                }
                if let Some(c) = r.checked {
                    m.insert("checked".into(), json!(c));
                }
                m.insert(
                    "spans".into(),
                    Value::Array(r.spans.iter().map(Span::to_json).collect()),
                );
                Value::Object(m)
            }
            Self::Code { code, language } => match language {
                Some(l) => json!({"type": "code", "code": code, "language": l}),
                None => json!({"type": "code", "code": code}),
            },
            Self::Divider => json!({"type": "divider"}),
        }
    }
}

/// A table being read: its row so far, and whether it is the header.
#[derive(Debug, Default)]
struct Row {
    spans: Vec<Span>,
    header: bool,
}

#[derive(Debug, Default)]
struct Mapper {
    out: Vec<Out>,
    cur: Option<Run>,
    quote: usize,
    /// One entry per open list: the next ordinal, `None` for bullets.
    lists: Vec<Option<u64>>,
    items: usize,
    bold: usize,
    italic: usize,
    strike: usize,
    links: Vec<Option<String>>,
    /// An image's alt text, while inside one.
    alt: Option<String>,
    /// A code block's text and language, while inside one.
    code: Option<(String, Option<String>)>,
    row: Option<Row>,
    in_head: bool,
}

impl Mapper {
    fn run(mut self, markdown: &str) -> Vec<Out> {
        // GFM's tables, strikethrough and task lists: what models emit.
        // No HTML is ever interpreted; it arrives as text.
        let options =
            Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;
        for event in Parser::new_ext(markdown, options) {
            self.event(event);
            if self.out.len() >= MAX_BLOCKS {
                break;
            }
        }
        self.flush();
        self.out.truncate(MAX_BLOCKS);
        self.out
    }

    fn flush(&mut self) {
        if let Some(run) = self.cur.take() {
            let keep = match run.kind {
                // An empty list item is still an item, as in the app.
                Kind::ListItem => !(run.continuation && run.is_blank()),
                _ => !run.is_blank(),
            };
            if keep {
                self.out.push(Out::Rich(run));
            }
        }
    }

    fn open(&mut self, run: Run) {
        self.flush();
        self.cur = Some(run);
    }

    fn block_kind(&self) -> Run {
        if self.quote > 0 {
            Run::new(Kind::Quote, self.quote)
        } else {
            Run::new(Kind::Paragraph, 0)
        }
    }

    fn list_depth(&self) -> usize {
        self.quote + self.lists.len().saturating_sub(1)
    }

    fn text(&mut self, text: &str, code: bool) {
        if let Some(alt) = &mut self.alt {
            alt.push_str(text);
            return;
        }
        let span = Span {
            text: text.to_owned(),
            bold: self.bold > 0,
            italic: self.italic > 0,
            strike: self.strike > 0,
            code,
            href: self.links.last().cloned().flatten(),
        };
        self.span(span);
    }

    fn span(&mut self, mut span: Span) {
        if let Some(row) = &mut self.row {
            span.bold |= row.header;
            match row.spans.last_mut() {
                Some(last) if last.same_style(&span) => last.text.push_str(&span.text),
                _ if span.text.is_empty() => {}
                _ => row.spans.push(span),
            }
            return;
        }
        if self.cur.is_none() {
            let run = if self.items > 0 {
                let mut r = Run::new(Kind::ListItem, self.list_depth());
                r.continuation = true;
                r
            } else {
                self.block_kind()
            };
            self.cur = Some(run);
        }
        if let Some(run) = &mut self.cur {
            run.push(span);
        }
    }

    fn event(&mut self, event: Event<'_>) {
        match event {
            Event::Start(tag) => self.start(tag),
            Event::End(tag) => self.end(tag),
            Event::Text(t) => match &mut self.code {
                Some((buf, _)) => buf.push_str(&t),
                None => self.text(&t, false),
            },
            Event::Code(t) => self.text(&t, true),
            Event::Html(t) | Event::InlineHtml(t) => self.text(&t, false),
            Event::SoftBreak | Event::HardBreak => self.text("\n", false),
            Event::Rule => {
                self.flush();
                self.out.push(Out::Divider);
            }
            Event::TaskListMarker(done) => {
                if let Some(run) = self.cur.as_mut().filter(|r| r.kind == Kind::ListItem) {
                    run.checked = Some(done);
                }
            }
            // Not enabled: footnotes, math, metadata.
            _ => {}
        }
    }

    fn start(&mut self, tag: Tag<'_>) {
        match tag {
            Tag::Paragraph => {
                if self.items > 0 {
                    // A loose list item's second paragraph goes on a new
                    // line of the same item.
                    if let Some(run) = self.cur.as_mut().filter(|r| !r.spans.is_empty()) {
                        run.push(Span {
                            text: "\n".into(),
                            bold: false,
                            italic: false,
                            strike: false,
                            code: false,
                            href: None,
                        });
                    }
                } else {
                    let run = self.block_kind();
                    self.open(run);
                }
            }
            Tag::Heading { level, .. } => {
                if self.items == 0 {
                    let mut run = Run::new(Kind::Heading, 0);
                    run.level = heading_level(level);
                    self.open(run);
                }
            }
            Tag::BlockQuote(_) => {
                self.flush();
                self.quote += 1;
            }
            Tag::CodeBlock(kind) => {
                self.flush();
                let language = match kind {
                    CodeBlockKind::Fenced(info) => info
                        .split_whitespace()
                        .next()
                        .filter(|l| !l.is_empty())
                        .map(str::to_owned),
                    CodeBlockKind::Indented => None,
                };
                self.code = Some((String::new(), language));
            }
            Tag::HtmlBlock => {
                if self.items == 0 {
                    let run = self.block_kind();
                    self.open(run);
                }
            }
            Tag::List(start) => {
                self.flush();
                self.lists.push(start);
            }
            Tag::Item => {
                self.flush();
                let ordinal = match self.lists.last_mut() {
                    Some(Some(n)) => {
                        let this = *n;
                        *n += 1;
                        Some(this)
                    }
                    _ => None,
                };
                let mut run = Run::new(Kind::ListItem, self.list_depth());
                run.ordinal = ordinal;
                self.cur = Some(run);
                self.items += 1;
            }
            Tag::Table(_) => self.flush(),
            Tag::TableHead => {
                self.in_head = true;
                self.row = Some(Row {
                    spans: Vec::new(),
                    header: true,
                });
            }
            Tag::TableRow => {
                self.row = Some(Row {
                    spans: Vec::new(),
                    header: self.in_head,
                });
            }
            Tag::TableCell => {
                if let Some(row) = self.row.as_mut().filter(|r| !r.spans.is_empty()) {
                    row.spans.push(Span {
                        text: "  ·  ".into(),
                        bold: false,
                        italic: false,
                        strike: false,
                        code: false,
                        href: None,
                    });
                }
            }
            Tag::Emphasis => self.italic += 1,
            Tag::Strong => self.bold += 1,
            Tag::Strikethrough => self.strike += 1,
            Tag::Link { dest_url, .. } => self.links.push(safe_href(&dest_url)),
            Tag::Image { .. } => self.alt = Some(String::new()),
            _ => {}
        }
    }

    fn end(&mut self, tag: TagEnd) {
        match tag {
            TagEnd::Paragraph | TagEnd::Heading(_) => {
                if self.items == 0 {
                    self.flush();
                }
            }
            TagEnd::HtmlBlock => {
                if let Some(last) = self.cur.as_mut().and_then(|r| r.spans.last_mut()) {
                    let trimmed = last.text.trim_end_matches('\n').len();
                    last.text.truncate(trimmed);
                }
                if self.items == 0 {
                    self.flush();
                }
            }
            TagEnd::BlockQuote(_) => {
                self.flush();
                self.quote = self.quote.saturating_sub(1);
            }
            TagEnd::CodeBlock => {
                if let Some((mut code, language)) = self.code.take() {
                    if code.ends_with('\n') {
                        code.pop();
                    }
                    self.out.push(Out::Code { code, language });
                }
            }
            TagEnd::List(_) => {
                self.flush();
                self.lists.pop();
            }
            TagEnd::Item => {
                self.flush();
                self.items = self.items.saturating_sub(1);
            }
            TagEnd::TableHead | TagEnd::TableRow => {
                if let Some(row) = self.row.take() {
                    if !row.spans.is_empty() {
                        let mut run = Run::new(Kind::Paragraph, 0);
                        run.spans = row.spans;
                        self.out.push(Out::Rich(run));
                    }
                }
                if tag == TagEnd::TableHead {
                    self.in_head = false;
                }
            }
            TagEnd::Emphasis => self.italic = self.italic.saturating_sub(1),
            TagEnd::Strong => self.bold = self.bold.saturating_sub(1),
            TagEnd::Strikethrough => self.strike = self.strike.saturating_sub(1),
            TagEnd::Link => {
                self.links.pop();
            }
            TagEnd::Image => {
                // The alt text is the content; the address is never
                // followed. Italic only, as the app does it.
                if let Some(alt) = self.alt.take().filter(|a| !a.is_empty()) {
                    self.span(Span {
                        text: alt,
                        bold: false,
                        italic: true,
                        strike: false,
                        code: false,
                        href: None,
                    });
                }
            }
            _ => {}
        }
    }
}

fn heading_level(level: HeadingLevel) -> u8 {
    match level {
        HeadingLevel::H1 => 1,
        HeadingLevel::H2 => 2,
        HeadingLevel::H3 => 3,
        HeadingLevel::H4 => 4,
        HeadingLevel::H5 => 5,
        HeadingLevel::H6 => 6,
    }
}

/// A link target the app may follow, or `None` (shown as plain text):
/// only `http`, `https` and `mailto`, never a relative one.
fn safe_href(raw: &str) -> Option<String> {
    let target = raw.trim();
    let (scheme, _) = target.split_once(':')?;
    let mut chars = scheme.chars();
    let well_formed = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    let allowed = matches!(
        scheme.to_ascii_lowercase().as_str(),
        "http" | "https" | "mailto"
    );
    (well_formed && allowed).then(|| target.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(md: &str) -> Value {
        formatted(md).map_or(Value::Null, Value::Array)
    }

    #[test]
    fn plain_text_stays_one_text_block() {
        assert_eq!(f("Done, the tests pass."), Value::Null);
        assert_eq!(
            f("Two lines\nof plain text.\n\nAnd a second paragraph."),
            Value::Null
        );
        assert_eq!(f("@alice can you look? 2 * 3 = 6"), Value::Null);
        assert_eq!(f("   "), Value::Null);
    }

    #[test]
    fn emphasis_code_and_mentions_are_spans() {
        assert_eq!(
            f("**Done.** Ask `@alice` or @bob, *please*."),
            json!([{"type": "rich_text", "kind": "paragraph", "spans": [
                {"text": "Done.", "bold": true},
                {"text": " Ask "},
                {"text": "@alice", "code": true},
                {"text": " or @bob, "},
                {"text": "please", "italic": true},
                {"text": "."},
            ]}])
        );
    }

    #[test]
    fn headings_lists_tasks_quotes_and_code() {
        let md = "# Plan\n\n1. roll\n2. wait\n   - nested\n\n- [x] done\n- [ ] open\n\n> careful\n\n```rust title\nfn main() {}\n```\n\n---\n";
        assert_eq!(
            f(md),
            json!([
                {"type": "rich_text", "kind": "heading", "level": 1, "spans": [{"text": "Plan"}]},
                {"type": "rich_text", "kind": "list_item", "ordinal": 1, "spans": [{"text": "roll"}]},
                {"type": "rich_text", "kind": "list_item", "ordinal": 2, "spans": [{"text": "wait"}]},
                {"type": "rich_text", "kind": "list_item", "depth": 1, "spans": [{"text": "nested"}]},
                {"type": "rich_text", "kind": "list_item", "checked": true, "spans": [{"text": "done"}]},
                {"type": "rich_text", "kind": "list_item", "checked": false, "spans": [{"text": "open"}]},
                {"type": "rich_text", "kind": "quote", "depth": 1, "spans": [{"text": "careful"}]},
                {"type": "code", "code": "fn main() {}", "language": "rust"},
                {"type": "divider"},
            ])
        );
    }

    #[test]
    fn an_ordered_list_keeps_its_start() {
        assert_eq!(
            f("3. third\n4. fourth"),
            json!([
                {"type": "rich_text", "kind": "list_item", "ordinal": 3, "spans": [{"text": "third"}]},
                {"type": "rich_text", "kind": "list_item", "ordinal": 4, "spans": [{"text": "fourth"}]},
            ])
        );
    }

    #[test]
    fn links_keep_only_safe_targets_and_images_are_their_alt_text() {
        assert_eq!(
            f("[docs](https://example.com/a) [x](javascript:alert(1)) [rel](/x) ![a cat](https://example.com/c.png)"),
            json!([{"type": "rich_text", "kind": "paragraph", "spans": [
                {"text": "docs", "href": "https://example.com/a"},
                {"text": " x rel "},
                {"text": "a cat", "italic": true},
            ]}])
        );
    }

    #[test]
    fn html_is_text_and_a_table_is_rows() {
        assert_eq!(
            f("<b>hi</b> there"),
            Value::Null,
            "inline HTML is plain text, so nothing to format"
        );
        assert_eq!(
            f("| a | b |\n|---|---|\n| 1 | **2** |"),
            json!([
                {"type": "rich_text", "kind": "paragraph", "spans": [{"text": "a", "bold": true}, {"text": "  ·  "}, {"text": "b", "bold": true}]},
                {"type": "rich_text", "kind": "paragraph", "spans": [{"text": "1"}, {"text": "  ·  "}, {"text": "2", "bold": true}]},
            ])
        );
    }

    #[test]
    fn the_block_count_is_capped() {
        let md = "- x\n".repeat(MAX_BLOCKS + 50);
        assert_eq!(formatted(&md).unwrap().len(), MAX_BLOCKS);
    }

    #[test]
    fn the_session_prefix_is_not_formatted() {
        assert_eq!(body_of("bob: # Plan", "bob"), "# Plan");
        assert_eq!(body_of("bobby: x", "bob"), "bobby: x");
        assert_eq!(body_of("no prefix", "bob"), "no prefix");
    }

    // ---- the shared vectors (`tests/vectors/markdown_blocks.json`) -----

    const VECTORS: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/markdown_blocks.json"
    );

    /// Name, what it shows, and the text exactly as a session sends it.
    fn vector_inputs() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            (
                "plain",
                "No markdown: one text block, no formatted array.",
                "bob: Done, the tests pass.\nNext: the soak, then @alice rolls it.",
            ),
            (
                "emphasis-and-mentions",
                "Bold, italic and inline code are spans; a mention stays text inside them.",
                "bob: **Done.** Ask @alice, *then* run `just test`.",
            ),
            (
                "heading-and-lists",
                "A heading on the first line after the prefix, a numbered list and a task list.",
                "bob: ## Options\n\n1. Roll it now\n2. Wait for the soak\n   - it ends at noon\n\n- [x] tests\n- [ ] docs",
            ),
            (
                "code-block",
                "A fenced block with a language, and the paragraph before it.",
                "bob: Run this:\n\n```sh\njust test\njust lint\n```",
            ),
            (
                "quote-link-divider",
                "A quote, a safe link, an unsafe link shown as text, and a divider.",
                "bob: > the soak is green\n\nSee [the runbook](https://example.com/rb) or [this](javascript:void(0)).\n\n---\n\n~~old plan~~",
            ),
            (
                "table",
                "A table is one line per row, the header bold, cells joined by a dot.",
                "bob: | lane | state |\n|---|---|\n| relay | **green** |",
            ),
            (
                "session-reply",
                "A whole reply: bold, a list with inline code and a mention, and a code block.",
                "bob: **Done.** Two things:\n\n- the *tests* pass\n- `just lint` is clean, @alice\n\n```sh\njust test\n```",
            ),
            (
                "no-prefix",
                "A text without the session's prefix is formatted whole.",
                "# Report\n\nAll *three* passed.",
            ),
        ]
    }

    fn build_vectors() -> Value {
        let cases: Vec<Value> = vector_inputs()
            .into_iter()
            .map(|(name, description, text)| {
                let body = body_of(text, "bob");
                json!({
                    "name": name,
                    "description": description,
                    "session_name": "bob",
                    "text": text,
                    "source": body,
                    "formatted": formatted(body),
                })
            })
            .collect();
        json!({
            "description": "A session's markdown as blocks. The device host sends a signed session reply as one text block whose text is what the session signed; when the text, without the session's `name: ` prefix (`source` here), has more than plain paragraphs, the block also carries `formatted`: rich_text, code and divider blocks in the app's block JSON, with no `source` field (the receiver sets each rich_text block's source to `source`). `formatted: null` means the block carries no formatted array. The same file, byte for byte, is airdress-cli's tests/vectors/markdown_blocks.json and the app's test/features/chat/markdown_blocks_vectors.json; change both or neither.",
            "cases": cases,
        })
    }

    /// `AIRDRESS_VECTORS_WRITE=1` rewrites the file; otherwise it must be
    /// what this code computes, byte for byte.
    #[test]
    fn the_markdown_vector_file_is_what_this_code_computes() {
        let want = format!(
            "{}\n",
            serde_json::to_string_pretty(&build_vectors()).unwrap()
        );
        if std::env::var("AIRDRESS_VECTORS_WRITE").as_deref() == Ok("1") {
            std::fs::write(VECTORS, &want).unwrap();
        }
        let have = std::fs::read_to_string(VECTORS).expect("the vector file");
        assert_eq!(
            have, want,
            "tests/vectors/markdown_blocks.json is stale: run AIRDRESS_VECTORS_WRITE=1 cargo test \
             --features mls --lib formatted, and copy it to the app"
        );
    }

    /// Every case that formats is something the app can draw: only the
    /// three block types, and never a `source` on the wire.
    #[test]
    fn every_vector_holds_only_blocks_the_app_draws() {
        let file: Value = serde_json::from_str(&std::fs::read_to_string(VECTORS).unwrap()).unwrap();
        let cases = file["cases"].as_array().unwrap();
        assert_eq!(cases.len(), vector_inputs().len());
        assert!(cases.iter().any(|c| c["formatted"].is_null()));
        for c in cases {
            for b in c["formatted"].as_array().into_iter().flatten() {
                assert!(matches!(
                    b["type"].as_str(),
                    Some("rich_text" | "code" | "divider")
                ));
                assert!(b.get("source").is_none());
            }
        }
    }
}
