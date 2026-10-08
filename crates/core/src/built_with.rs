//! What Keep Shipping is built with: the venture's own entry in the Factory
//! Zero registry, vendored at build time.
//!
//! The entry (`built_with.json`, beside this module) is a verbatim copy of the
//! FZ-012 venture in the published registry at
//! <https://factory0.ventures/stack.json>. It is read with [`include_str!`] —
//! there is no fetch at run time, so `about`, `--version` and the review page
//! answer from the binary alone, and the crate stays I/O-free for `wasm32`.
//! To update it, re-vendor the FZ-012 entry from the registry and commit it;
//! `KS_STACK_SYNC=1 cargo test -p ks-core --test stack_sync` fails when the
//! vendored copy has drifted from the published one.
//!
//! `status` is an enum, not a string, so an entry the registry calls `planned`
//! cannot be rendered as live by anything built on this module: there is no
//! third state to fall into and no spelling to get wrong.

/// The published registry the vendored entry is checked against.
pub const REGISTRY_URL: &str = "https://factory0.ventures/stack.json";

/// Where the subprocessors list is published. `keepshipping.run/privacy` does
/// not exist yet (it is a 404), so the registry's venture page stands in until
/// the product has a privacy page of its own to link.
pub const SUBPROCESSORS_URL: &str = "https://factory0.ventures/ventures/keep-shipping/";

/// The vendored FZ-012 entry, exactly as the registry publishes it.
const VENTURE_JSON: &str = include_str!("built_with.json");

/// Whether a `use` is in service today or only decided and tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// In use today.
    Live,
    /// Decided and tracked, not in use yet.
    Planned,
}

impl Status {
    /// The registry's own word for the status, as published.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Live => "live",
            Status::Planned => "planned",
        }
    }
}

/// The FZ-012 venture entry: the product, and what it is built with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Venture {
    /// The registry id, `FZ-012`.
    pub id: String,
    /// The product's name, `Keep Shipping`.
    pub name: String,
    /// The product's own site.
    pub site: String,
    /// The venture's page in the registry, and today the subprocessors list.
    pub page: String,
    /// The sister ventures and third parties, in the registry's order.
    pub uses: Vec<Use>,
}

/// One thing the product is built with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Use {
    /// The registry's id for it: a sister venture's (`FZ-004`) or a
    /// third-party slug (`polar`).
    pub id: String,
    /// Its name, as the registry writes it.
    pub name: String,
    /// `factory-zero` for a sister venture, `third-party` otherwise.
    pub kind: String,
    /// Where it lives, linked from every rendering.
    pub url: String,
    /// What role it plays here, from the registry's role vocabulary.
    pub role: String,
    /// The registry's phrase for the role, e.g. `Built with`.
    pub phrase: String,
    /// Whether it is in use today.
    pub status: Status,
    /// One line on what the use actually covers here.
    pub note: String,
}

/// The vendored entry, parsed. A copy that does not parse is a bug in the
/// vendoring, not a user's problem — hence the panic naming the way back.
pub fn venture() -> Venture {
    parse(VENTURE_JSON).expect("vendored built_with.json failed to parse; run the stack-sync check")
}

/// The vendored JSON, verbatim, for the stack-sync test to compare against the
/// published registry.
pub fn venture_json() -> &'static str {
    VENTURE_JSON
}

/// `Name (status)` for every use, comma-space joined in the registry's order —
/// the one-line form `--version` prints.
pub fn summary() -> String {
    venture()
        .uses
        .iter()
        .map(|u| format!("{} ({})", u.name, u.status.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The JSON parsed, or what is wrong with it. Only the shapes the registry
/// emits are read — objects, arrays, strings — because that is all the entry
/// uses, and ks-core takes no dependencies (the wasm gate).
fn parse(src: &str) -> Result<Venture, String> {
    let mut reader = Reader { src, at: 0 };
    let value = reader.value()?;
    reader.end()?;
    venture_of(&value)
}

/// What the parser read: the subset of JSON the registry entry uses.
#[derive(Debug, PartialEq)]
enum Json {
    Str(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

struct Reader<'a> {
    src: &'a str,
    at: usize,
}

impl Reader<'_> {
    fn skip(&mut self) {
        self.at += self.src[self.at..].len() - self.src[self.at..].trim_start().len();
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip();
        self.src.as_bytes().get(self.at).copied()
    }

    fn eat(&mut self, byte: u8) -> Result<(), String> {
        match self.peek() {
            Some(found) if found == byte => {
                self.at += 1;
                Ok(())
            }
            Some(found) => Err(format!(
                "expected `{}`, found `{}` at byte {}",
                byte as char, found as char, self.at
            )),
            None => Err(format!("expected `{}`, found the end at byte {}", byte as char, self.at)),
        }
    }

    fn end(&mut self) -> Result<(), String> {
        self.skip();
        if self.at == self.src.len() {
            Ok(())
        } else {
            Err(format!("trailing characters at byte {}", self.at))
        }
    }

    /// A quoted string, escapes decoded. Raw non-ASCII bytes (the entry's `’`)
    /// pass through untouched, so the registry's own punctuation survives.
    fn string(&mut self) -> Result<String, String> {
        self.eat(b'"')?;
        let mut out = String::new();
        loop {
            let rest = &self.src[self.at..];
            match rest.bytes().position(|b| b == b'"' || b == b'\\') {
                None => return Err(format!("unterminated string at byte {}", self.at)),
                Some(0) => {}
                Some(len) => {
                    out.push_str(&rest[..len]);
                    self.at += len;
                }
            }
            match self.src.as_bytes()[self.at] {
                b'"' => {
                    self.at += 1;
                    return Ok(out);
                }
                _ => {
                    self.at += 1;
                    self.escape(&mut out)?;
                }
            }
        }
    }

    /// One backslash escape, consumed.
    fn escape(&mut self, out: &mut String) -> Result<(), String> {
        let ch = self.src[self.at..].chars().next().ok_or("escape ends the input")?;
        self.at += ch.len_utf8();
        match ch {
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            '/' => out.push('/'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'u' => out.push(self.unicode()?),
            other => return Err(format!("unknown escape `\\{other}`")),
        }
        Ok(())
    }

    /// `\\uXXXX`, surrogate pairs combined; a lone surrogate is refused rather
    /// than smuggled through as replacement characters.
    fn unicode(&mut self) -> Result<char, String> {
        let first = self.hex4()?;
        let code = if (0xD800..0xDC00).contains(&first) {
            if !self.src[self.at..].starts_with("\\u") {
                return Err("unpaired high surrogate".into());
            }
            self.at += 2;
            let second = self.hex4()?;
            if !(0xDC00..0xE000).contains(&second) {
                return Err("unpaired high surrogate".into());
            }
            0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
        } else if (0xDC00..0xE000).contains(&first) {
            return Err("unpaired low surrogate".into());
        } else {
            first
        };
        char::from_u32(code).ok_or_else(|| format!("bad `\\u{code:04x}` escape"))
    }

    /// Four hexadecimal digits, consumed.
    fn hex4(&mut self) -> Result<u32, String> {
        let digits = self.src.get(self.at..self.at + 4).ok_or("truncated `\\u` escape")?;
        if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("`{digits}` is not four hexadecimal digits"));
        }
        self.at += 4;
        u32::from_str_radix(digits, 16).map_err(|e| e.to_string())
    }

    /// One JSON value: a string, an array or an object — the registry emits no
    /// numbers, booleans or null in this entry, and reading less is how a
    /// shape the parser does not know about fails loudly instead of quietly.
    fn value(&mut self) -> Result<Json, String> {
        match self.peek() {
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b'[') => {
                self.at += 1;
                let mut items = Vec::new();
                loop {
                    match self.peek() {
                        Some(b']') => {
                            self.at += 1;
                            return Ok(Json::Array(items));
                        }
                        Some(_) => items.push(self.value()?),
                        None => return Err("unterminated array".into()),
                    }
                    match self.peek() {
                        Some(b',') => self.at += 1,
                        Some(b']') => {}
                        _ => return Err("expected `,` or `]` in an array".into()),
                    }
                }
            }
            Some(b'{') => {
                self.at += 1;
                let mut fields = Vec::new();
                loop {
                    match self.peek() {
                        Some(b'}') => {
                            self.at += 1;
                            return Ok(Json::Object(fields));
                        }
                        Some(b'"') => {
                            let key = self.string()?;
                            self.eat(b':')?;
                            fields.push((key, self.value()?));
                        }
                        Some(_) => return Err("expected a key or `}` in an object".into()),
                        None => return Err("unterminated object".into()),
                    }
                    match self.peek() {
                        Some(b',') => self.at += 1,
                        Some(b'}') => {}
                        _ => return Err("expected `,` or `}` in an object".into()),
                    }
                }
            }
            Some(found) => Err(format!(
                "expected a string, an array or an object, found `{}` at byte {}",
                found as char, self.at
            )),
            None => Err("no value where one was expected".into()),
        }
    }
}

/// The parsed JSON as the venture entry, unknown keys ignored the way a
/// schemaless reader would — the stack-sync test is what fails on drift.
fn venture_of(json: &Json) -> Result<Venture, String> {
    let Json::Object(fields) = json else {
        return Err("the entry is not an object".into());
    };
    let field = |wanted: &str, fields: &[(String, Json)]| -> Result<String, String> {
        fields
            .iter()
            .find(|(key, _)| key == wanted)
            .map(|(_, value)| match value {
                Json::Str(text) => Ok(text.clone()),
                _ => Err(format!("`{wanted}` is not a string")),
            })
            .unwrap_or_else(|| Err(format!("the entry has no `{wanted}`")))
    };
    let uses = match fields.iter().find(|(key, _)| key == "uses") {
        Some((_, Json::Array(items))) => items.iter().map(use_of).collect::<Result<Vec<_>, _>>()?,
        Some((_, _)) => return Err("`uses` is not an array".into()),
        None => return Err("the entry has no `uses`".into()),
    };
    Ok(Venture {
        id: field("id", fields)?,
        name: field("name", fields)?,
        site: field("site", fields)?,
        page: field("page", fields)?,
        uses,
    })
}

/// One element of `uses` as a [`Use`].
fn use_of(json: &Json) -> Result<Use, String> {
    let Json::Object(fields) = json else {
        return Err("an entry of `uses` is not an object".into());
    };
    let status = match fields.iter().find(|(key, _)| key == "status") {
        Some((_, Json::Str(text))) => match text.as_str() {
            "live" => Status::Live,
            "planned" => Status::Planned,
            other => return Err(format!("`{other}` is not a status the registry defines")),
        },
        Some((_, _)) => return Err("`status` is not a string".into()),
        None => return Err("an entry of `uses` has no `status`".into()),
    };
    let field = |wanted: &str| -> Result<String, String> {
        fields
            .iter()
            .find(|(key, _)| key == wanted)
            .map(|(_, value)| match value {
                Json::Str(text) => Ok(text.clone()),
                _ => Err(format!("`{wanted}` is not a string")),
            })
            .unwrap_or_else(|| Err(format!("an entry of `uses` has no `{wanted}`")))
    };
    Ok(Use {
        id: field("id")?,
        name: field("name")?,
        kind: field("kind")?,
        url: field("url")?,
        role: field("role")?,
        phrase: field("phrase")?,
        status,
        note: field("note")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entry parses, and is the venture it says it is.
    #[test]
    fn the_vendored_entry_is_keep_shipping() {
        let venture = venture();
        assert_eq!(venture.id, "FZ-012");
        assert_eq!(venture.name, "Keep Shipping");
        assert_eq!(venture.site, "https://keepshipping.run/");
        assert!(!venture.uses.is_empty(), "an entry with no uses says nothing");
    }

    /// Every use is fully described and linked, and the entry's own page is
    /// where the subprocessors link points.
    #[test]
    fn every_use_is_complete_and_linked() {
        let venture = venture();
        assert_eq!(SUBPROCESSORS_URL, venture.page, "the subprocessors link is the venture page");
        for u in &venture.uses {
            assert!(u.url.starts_with("https://"), "{} is not an https link: {}", u.name, u.url);
            assert!(!u.phrase.is_empty(), "{} has no phrase", u.name);
            assert!(!u.note.is_empty(), "{} has no note", u.name);
            assert!(!u.kind.is_empty(), "{} has no kind", u.name);
            assert!(!u.role.is_empty(), "{} has no role", u.name);
            // The enum has exactly the registry's two statuses; as_str is the
            // published spelling of each.
            assert!(
                matches!(u.status, Status::Live | Status::Planned)
                    && matches!(u.status.as_str(), "live" | "planned"),
                "{} has an unknown status",
                u.name
            );
        }
    }

    /// The one-line form `--version` prints, in the registry's order.
    #[test]
    fn the_summary_names_every_use_with_its_status() {
        assert_eq!(
            summary(),
            "Cratefield (planned), SupportGenius (planned), Polar (planned), \
             Google Fonts (live), Cloudflare (live)"
        );
    }

    /// The parser refuses a status the registry does not define, so nothing
    /// downstream can invent a third state.
    #[test]
    fn an_unknown_status_is_refused() {
        let broken = VENTURE_JSON.replace("\"status\": \"live\"", "\"status\": \"shipping\"");
        assert!(parse(&broken).is_err());
    }
}
