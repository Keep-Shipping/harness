//! The language features, as pure functions over a checked document:
//! diagnostics, hover, go-to-definition, completion and rename. The server
//! owns the transport and the open documents; everything it answers comes
//! from here.
//!
//! Completion is line-based: it has to work while the file is still being
//! typed, where the parse tree is whatever the recovery managed to build.
//! The checks that hold are the ones that cannot change mid-keystroke —
//! which block the line sits in, and which names the checked file already
//! declares.

use ks_core::{Catalog, Checked, Step, StepTypes};
use ks_lang::{Scalar, Span, classify_scalar};
use serde_json::{Value, json};

use crate::docs;
use crate::text::{Encoding, LineIndex, Position, Range, clamp};

/// The `source` on every diagnostic and every hover the server publishes.
pub const SOURCE: &str = "keepshipping";

/// The context namespaces a reference's first segment may name. The checker
/// knows these as `NAMESPACES`; the copy here is for completion, where no
/// check has run over the text being typed.
const NAMESPACES: &[(&str, &[&str])] = &[
    ("git", &["sha", "ref", "branch", "tag"]),
    ("pr", &["number", "base"]),
    ("run", &["id", "actor", "is_agent"]),
    ("env", &["name"]),
    ("ci", &["provider"]),
    ("secrets", &[]),
];

/// One open document: its text, the check over it, and the line index its
/// positions come from. Building one re-checks the file, so the server
/// builds one per document version and answers every request from it.
pub struct Doc {
    text: String,
    checked: Checked,
    index: LineIndex,
}

impl Doc {
    pub fn new(text: String, encoding: Encoding) -> Doc {
        let checked = ks_core::check(&ks_lang::parse(&text));
        let index = LineIndex::new(&text, encoding);
        Doc { text, checked, index }
    }

    /// The byte offset a request's `position` names. A position that is not
    /// there (a malformed request, a stale edit) reads as the start.
    pub fn offset_at(&self, position: &Value) -> u32 {
        let line = position["line"].as_u64().unwrap_or(0) as u32;
        let character = position["character"].as_u64().unwrap_or(0) as u32;
        self.index.offset(&self.text, Position { line, character })
    }

    fn range(&self, span: Span) -> Range {
        Range {
            start: self.index.position(&self.text, span.start),
            end: self.index.position(&self.text, span.end),
        }
    }
}

/// Every diagnostic of the file, parser and checker alike: `check` folds
/// the parse diagnostics into its own, so publishing them once here neither
/// drops nor duplicates one.
pub fn diagnostics(doc: &Doc, uri: &str) -> Value {
    let items: Vec<Value> = doc
        .checked
        .diagnostics
        .iter()
        .map(|d| {
            let mut message = d.message.clone();
            for hint in &d.hints {
                message.push_str("\n\nhint: ");
                message.push_str(hint);
            }
            let mut item = json!({
                "range": doc.range(d.span).to_json(),
                "severity": match d.severity {
                    ks_lang::Severity::Error => 1,
                    ks_lang::Severity::Warning => 2,
                },
                "code": d.code.as_str(),
                "source": SOURCE,
                "message": message,
            });
            if !d.labels.is_empty() {
                let related: Vec<Value> = d
                    .labels
                    .iter()
                    .map(|l| {
                        json!({
                            "location": { "uri": uri, "range": doc.range(l.span).to_json() },
                            "message": l.message,
                        })
                    })
                    .collect();
                item["relatedInformation"] = Value::Array(related);
            }
            item
        })
        .collect();
    json!({ "uri": uri, "diagnostics": items })
}

/// The hover at `offset`: the type of whatever the checker typed there,
/// plus the step it names, or the kind and inputs of a step header.
pub fn hover(doc: &Doc, offset: u32) -> Option<Value> {
    for step in doc.checked.workflow.steps() {
        if step.span.contains(offset) {
            let signature =
                format!("```ks\n{}: {}\n```", step.name, step.kind.as_deref().unwrap_or("?"));
            return Some(hover_object(
                doc.range(step.span).to_json(),
                signature + &step_note(doc, step),
            ));
        }
        if let Some(kind) = step.kind.as_deref()
            && step.kind_span.contains(offset)
        {
            return Some(kind_hover(doc, step.kind_span, kind));
        }
    }
    let (span, ty) = doc.checked.type_at(offset)?;
    let text = span.slice(&doc.text);
    let note = match doc.checked.workflow.step(first_segment(text)) {
        Some(step) => step_note(doc, step),
        None => String::new(),
    };
    Some(hover_object(doc.range(span).to_json(), format!("```ks\n{text}: {ty}\n```") + &note))
}

/// The `build:` key a reference names, or the header a cursor sits on.
pub fn definition(doc: &Doc, uri: &str, offset: u32) -> Option<Value> {
    let span = rename_target(doc, offset)?.1;
    Some(json!({ "uri": uri, "range": doc.range(span).to_json() }))
}

/// What completion offers at `offset`, by what the line looks like.
pub fn completion(doc: &Doc, offset: u32) -> Value {
    let items = completion_items(doc, offset);
    json!({ "isIncomplete": false, "items": items })
}

/// The span a rename at `offset` would replace, and the name it holds.
pub fn prepare_rename(doc: &Doc, offset: u32) -> Option<Value> {
    let (name, span) = rename_target(doc, offset)?;
    Some(json!({ "range": doc.range(span).to_json(), "placeholder": name }))
}

/// The edits renaming the step at `offset`, or why the new name is refused.
pub fn rename(doc: &Doc, uri: &str, offset: u32, new_name: &str) -> Result<Value, String> {
    let (name, _) = rename_target(doc, offset).ok_or("there is no step to rename here")?;
    if classify_scalar(new_name) != Scalar::Ident {
        return Err(format!("`{new_name}` is not a step name"));
    }
    if NAMESPACES.iter().any(|(ns, _)| *ns == new_name) {
        return Err(format!("`{new_name}` names a context namespace, so it cannot be a step"));
    }
    if name != new_name && doc.checked.workflow.step(new_name).is_some() {
        return Err(format!("`{new_name}` is already a step in this file"));
    }
    let mut edits =
        vec![edit(doc, doc.checked.workflow.step(name).expect("the step").span, new_name)];
    for occ in occurrences(doc) {
        if occ.name == name {
            edits.push(edit(doc, occ.seg, new_name));
        }
    }
    let mut changes = serde_json::Map::new();
    changes.insert(uri.to_string(), Value::Array(edits));
    Ok(json!({ "changes": changes }))
}

// --- hover ---------------------------------------------------------------

/// A markdown hover over a range.
fn hover_object(range: Value, contents: String) -> Value {
    json!({ "contents": { "kind": "markdown", "value": contents }, "range": range })
}

/// The hover for a step kind named in a header: what it does, and the
/// inputs it checks and the outputs it publishes.
fn kind_hover(doc: &Doc, span: Span, kind: &str) -> Value {
    let mut text = format!("```ks\n{kind}\n```");
    if let Some(note) = docs::kind_doc(kind) {
        text.push_str(&format!("\n\n{note}"));
    }
    let catalog = Catalog::builtin();
    match catalog.step(kind) {
        Some(spec) => {
            // `when:` is an input on every kind, declared by the catalog
            // rather than by the schema.
            let inputs = list(&spec.inputs, &["`when`: bool"]);
            let mut outputs = list(&spec.outputs, &[]);
            if spec.runtime_outputs {
                outputs.push_str(", ");
                outputs.push_str(&join(["`out.<name>` (run time)"]));
            }
            text.push_str(&format!("\n\ninputs: {inputs}\n\noutputs: {outputs}"));
        }
        None => text.push_str("\n\nnot a built-in kind: its inputs and outputs are unchecked."),
    }
    hover_object(doc.range(span).to_json(), text)
}

/// `typed` and `extra` as a comma-separated list of names with their type.
fn list(typed: &[(String, ks_core::Type)], extra: &[&str]) -> String {
    let mut items: Vec<String> = typed.iter().map(|(name, ty)| format!("`{name}`: {ty}")).collect();
    items.extend(extra.iter().map(|item| item.to_string()));
    join(items.iter().map(String::as_str))
}

fn join<'a>(items: impl IntoIterator<Item = &'a str>) -> String {
    let items: Vec<&str> = items.into_iter().collect();
    if items.is_empty() { "none".to_string() } else { items.join(", ") }
}

/// What a step does, and what the comments above its header say about it.
fn step_note(doc: &Doc, step: &Step) -> String {
    let mut note = format!("\n\n`{}` — {}\n", step.name, docs::step_doc(step.kind.as_deref()));
    for comment in doc.index.comments_above(&doc.text, step.span.start) {
        note.push_str(&format!("\n> {comment}\n"));
    }
    note
}

// --- references ----------------------------------------------------------

/// One place a name is written: the whole reference, and its first segment
/// (`build` in `build.digest` and in `{build.digest}`) on its own — that
/// segment is what a rename replaces.
struct Occurrence<'a> {
    name: &'a str,
    span: Span,
    seg: Span,
}

impl Occurrence<'_> {
    /// A cursor anywhere in the reference is on it — on any segment of
    /// `build.digest`, or inside its braces.
    fn on(&self, offset: u32) -> bool {
        self.span.contains(offset) || self.seg.contains(offset)
    }
}

/// Every reference to a step, in source order. The checker's own record of
/// what it typed is the authority here rather than a walk of the syntax
/// tree: it names exactly what it resolved, so a bare step name is found
/// (`to: build`) while a word that merely spells one — a trigger branch, a
/// path, a string literal — is left alone.
fn occurrences<'a>(doc: &'a Doc) -> Vec<Occurrence<'a>> {
    let mut out: Vec<Occurrence<'a>> = doc
        .checked
        .types
        .iter()
        .filter_map(|(span, _)| {
            let text = span.slice(&doc.text);
            let name = first_segment(text);
            doc.checked.workflow.step(name)?;
            let start = span.start + text.find(name)? as u32;
            Some(Occurrence { name, span: *span, seg: Span::new(start, start + name.len() as u32) })
        })
        .collect();
    out.sort_by_key(|o| (o.span.start, o.span.end));
    out.dedup_by_key(|o| (o.span.start, o.span.end));
    out
}

fn first_segment(name: &str) -> &str {
    name.split('.').next().unwrap_or(name)
}

/// The step a cursor sits on: its name and the span of its header.
fn rename_target(doc: &Doc, offset: u32) -> Option<(&str, Span)> {
    for step in doc.checked.workflow.steps() {
        if step.span.contains(offset) {
            return Some((step.name.as_str(), step.span));
        }
    }
    let occ = occurrences(doc).into_iter().find(|o| o.on(offset))?;
    doc.checked.workflow.step(occ.name).map(|step| (occ.name, step.span))
}

fn edit(doc: &Doc, span: Span, new_text: &str) -> Value {
    json!({ "range": doc.range(span).to_json(), "newText": new_text })
}

// --- completion ----------------------------------------------------------

/// Which block the line being typed sits in, as far as indentation says.
enum Section {
    /// Directly under `steps:`: a step header, so its value is a kind.
    Steps,
    /// Directly under the named step: an input of that step.
    Step(String),
    /// Anything else: a plain value.
    Value,
}

fn completion_items(doc: &Doc, offset: u32) -> Vec<Value> {
    let offset = clamp(&doc.text, offset);
    let start = doc.index.line_start(offset);
    let line = doc.index.line_text(&doc.text, offset);
    let column = ((offset - start) as usize).min(line.len());
    let indent = line.len() - line.trim_start().len();
    let before = &line[indent.min(column)..column];
    let section = section_of(doc, start, indent);
    // A `#` before the cursor opened a comment: everything after it is prose.
    if before.starts_with('#') {
        return Vec::new();
    }
    // No colon yet: the user is writing the key, and the only keys worth
    // offering are the inputs of the step they are inside.
    let Some((key, typed)) = before.split_once(':') else {
        return match section {
            Section::Step(name) => inputs_of(doc, &name),
            _ => Vec::new(),
        };
    };
    let key = key.trim();
    if key.is_empty() || key.contains(char::is_whitespace) {
        return Vec::new();
    }
    // `build.` — the outputs of a step, or a context namespace's values.
    if let Some((head, _)) = typed.trim_start().split_once('.') {
        return match doc.checked.workflow.step(head) {
            Some(step) => outputs_of(doc, step),
            None => namespace_members(doc, head),
        };
    }
    match section {
        // A step header's value is its kind; every other value is a
        // reference to a step, a context or an environment.
        Section::Steps => kinds(),
        _ => reference_values(doc),
    }
}

/// The block a line at `start` indented by `indent` sits in: the nearest
/// line above it that is indented less and opens a block.
fn section_of(doc: &Doc, start: u32, indent: usize) -> Section {
    let mut at = start;
    while at > 0 {
        let end = (at - 1) as usize;
        let line_start = doc.text[..end].rfind('\n').map_or(0, |i| i + 1);
        at = line_start as u32;
        let line = &doc.text[line_start..end];
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if line.len() - line.trim_start().len() >= indent {
            continue;
        }
        if let Some(block) = trimmed.strip_suffix(':') {
            return if block.trim() == "steps" { Section::Steps } else { Section::Value };
        }
        let key = trimmed.split_once(':').map_or("", |(k, _)| k.trim());
        return match doc.checked.workflow.step(key) {
            Some(_) => Section::Step(key.to_string()),
            None => Section::Value,
        };
    }
    Section::Value
}

fn kinds() -> Vec<Value> {
    Catalog::builtin()
        .kinds()
        .map(|spec| item(&spec.name, 7, Some("step kind"), docs::kind_doc(&spec.name)))
        .collect()
}

fn inputs_of(doc: &Doc, step: &str) -> Vec<Value> {
    let catalog = Catalog::builtin();
    let Some(spec) = kind_of(doc, step, &catalog) else { return Vec::new() };
    spec.inputs
        .iter()
        .map(|(name, ty)| item(name, 10, Some(&ty.to_string()), None))
        .chain(std::iter::once(item(
            "when",
            10,
            Some("bool"),
            Some("run the step only when this holds"),
        )))
        .collect()
}

fn outputs_of(doc: &Doc, step: &Step) -> Vec<Value> {
    let catalog = Catalog::builtin();
    let Some(spec) = kind_of(doc, step.name.as_str(), &catalog) else { return Vec::new() };
    let mut items: Vec<Value> =
        spec.outputs.iter().map(|(name, ty)| item(name, 5, Some(&ty.to_string()), None)).collect();
    if spec.runtime_outputs {
        items.push(item(
            "out",
            5,
            None,
            Some("outputs known only at run time, as `<step>.out.<name>`"),
        ));
    }
    items
}

fn reference_values(doc: &Doc) -> Vec<Value> {
    let mut items: Vec<Value> = doc
        .checked
        .workflow
        .steps()
        .iter()
        .map(|step| {
            let detail = step.kind.clone().unwrap_or_else(|| "step".to_string());
            item(&step.name, 6, Some(&detail), step.kind.as_deref().and_then(docs::kind_doc))
        })
        .collect();
    items.extend(
        NAMESPACES
            .iter()
            .map(|(name, _)| item(name, 9, Some("context"), Some("a value of the run itself"))),
    );
    for env in doc.checked.workflow.envs() {
        items.push(item(&env.name, 13, Some("environment"), None));
        for var in &env.vars {
            items.push(item(var, 6, Some("env var"), Some("a variable this environment declares")));
        }
    }
    items
}

fn namespace_members(doc: &Doc, head: &str) -> Vec<Value> {
    let Some((_, members)) = NAMESPACES.iter().find(|(name, _)| *name == head) else {
        return Vec::new();
    };
    if head == "env" {
        let mut items: Vec<Value> = members.iter().map(|m| item(m, 5, Some("any"), None)).collect();
        for env in doc.checked.workflow.envs() {
            for var in &env.vars {
                items.push(item(var, 5, Some("any"), Some("a variable this environment declares")));
            }
        }
        return items;
    }
    members.iter().map(|m| item(m, 5, None, None)).collect()
}

/// The catalog entry for the kind step `name` declares. Read from the
/// header line as well as from the check: while the body of a step is
/// being typed the checker can lose the header's value, and completion
/// still has to know what the inputs are.
fn kind_of<'c>(doc: &Doc, name: &str, catalog: &'c Catalog) -> Option<&'c StepTypes> {
    let kind = doc.checked.workflow.step(name).and_then(|s| s.kind.as_deref());
    catalog.step(kind.or_else(|| header_kind(doc, name))?)
}

/// What a step header line names as its kind, found in the text.
fn header_kind<'a>(doc: &'a Doc, name: &str) -> Option<&'a str> {
    doc.text.lines().find_map(|line| {
        let (key, value) = line.trim().split_once(':')?;
        (key.trim() == name).then(|| value.trim()).filter(|value| !value.is_empty())
    })
}

/// A completion item: the label, the LSP kind, and what the client shows
/// beside it. `doc` is shown on hover in the completion list.
fn item(label: &str, kind: u8, detail: Option<&str>, doc: Option<&str>) -> Value {
    let mut value = json!({ "label": label, "kind": kind });
    if let Some(detail) = detail {
        value["detail"] = json!(detail);
    }
    if let Some(text) = doc {
        value["documentation"] = json!({ "kind": "markdown", "value": text });
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    const HERO: &str = "\
# deploy the api: image -> infra -> prod
steps:
  # the image every deploy runs
  build:   oci.image
    from:  ./Dockerfile

  deploy:  k8s.rollout
    image: build.digest     # oci.Digest, never a tag
";

    fn doc_at(src: &str, needle: &str) -> (Doc, u32) {
        let doc = Doc::new(src.to_string(), Encoding::Utf16);
        let at = src.find(needle).expect("the text") as u32;
        (doc, at)
    }

    fn hover_text(doc: &Doc, offset: u32) -> String {
        hover(doc, offset).expect("a hover")["contents"]["value"].as_str().expect("text").into()
    }

    #[test]
    fn a_reference_hovers_as_its_type_and_the_step_it_names() {
        let (doc, at) = doc_at(HERO, "build.digest");
        let text = hover_text(&doc, at);
        assert!(text.contains("build.digest: oci.Digest"), "{text}");
        assert!(text.contains("oci.image"), "{text}");
        // The comment above the `build:` header is the user's own prose.
        assert!(text.contains("the image every deploy runs"), "{text}");
    }

    #[test]
    fn a_step_header_hovers_as_its_kind() {
        let (doc, at) = doc_at(HERO, "oci.image");
        let text = hover_text(&doc, at);
        assert!(text.contains("```ks\noci.image\n```"), "{text}");
        assert!(text.contains("container image"), "{text}");
        assert!(text.contains("inputs: `from`: path"), "{text}");
        assert!(text.contains("outputs: `digest`: oci.Digest"), "{text}");
    }

    #[test]
    fn the_step_name_itself_hovers_as_the_step() {
        let (doc, at) = doc_at(HERO, "build:   oci");
        let text = hover_text(&doc, at);
        assert!(text.contains("build: oci.image"), "{text}");
        assert!(text.contains("container image"), "{text}");
    }

    #[test]
    fn hover_where_nothing_is_typed_answers_nothing() {
        let (doc, _) = doc_at(HERO, "steps:");
        assert!(hover(&doc, 0).is_none());
    }

    #[test]
    fn diagnostics_carry_the_code_the_severity_and_the_range() {
        let broken = "steps:\n  build: oci.image\n  deploy: k8s.rollout\n    image: build.tag\n";
        let doc = Doc::new(broken.to_string(), Encoding::Utf16);
        let published = diagnostics(&doc, "file:///ship.ks");
        assert_eq!(published["uri"], "file:///ship.ks");
        let items = published["diagnostics"].as_array().expect("an array").clone();
        let mismatch = items.iter().find(|d| d["code"] == "KS0101").expect("a type mismatch");
        assert_eq!(mismatch["severity"], 1);
        assert_eq!(mismatch["source"], SOURCE);
        assert_eq!(mismatch["range"]["start"]["line"], 3);
        assert_eq!(mismatch["range"]["start"]["character"], 11);
        assert!(mismatch["message"].as_str().expect("text").contains("oci.Digest"), "{mismatch}");
    }

    #[test]
    fn a_clean_file_publishes_nothing() {
        let doc = Doc::new(HERO.to_string(), Encoding::Utf16);
        let published = diagnostics(&doc, "file:///ship.ks");
        assert_eq!(published["diagnostics"], json!([]));
    }

    #[test]
    fn a_definition_jumps_to_the_step_key() {
        let (doc, at) = doc_at(HERO, "digest");
        let found = definition(&doc, "file:///ship.ks", at).expect("a definition");
        assert_eq!(found["uri"], "file:///ship.ks");
        // The `build:` key, wherever the file's comments put it.
        assert_eq!(found["range"]["start"]["line"], 3);
        assert_eq!(found["range"]["end"]["line"], 3);
    }

    #[test]
    fn a_definition_jumps_from_either_segment_and_from_an_interpolation() {
        let src = "steps:\n  build: oci.image\n    push: ghcr.io/acme/api:{build.digest}\n";
        let (doc, first) = doc_at(src, "build.digest}");
        let at = |offset| {
            definition(&doc, "f", offset).expect("a definition")["range"]["start"]["line"].clone()
        };
        assert_eq!(at(first), json!(1), "the step segment");
        assert_eq!(at(first + 10), json!(1), "the output segment");
    }

    #[test]
    fn a_reference_to_something_undeclared_has_no_definition() {
        let (doc, at) = doc_at(HERO, "./Dockerfile");
        assert!(definition(&doc, "file:///ship.ks", at).is_none());
    }

    fn labels(doc: &Doc, offset: u32) -> Vec<String> {
        completion(doc, offset)["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|i| i["label"].as_str().expect("a label").to_string())
            .collect()
    }

    /// A document and a cursor just after `needle`, the way an editor
    /// sends one: a position, not a byte offset.
    fn typing(src: &str, needle: &str) -> (Doc, u32) {
        let doc = Doc::new(src.to_string(), Encoding::Utf16);
        (doc, src.find(needle).expect("the text") as u32 + needle.len() as u32)
    }

    #[test]
    fn a_step_header_offers_the_step_kinds() {
        let (doc, at) = typing("steps:\n  build: ", "build: ");
        let labels = labels(&doc, at);
        assert!(labels.contains(&"oci.image".to_string()), "{labels:?}");
        assert!(labels.contains(&"approval".to_string()), "{labels:?}");
    }

    #[test]
    fn a_key_inside_a_step_offers_that_kinds_inputs() {
        let (doc, at) = typing("steps:\n  build: oci.image\n    fr", "    fr");
        assert_eq!(
            labels(&doc, at),
            [
                "from",
                "context",
                "args",
                "secrets",
                "platforms",
                "target",
                "push",
                "sign",
                "sbom",
                "cache",
                "when"
            ]
        );
    }

    #[test]
    fn a_partial_dotted_name_offers_that_step_outputs() {
        let src = "steps:\n  build: oci.image\n  deploy: k8s.rollout\n    image: build.";
        let (doc, at) = typing(src, "build.");
        assert_eq!(labels(&doc, at), ["digest", "ref", "tag", "signed", "sbom", "platforms"]);
    }

    #[test]
    fn a_partial_namespace_name_offers_its_members() {
        let src = "steps:\n  build: oci.image\n    push: git.";
        let (doc, at) = typing(src, "git.");
        assert_eq!(labels(&doc, at), ["sha", "ref", "branch", "tag"]);
    }

    #[test]
    fn a_bare_value_offers_steps_namespaces_and_environments() {
        let src =
            "envs:\n  prod:\n    vars:\n      region: eu\nsteps:\n  build: oci.image\n    from: ";
        let (doc, at) = typing(src, "from: ");
        let labels = labels(&doc, at);
        for want in ["build", "git", "secrets", "prod", "region"] {
            assert!(labels.contains(&want.to_string()), "{want} missing from {labels:?}");
        }
    }

    #[test]
    fn completion_in_a_comment_or_a_top_level_key_offers_nothing() {
        let src = "name: api\n# the trigger\non";
        let doc = Doc::new(src.to_string(), Encoding::Utf16);
        assert!(labels(&doc, 17).is_empty(), "a top-level key");
        assert!(labels(&doc, src.find("the trigger").expect("the comment") as u32).is_empty());
        // A `#` is a comment whatever follows it.
        let src = "steps:\n  build: oci.image\n    #from: bui";
        let (doc, at) = typing(src, "#from: bui");
        assert!(labels(&doc, at).is_empty());
    }

    #[test]
    fn renaming_a_step_edits_its_header_and_every_reference() {
        let src = "steps:\n  build: oci.image\n  deploy: k8s.rollout\n    image: build.digest\n    to: apply.out.x\n";
        let (doc, at) = doc_at(src, "build.digest");
        let edit = rename(&doc, "f", at, "compile").expect("a rename");
        let edits = edit["changes"]["f"].as_array().expect("edits").clone();
        assert_eq!(edits.len(), 2, "{edit}");
        assert_eq!(edits[0]["range"]["start"]["line"], 1, "the header");
        assert_eq!(edits[0]["newText"], "compile");
        assert_eq!(edits[1]["range"]["start"]["line"], 3, "the reference");
        assert_eq!(edits[1]["range"]["end"]["character"], 16, "only the first segment");
    }

    #[test]
    fn renaming_from_the_header_key_works_too() {
        let (doc, at) = doc_at(HERO, "build:   oci");
        let prepared = prepare_rename(&doc, at).expect("a rename target");
        assert_eq!(prepared["placeholder"], "build");
        assert!(rename(&doc, "f", at, "compile").is_ok());
    }

    #[test]
    fn a_rename_that_would_break_the_file_is_refused() {
        let (doc, at) = doc_at(HERO, "build.digest");
        assert!(rename(&doc, "f", at, "a name").unwrap_err().contains("not a step name"));
        assert!(rename(&doc, "f", at, "secrets").unwrap_err().contains("context namespace"));
        assert!(rename(&doc, "f", at, "deploy").unwrap_err().contains("already a step"));
    }

    #[test]
    fn there_is_nothing_to_rename_in_a_path() {
        let (doc, at) = doc_at(HERO, "./Dockerfile");
        assert!(prepare_rename(&doc, at).is_none());
        assert!(rename(&doc, "f", at, "compile").is_err());
    }

    /// A step can be named without a field — `wait: build` wires a dependency.
    /// Renaming it must carry that word along, or the reference dangles.
    #[test]
    fn a_rename_carries_a_bare_step_reference() {
        let src = "steps:\n  build: oci.image\n  deploy: k8s.rollout\n    image: build.digest\n    wait: build\n";
        let doc = Doc::new(src.to_string(), Encoding::Utf16);
        let at = src.find("build: oci").expect("the header") as u32;
        let edits = rename(&doc, "f", at, "compile").expect("rename");
        let changed = edits["changes"]["f"].as_array().expect("edits").clone();
        let texts: Vec<&str> =
            changed.iter().map(|e| e["newText"].as_str().expect("text")).collect();
        // header, `image: build.digest`, and the bare `wait: build`.
        assert_eq!(texts, ["compile", "compile", "compile"]);
        // The result still checks clean, so the rename left nothing dangling.
        let after = Doc::new(apply(src, &changed), Encoding::Utf16);
        assert!(after.checked.diagnostics.is_empty(), "{:?}", after.checked.diagnostics);
    }

    #[test]
    fn a_word_that_only_spells_a_step_is_not_a_reference() {
        let src = "on:\n  push:\n    branches: [build]\npolicy:\n  never:\n    agents: [build]\nsteps:\n  build: oci.image\n    from: ./build\n    label: \"build\"\n";
        let doc = Doc::new(src.to_string(), Encoding::Utf16);
        let at = src.find("build: oci").expect("the header") as u32;
        let edits = rename(&doc, "f", at, "compile").expect("rename");
        let changed = edits["changes"]["f"].as_array().expect("edits").clone();
        assert_eq!(changed.len(), 1, "only the header: {changed:?}");
    }

    /// Apply edits back to front, so an earlier edit's offsets stay valid.
    fn apply(src: &str, edits: &[Value]) -> String {
        let index = LineIndex::new(src, Encoding::Utf16);
        let at = |position: &Value| {
            index.offset(
                src,
                Position {
                    line: position["line"].as_u64().expect("line") as u32,
                    character: position["character"].as_u64().expect("character") as u32,
                },
            )
        };
        let mut spans: Vec<(u32, u32, &str)> = edits
            .iter()
            .map(|e| {
                (
                    at(&e["range"]["start"]),
                    at(&e["range"]["end"]),
                    e["newText"].as_str().expect("newText"),
                )
            })
            .collect();
        spans.sort_unstable_by_key(|(start, ..)| std::cmp::Reverse(*start));
        let mut out = src.to_string();
        for (start, end, text) in spans {
            out.replace_range(start as usize..end as usize, text);
        }
        out
    }
}
