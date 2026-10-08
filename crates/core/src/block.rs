//! Blocks: what a `block:` file declares, read as the signature a use is
//! checked against — inputs with their defaults, outputs, and the actions
//! the internal steps perform ([#80](https://github.com/Keep-Shipping/harness/issues/80)).
//!
//! Pure: signatures are resolved from parsed files and a [`Catalog`], so no
//! store, network or filesystem is reached from here.

use std::collections::{BTreeMap, BTreeSet};

use ks_lang::{Atom, Code, Diagnostic, Entry, Span};

use crate::catalog::{AFTER, Catalog, StepTypes, WHEN};
use crate::check::{annotation_default, env_gate, secret_keys, value_text};
use crate::script_step::is_script_kind;
use crate::step::{ActionClass, ActionKind, StepCapabilities};
use crate::types::Type;

/// How many blocks may nest. A block may use other blocks; four levels is
/// deep enough to compose a service out of parts, and the bound keeps
/// resolving signatures bounded whatever the files say.
pub const MAX_BLOCK_DEPTH: usize = 4;

/// The key a block is used under in its own `steps:`.
pub const BLOCK_KEY: &str = "block";

/// The keys a use may not spend an input on: they are read off the step
/// whatever its kind, so an input of that name would silently shadow.
const RESERVED: [&str; 3] = [WHEN, AFTER, "outputs"];

/// Whether a block may declare an input under `name`.
#[must_use]
pub fn input_allowed(name: &str) -> bool {
    !RESERVED.contains(&name)
}

/// One declared input: its type, and the default a use may leave out.
#[derive(Clone, Debug)]
pub struct BlockInput {
    /// The name the use passes it under.
    pub name: String,
    /// The declared type; the default, when there is one, must fit it.
    pub ty: Type,
    /// The default as written (`2` for `replicas: int = 2`). `None` is a
    /// required input: a use omitting it is an error.
    pub default: Option<String>,
}

/// What a block file declares: everything a use is checked against, and
/// nothing else. A use is checked against the signature alone — it never
/// sees the steps inside.
#[derive(Clone, Debug)]
pub struct BlockSignature {
    /// The name `block:` declares.
    pub name: String,
    /// Inputs in declaration order.
    pub inputs: Vec<BlockInput>,
    /// The `outputs:` mapping, name to type.
    pub outputs: Vec<(String, Type)>,
    /// What the block does, collected from its internal steps — a step using
    /// another block contributes that block's actions, so the whole nest is
    /// visible to policy. Each action keeps the kind that performs it, so a
    /// refusal names the work rather than the name the use spells.
    pub actions: Vec<(ActionClass, String)>,
    /// The distinct `secrets.<name>` keys the block's internal steps read, so
    /// a use is judged against what its block needs — a block that reads a
    /// secret trips `agents: never: read secrets` exactly as a direct step
    /// does. Sorted, so it is one report per distinct key.
    pub secrets: Vec<String>,
    /// The signature as the step contract a use takes, so a block flows
    /// through the same `spec` path a catalog step does.
    types: StepTypes,
}

impl BlockSignature {
    fn new(
        name: String,
        inputs: Vec<BlockInput>,
        outputs: Vec<(String, Type)>,
        actions: Vec<(ActionClass, String)>,
        secrets: Vec<String>,
    ) -> BlockSignature {
        // A defaulted input is optional at a use, the way a step schema's
        // own default makes its input optional.
        let types = StepTypes {
            name: name.clone(),
            inputs: inputs
                .iter()
                .map(|i| {
                    let ty = if i.default.is_some() {
                        Type::Optional(Box::new(i.ty.clone()))
                    } else {
                        i.ty.clone()
                    };
                    (i.name.clone(), ty)
                })
                .collect(),
            outputs: outputs.clone(),
            runtime_outputs: false,
            decision: false,
            capabilities: StepCapabilities::default(),
        };
        BlockSignature { name, inputs, outputs, actions, secrets, types }
    }

    /// The signature as the step contract a use is checked against: its
    /// inputs (the defaulted ones optional) and its declared outputs.
    #[must_use]
    pub fn as_step_types(&self) -> &StepTypes {
        &self.types
    }

    /// The action classes of one internal step: the nested block's own, whole,
    /// where the step uses a block; else the action the step declares — its
    /// kind's when the catalog knows it, the `action:` a script step writes
    /// when it does not — in the environment its `when: env is <name>` binds it
    /// to. A kind the catalog does not know and that is not a script asserts
    /// nothing.
    fn actions_of(
        step: Entry<'_>,
        catalog: &Catalog,
        nested: &BTreeMap<String, BlockSignature>,
    ) -> Vec<(ActionClass, String)> {
        let Some((kind, _)) = kind_of(step) else { return Vec::new() };
        if let Some(block) = nested.get(kind) {
            return block.actions.clone();
        }
        let action = if catalog.step(kind).is_some() {
            Some(ActionKind::of_kind(kind))
        } else if is_script_kind(kind) {
            // A script step says what it does with `action:` ([#89]), and that
            // is the same claim the checker reads on the step itself
            // ([`crate::check`]). A use of a block that carries one must not
            // see less than a use of the same script written out in full, or a
            // block becomes the way to drop a declared apply ([#123]).
            declared_action(step)
        } else {
            None
        };
        let Some(action) = action else { return Vec::new() };
        let class = match env_gate(step) {
            Some(env) => ActionClass::new(action).in_env(env),
            None => ActionClass::new(action),
        };
        vec![(class, kind.to_string())]
    }
}

/// The signature a parsed block file declares, or `None` when the file is not
/// a block file (no top-level `block:`). `nested` are the signatures of the
/// blocks its internal steps use, keyed by the kind as written; a step using
/// one contributes that block's actions, flattened.
pub fn signature(
    parse: &ks_lang::Parse,
    catalog: &Catalog,
    nested: &BTreeMap<String, BlockSignature>,
) -> Option<BlockSignature> {
    let entries: Vec<Entry<'_>> = parse.file().entries().collect();
    let block = entries.iter().find(|e| e.key_name() == Some(BLOCK_KEY))?;
    let name = block.expr().as_ref().and_then(value_text)?;
    let inputs = child(&entries, "inputs")
        .map(|e| {
            e.children()
                .filter_map(|i| {
                    let name = i.key_name()?.to_string();
                    let expr = i.expr()?;
                    Some(match annotation_default(&expr) {
                        // `replicas: int = 2`
                        Some((_, ty, rhs)) => BlockInput { name, ty, default: value_text(rhs) },
                        // `domain: string` — a type that does not parse is
                        // reported by the checker's own pass.
                        None => BlockInput {
                            name,
                            ty: value_text(&expr).and_then(|t| Type::parse(&t))?,
                            default: None,
                        },
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let outputs = child(&entries, "outputs")
        .map(|e| {
            e.children()
                .filter_map(|o| {
                    let name = o.key_name()?.to_string();
                    let expr = o.expr()?;
                    // `url: string = ship.url`
                    let (_, ty, _) = annotation_default(&expr)?;
                    Some((name, ty))
                })
                .collect()
        })
        .unwrap_or_default();
    let mut actions: Vec<(ActionClass, String)> = Vec::new();
    let mut secrets: BTreeSet<String> = BTreeSet::new();
    if let Some(steps) = child(&entries, "steps") {
        for s in steps.children() {
            actions.extend(BlockSignature::actions_of(s, catalog, nested));
            // A step using another block needs whatever that block needs.
            match kind_of(s).map(|(k, _)| k).and_then(|k| nested.get(k)) {
                Some(block) => secrets.extend(block.secrets.iter().cloned()),
                None => secrets.extend(secret_keys(s)),
            }
        }
    }
    Some(BlockSignature::new(name, inputs, outputs, actions, secrets.into_iter().collect()))
}

/// A problem with the block graph, where the file it is in declares it.
#[derive(Clone, Debug)]
pub struct BlockProblem {
    /// The file the offending line is written in.
    pub file: String,
    pub code: Code,
    pub span: Span,
    pub message: String,
}

impl BlockProblem {
    /// The problem as a diagnostic, so it reports like every other finding.
    #[must_use]
    pub fn diagnostic(&self) -> Diagnostic {
        Diagnostic::error(self.code, self.span, format!("{}: {}", self.file, self.message))
    }
}

/// Every block in `files`, keyed by the name `block:` declares, with the
/// problems resolving them found: a nest that closes a circle, and one that
/// nests deeper than [`MAX_BLOCK_DEPTH`]. Pure: `files` is keyed by path and
/// every parse was made by the caller.
#[must_use]
pub fn block_signatures(
    files: &BTreeMap<String, &ks_lang::Parse>,
    catalog: &Catalog,
) -> (BTreeMap<String, BlockSignature>, Vec<BlockProblem>) {
    let by_name: BTreeMap<String, (String, &ks_lang::Parse)> = files
        .iter()
        .filter_map(|(path, parse)| Some((declared_name(parse)?, (path.clone(), *parse))))
        .collect();
    let mut out = BTreeMap::new();
    let mut problems = Vec::new();
    for name in by_name.keys() {
        let mut stack = Vec::new();
        if let Some(sig) = resolve(name, &by_name, catalog, &mut stack, &mut problems) {
            out.insert(name.clone(), sig);
        }
    }
    // A circle — and an over-deep nest — is reachable from every block on the
    // path, so the same line is reported again and again: one report per
    // (file, line, finding) is enough, and the file is part of the key so a
    // different block's over-deep use is still its own report.
    let mut seen: BTreeSet<(String, u32, &'static str)> = BTreeSet::new();
    problems.retain(|p| seen.insert((p.file.clone(), p.span.start, p.code.as_str())));
    (out, problems)
}

/// The signature of the block `name` declares, resolving the blocks it uses
/// first. `stack` is the nest being resolved, `name` included, which is how a
/// circle and the depth limit are both caught.
fn resolve(
    name: &str,
    by_name: &BTreeMap<String, (String, &ks_lang::Parse)>,
    catalog: &Catalog,
    stack: &mut Vec<String>,
    problems: &mut Vec<BlockProblem>,
) -> Option<BlockSignature> {
    // `name` is never already on the stack: every caller checks that first,
    // which is what makes the circle report name the path it found it on.
    let (file, parse) = by_name.get(name)?;
    stack.push(name.to_string());
    let mut nested = BTreeMap::new();
    for (kind, span) in uses(parse, by_name) {
        if stack.contains(&kind) {
            let mut path: Vec<String> = stack.clone();
            path.push(kind.clone());
            problems.push(BlockProblem {
                file: file.clone(),
                code: Code::Cycle,
                span,
                message: format!("blocks nest in a circle: {}", path.join(" → ")),
            });
            continue;
        }
        if stack.len() >= MAX_BLOCK_DEPTH {
            problems.push(BlockProblem {
                file: file.clone(),
                code: Code::BlockDepth,
                span,
                message: format!("blocks nest more than {MAX_BLOCK_DEPTH} deep here"),
            });
            continue;
        }
        if let Some(sig) = resolve(&kind, by_name, catalog, stack, problems) {
            nested.insert(kind, sig);
        }
    }
    stack.pop();
    signature(parse, catalog, &nested)
}

/// The name a parsed file's `block:` declares, if it is a block file.
pub fn declared_name(parse: &ks_lang::Parse) -> Option<String> {
    parse
        .file()
        .entries()
        .find(|e| e.key_name() == Some(BLOCK_KEY))
        .and_then(|e| e.expr())
        .as_ref()
        .and_then(value_text)
}

/// The blocks a file uses, as the kinds are written, with their spans.
fn uses<'a>(
    parse: &'a ks_lang::Parse,
    by_name: &BTreeMap<String, (String, &'a ks_lang::Parse)>,
) -> Vec<(String, Span)> {
    all_uses(parse).into_iter().filter(|(kind, _)| by_name.contains_key(kind)).collect()
}

/// Every step kind a file's `steps:` names, with their spans — a block use or
/// a catalog step kind, told apart by the caller.
fn all_uses(parse: &ks_lang::Parse) -> Vec<(String, Span)> {
    parse
        .file()
        .entries()
        .find(|e| e.key_name() == Some("steps"))
        .map(|steps| {
            steps
                .children()
                .filter_map(|s| kind_of(s))
                .map(|(k, span)| (k.to_string(), span))
                .collect()
        })
        .unwrap_or_default()
}

/// The action a script step declares under `action:`, as
/// [`ActionKind::parse`] reads it.
///
/// `None` when the step declares none — the kind reads as
/// [`ActionKind::Other`](ActionKind::Other) and asserts nothing — and when it
/// declares a name no kind takes. The name is not validated here: the checker
/// reports an unknown one where it reports every other one, on the file that
/// writes it.
fn declared_action(step: Entry<'_>) -> Option<ActionKind> {
    let p = step.children().find(|c| c.key_name() == Some("action"))?;
    ActionKind::parse(&value_text(&p.expr()?)?)
}

/// The step's kind word, as written, and where it is.
fn kind_of(step: Entry<'_>) -> Option<(&str, Span)> {
    let expr = step.expr()?;
    let word = expr.atoms().iter().find_map(|a| match a {
        Atom::Word(w) => Some(w),
        _ => None,
    })?;
    Some((word.text(), word.node.span()))
}

/// The top-level `inputs:`/`outputs:`/`steps:` entry, if the file declares
/// one.
fn child<'a>(entries: &'a [Entry<'a>], key: &str) -> Option<Entry<'a>> {
    entries.iter().find(|e| e.key_name() == Some(key)).copied()
}
