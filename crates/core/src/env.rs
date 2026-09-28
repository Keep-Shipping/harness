//! Environment selection: which declared environment a run uses.

use ks_lang::{Code, Diagnostic, Span};

use crate::check::suggest;
use crate::workflow::{Trigger, Workflow};

/// The environment a run will use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvChoice {
    Selected(String),
    /// Several environments match; a human must pick one.
    Ambiguous(Vec<String>),
}

/// Pick the environment: an explicit request wins, then an event matching
/// exactly one environment's `on:` triggers, then a single declared
/// environment (a file without `envs:` has the implicit `default`).
pub fn select_env(
    wf: &Workflow,
    requested: Option<&str>,
    event: Option<&Trigger>,
) -> Result<EnvChoice, Diagnostic> {
    let envs = wf.envs();
    if let Some(request) = requested {
        return match envs.iter().find(|e| e.name == request) {
            Some(e) => Ok(EnvChoice::Selected(e.name.clone())),
            None => {
                let names: Vec<String> = envs.iter().map(|e| e.name.clone()).collect();
                let msg = format!("unknown environment `{request}`");
                Err(match suggest(request, &names) {
                    Some(s) => Diagnostic::error(Code::EnvProblem, Span::default(), msg)
                        .with_hint(format!("did you mean `{s}`?")),
                    None => Diagnostic::error(Code::EnvProblem, Span::default(), msg)
                        .with_hint(format!("declared environments: {}", names.join(", "))),
                })
            }
        };
    }
    if let Some(event) = event {
        let matching: Vec<String> = envs
            .iter()
            .filter(|e| e.triggers.iter().any(|t| trigger_matches(t, event)))
            .map(|e| e.name.clone())
            .collect();
        if matching.len() == 1 {
            return Ok(EnvChoice::Selected(matching.into_iter().next().expect("one match")));
        }
        if matching.len() > 1 {
            return Ok(EnvChoice::Ambiguous(matching));
        }
    }
    match envs.len() {
        1 => Ok(EnvChoice::Selected(envs[0].name.clone())),
        _ => Ok(EnvChoice::Ambiguous(envs.iter().map(|e| e.name.clone()).collect())),
    }
}

/// Kinds match, and globs (simple `*` wildcards) when both sides have one.
fn trigger_matches(env_trigger: &Trigger, event: &Trigger) -> bool {
    if env_trigger.kind != event.kind {
        return false;
    }
    match (&env_trigger.glob, &event.glob) {
        (None, _) | (_, None) => true,
        (Some(a), Some(b)) => glob_match(a, b) || glob_match(b, a),
    }
}

/// `*` matches any run of characters; everything else is literal. Linear in
/// pattern and text: a greedy match with a single backtrack pointer, never a
/// retry-per-position search (which made many `*`s exponential).
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    // Position of the last `*` in the pattern, and where its match started,
    // so a mismatch can retry with the `*` swallowing one more character.
    let (mut star, mut star_text) = (None::<usize>, 0usize);
    while ti < t.len() {
        match p.get(pi) {
            Some('*') => {
                star = Some(pi);
                pi += 1;
                star_text = ti;
            }
            Some(&c) if c == t[ti] => {
                pi += 1;
                ti += 1;
            }
            _ => match star {
                Some(s) => {
                    pi = s + 1;
                    star_text += 1;
                    ti = star_text;
                }
                None => return false,
            },
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}
